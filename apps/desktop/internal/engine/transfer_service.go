// Package engine exposes the SendBeam engine to the desktop frontend through
// Wails services. WebRTC, crypto, file I/O, durability, and trust logic stay
// in the Go engine (packages/engine); these services are only a thin
// presentation seam, exactly as the CLI consumes the engine through its
// public API.
package engine

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/engine/wsclient"
	"github.com/sendbeam/wire"
	qrcode "github.com/skip2/go-qrcode"
)

// TransferEventName is the single event name the service emits for every live
// transfer update. The payload is a TransferEvent snapshot; the frontend
// re-renders from the latest snapshot per transfer id.
const TransferEventName = "sendbeam:transfer"

// DefaultServer mirrors the CLI's default signaling server, so a desktop peer
// pairs with CLI and browser peers of the same deployment out of the box.
const DefaultServer = "wss://localhost:8443/ws"

// FileInfo is one file in the transfer set, for aggregate display.
type FileInfo struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// TransferEvent is a live snapshot of one transfer's state. Kind tells the
// frontend what changed; the rest are the current values (progress events are
// throttled to a bounded cadence, the terminal kind is always emitted).
type TransferEvent struct {
	ID   string `json:"id"`
	Kind string `json:"kind"` // invite | phase | connect | transport | manifest | progress | state | done | error

	// Invite (offerer, kind=invite).
	Code string `json:"code,omitempty"`
	Link string `json:"link,omitempty"`
	QR   string `json:"qr,omitempty"` // data URL of the invite QR

	// Handshake (kind=phase).
	Phase string `json:"phase,omitempty"`

	// Secure channel (kind=connect).
	Fingerprint string `json:"fingerprint,omitempty"`

	// Byte path (kind=transport).
	Transport string `json:"transport,omitempty"`

	// File set (kind=manifest).
	Files      []FileInfo `json:"files,omitempty"`
	TotalBytes int64      `json:"totalBytes,omitempty"`

	// Progress (kind=progress): cumulative acknowledged bytes, percent,
	// five-second rolling rate, ETA, current file, aggregate state.
	DoneBytes   int64   `json:"doneBytes,omitempty"`
	Percent     int     `json:"percent,omitempty"`
	RateBps     float64 `json:"rateBps,omitempty"`
	ETA         string  `json:"eta,omitempty"`
	CurrentFile string  `json:"currentFile,omitempty"`
	FileBytes   int64   `json:"fileBytes,omitempty"`
	FileSize    int64   `json:"fileSize,omitempty"`
	FilesDone   int     `json:"filesDone,omitempty"`
	FilesTotal  int     `json:"filesTotal,omitempty"`
	RemainingMS int64   `json:"remainingMs,omitempty"` // -1 when unknown
	State       string  `json:"state,omitempty"`       // running | paused | canceled
	Paused      bool    `json:"paused,omitempty"`
	Canceled    bool    `json:"canceled,omitempty"`
	Failed      bool    `json:"failed,omitempty"`

	// Terminal (kind=done/error).
	Digest  string `json:"digest,omitempty"`
	OutDir  string `json:"outDir,omitempty"`
	OutPath string `json:"outPath,omitempty"`
	Error   string `json:"error,omitempty"`
}

// SignalDialer returns the signaling signal for one transfer side. The desktop
// uses the same wsclient as the CLI (browser/CLI interop by construction);
// tests inject loopback ends.
type SignalDialer func(ctx context.Context, server string, role wire.Role) (transfer.Signal, error)

// defaultDialer dials the real signaling server exactly as the CLI does.
func defaultDialer(ctx context.Context, server string, _ wire.Role) (transfer.Signal, error) {
	return wsclient.NewReconnectingSignal(ctx, server, wsclient.DialOptions{})
}

// TransferService drives one or more engine transfers through transfer.Run,
// streaming TransferEvent snapshots to the frontend. All WebRTC, crypto, file
// I/O, durability, and trust logic stays in packages/engine.
type TransferService struct {
	emit func(name string, data any) // nil in tests; wired to app events in main
	dial SignalDialer

	// forceRelay skips direct negotiation (loopback tests; production leaves it
	// false so the adaptive direct/relay racer runs). iceServers nil uses the
	// engine's default STUN; an explicit empty slice is host-only (loopback).
	forceRelay bool
	iceServers []webrtc.ICEServer

	mu   sync.Mutex
	next int
	runs map[string]*transferRun
}

// NewTransferService builds the service. emit is the frontend sink (wails
// app.Event.Emit in production, a recorder in tests); dial is the signaling
// seam (nil uses the real wsclient).
func NewTransferService(emit func(name string, data any), dial SignalDialer) *TransferService {
	if dial == nil {
		dial = defaultDialer
	}
	return &TransferService{emit: emit, dial: dial, runs: map[string]*transferRun{}}
}

// setLoopbackConfig is the test seam for the loopback relay: host-only ICE and
// the forced-relay path, mirroring the engine's own parity tests.
func (s *TransferService) setLoopbackConfig() {
	s.forceRelay = true
	s.iceServers = []webrtc.ICEServer{}
}

// Handle identifies a started transfer.
type Handle struct {
	ID   string `json:"id"`
	Role string `json:"role"` // send | receive
}

// transferRun is one in-flight transfer. It owns the engine Controls once the
// channel opens and the rolling rate samples for speed/ETA.
type transferRun struct {
	id   string
	role wire.Role

	svc  *TransferService
	ctx  context.Context
	canc context.CancelFunc

	mu       sync.Mutex
	controls transfer.Controls

	files       []FileInfo
	totalBytes  int64
	doneBytes   int64
	reused      int64 // verified baseline reused at resume (0 for fresh transfers)
	fileIdx     int
	fileBytes   int64
	fileSize    int64
	filesDone   int
	paused      bool
	canceled    bool
	failed      bool
	transport   string
	fingerprint string

	samples []progressSample
	now     func() time.Time
}

type progressSample struct {
	at    time.Time
	bytes int64
}

// Send starts an offerer (send) transfer for the given files/folders and
// returns immediately. The invite (code/link/QR) is streamed as an invite
// event once the room is allocated.
func (s *TransferService) Send(paths []string, server string) (Handle, error) {
	if len(paths) == 0 {
		return Handle{}, errors.New("no files or folders selected")
	}
	if server == "" {
		server = DefaultServer
	}
	if err := validatePaths(paths); err != nil {
		return Handle{}, err
	}
	id := s.newID()
	r := s.newRun(id, wire.RoleOfferer)
	sources, total, err := transfer.NewOSFileSources(paths)
	if err != nil {
		s.remove(r)
		return Handle{}, err
	}
	for _, src := range sources {
		meta := src.Meta()
		r.mu.Lock()
		r.files = append(r.files, FileInfo{Name: meta.Name, Size: meta.Size})
		r.totalBytes += meta.Size
		r.mu.Unlock()
	}
	_ = total

	go r.runSend(r.ctx, server, sources)
	return Handle{ID: id, Role: "send"}, nil
}

// Receive starts a joiner (receive) transfer for a code (or a full invite
// link) into destDir and returns immediately. The file set is streamed as a
// manifest event once the sender's manifest arrives.
func (s *TransferService) Receive(code string, destDir string, server string) (Handle, error) {
	if code == "" {
		return Handle{}, errors.New("an invite code (or link) is required")
	}
	code = normalizeCode(code)
	if destDir == "" {
		destDir = "."
	}
	if server == "" {
		server = DefaultServer
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return Handle{}, fmt.Errorf("create destination: %w", err)
	}
	id := s.newID()
	r := s.newRun(id, wire.RoleJoiner)

	go r.runReceive(r.ctx, code, destDir, server)
	return Handle{ID: id, Role: "receive"}, nil
}

// Drop starts a send for paths dropped onto the window, mirroring Send.
func (s *TransferService) Drop(paths []string) (Handle, error) {
	return s.Send(paths, DefaultServer)
}

// Pause pauses the transfer with id (both sides stop producing new data).
func (s *TransferService) Pause(id string) error {
	return s.control(id, func(c transfer.Controls) error { return c.Pause() })
}

// Resume resumes the transfer with id.
func (s *TransferService) Resume(id string) error {
	return s.control(id, func(c transfer.Controls) error { return c.Resume() })
}

// Cancel cancels the transfer with id.
func (s *TransferService) Cancel(id string) error {
	return s.control(id, func(c transfer.Controls) error { return c.Cancel("canceled by user") })
}

// control looks up the live Controls for id and applies fn.
func (s *TransferService) control(id string, fn func(transfer.Controls) error) error {
	s.mu.Lock()
	r, ok := s.runs[id]
	s.mu.Unlock()
	if !ok {
		return fmt.Errorf("no active transfer %q", id)
	}
	r.mu.Lock()
	c := r.controls
	r.mu.Unlock()
	if c == nil {
		return fmt.Errorf("transfer %q has not connected yet", id)
	}
	return fn(c)
}

func (s *TransferService) newID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	return fmt.Sprintf("t%d", s.next)
}

func (s *TransferService) newRun(id string, role wire.Role) *transferRun {
	ctx, canc := context.WithCancel(context.Background())
	r := &transferRun{
		id: id, role: role, svc: s, ctx: ctx, canc: canc,
		now: time.Now,
	}
	s.mu.Lock()
	s.runs[id] = r
	s.mu.Unlock()
	return r
}

func (s *TransferService) remove(r *transferRun) {
	r.canc()
	s.mu.Lock()
	delete(s.runs, r.id)
	s.mu.Unlock()
}

// publish sends a snapshot event to the frontend (and to tests via the
// injected emit sink). Phase is set by the callbacks via mut; the rest are the
// current run values.
func (r *transferRun) publish(kind string, mut ...func(*TransferEvent)) {
	r.mu.Lock()
	ev := &TransferEvent{
		ID:          r.id,
		Kind:        kind,
		Transport:   r.transport,
		Fingerprint: r.fingerprint,
		Files:       append([]FileInfo(nil), r.files...),
		TotalBytes:  r.totalBytes,
		DoneBytes:   r.doneBytes,
		FileBytes:   r.fileBytes,
		FileSize:    r.fileSize,
		FilesDone:   r.filesDone,
		FilesTotal:  len(r.files),
		State:       r.stateString(),
		Paused:      r.paused,
		Canceled:    r.canceled,
		Failed:      r.failed,
		RemainingMS: -1,
	}
	if r.totalBytes > 0 {
		ev.Percent = int(r.doneBytes * 100 / r.totalBytes)
	}
	rate, eta := r.rateAndETA()
	if rate > 0 {
		ev.RateBps = rate
		ev.ETA = formatETA(eta)
		ev.RemainingMS = eta.Milliseconds()
	}
	if r.fileIdx >= 0 && r.fileIdx < len(r.files) {
		ev.CurrentFile = r.files[r.fileIdx].Name
	}
	r.mu.Unlock()

	for _, m := range mut {
		m(ev)
	}
	if r.svc.emit != nil {
		r.svc.emit(TransferEventName, ev)
	}
}

func (r *transferRun) stateString() string {
	switch {
	case r.failed:
		return "failed"
	case r.canceled:
		return "canceled"
	case r.paused:
		return "paused"
	default:
		return "running"
	}
}

// rateAndETA computes the five-second rolling rate and remaining duration from
// the sampled acknowledged bytes (mirrors the CLI progress math).
func (r *transferRun) rateAndETA() (float64, time.Duration) {
	if len(r.samples) < 2 {
		return 0, 0
	}
	first, last := r.samples[0], r.samples[len(r.samples)-1]
	elapsed := last.at.Sub(first.at).Seconds()
	if elapsed <= 0 || last.bytes <= first.bytes {
		return 0, 0
	}
	rate := float64(last.bytes-first.bytes) / elapsed
	remaining := r.totalBytes - r.reused - r.doneBytes
	if remaining < 0 {
		remaining = 0
	}
	if rate <= 0 {
		return rate, 0
	}
	return rate, time.Duration(float64(time.Second) * float64(remaining) / rate)
}

func (r *transferRun) recordSample(bytes int64) {
	now := r.now()
	r.samples = append(r.samples, progressSample{at: now, bytes: bytes})
	cutoff := now.Add(-5 * time.Second)
	for len(r.samples) > 2 && !r.samples[1].at.After(cutoff) {
		r.samples = r.samples[1:]
	}
}

// runSend drives the offerer side of the transfer.
func (r *transferRun) runSend(ctx context.Context, server string, sources []wire.FileSource) {
	defer r.svc.remove(r)

	sig, err := r.svc.dial(ctx, server, wire.RoleOfferer)
	if err != nil {
		r.fail("dial: " + err.Error())
		return
	}
	defer sig.Close()

	lastProgress := time.Time{}
	emitProgress := func() {
		now := time.Now()
		if now.Sub(lastProgress) < 200*time.Millisecond {
			return
		}
		lastProgress = now
		r.publish("progress")
	}

	spec := transfer.Spec{
		Session: rendezvous.Options{
			Role: rendezvous.RoleOfferer,
			OnPhase: func(p rendezvous.Phase) {
				r.publish("phase", func(ev *TransferEvent) { ev.Phase = string(p) })
			},
			OnCode: func(code string) {
				r.publish("invite", func(ev *TransferEvent) {
					ev.Code = code
					ev.Link = inviteLink(server, code)
					ev.QR = qrDataURL(ev.Link)
				})
			},
		},
		Sources:        sources,
		ForceRelay:     r.svc.forceRelay,
		ICEServers:     r.svc.iceServers,
		OnTransport:    r.onTransport,
		OnConnect:      func() { r.publish("connect") },
		OnFileProgress: r.onFileProgress,
		OnProgress: func(n int64) {
			r.mu.Lock()
			r.doneBytes = n
			r.recordSample(n)
			r.mu.Unlock()
			emitProgress()
		},
		OnControls: func(c transfer.Controls) {
			r.mu.Lock()
			r.controls = c
			r.mu.Unlock()
			r.publish("connect") // controls ready
		},
		OnStateChange: r.onState,
	}

	out, err := transfer.Run(ctx, sig, spec)
	if err != nil {
		r.fail(err.Error())
		return
	}
	r.mu.Lock()
	var done int64
	for i, f := range out.Files {
		done += f.Size
		if i < len(r.files) {
			r.files[i].Size = f.Size
		}
	}
	r.doneBytes = done
	// Verified success: every file in the set completed.
	r.filesDone = len(out.Files)
	r.mu.Unlock()

	if out.Handshake != nil {
		r.mu.Lock()
		r.fingerprint = fingerprint(out.Handshake.Master)
		r.mu.Unlock()
	}
	r.publish("done", func(ev *TransferEvent) {
		ev.Digest = out.Digest
		ev.Percent = 100
	})
}

// runReceive drives the joiner side of the transfer.
func (r *transferRun) runReceive(ctx context.Context, code, destDir, server string) {
	defer r.svc.remove(r)

	sig, err := r.svc.dial(ctx, server, wire.RoleJoiner)
	if err != nil {
		r.fail("dial: " + err.Error())
		return
	}
	defer sig.Close()

	lastProgress := time.Time{}
	emitProgress := func() {
		now := time.Now()
		if now.Sub(lastProgress) < 200*time.Millisecond {
			return
		}
		lastProgress = now
		r.publish("progress")
	}
	spec := transfer.Spec{
		Session: rendezvous.Options{
			Role: rendezvous.RoleJoiner,
			Code: code,
			OnPhase: func(p rendezvous.Phase) {
				r.publish("phase", func(ev *TransferEvent) { ev.Phase = string(p) })
			},
		},
		DestDir:    destDir,
		ForceRelay: r.svc.forceRelay,
		ICEServers: r.svc.iceServers,
		OnManifestSet: func(m wire.Manifest) {
			r.mu.Lock()
			r.files = r.files[:0]
			r.totalBytes = m.TotalSize
			for _, f := range m.Files {
				r.files = append(r.files, FileInfo{Name: f.Name, Size: f.Size})
			}
			r.mu.Unlock()
			r.publish("manifest")
		},
		OnTransport:    r.onTransport,
		OnConnect:      func() { r.publish("connect") },
		OnFileProgress: r.onFileProgress,
		OnProgress: func(n int64) {
			r.mu.Lock()
			r.doneBytes = n
			r.recordSample(n)
			r.mu.Unlock()
			emitProgress()
		},
		OnControls: func(c transfer.Controls) {
			r.mu.Lock()
			r.controls = c
			r.mu.Unlock()
			r.publish("connect") // controls ready
		},
		OnStateChange: r.onState,
	}

	out, err := transfer.Run(ctx, sig, spec)
	if err != nil {
		r.fail(err.Error())
		return
	}
	r.mu.Lock()
	r.doneBytes = out.Size
	r.filesDone = len(out.Files)
	if out.Handshake != nil {
		r.fingerprint = fingerprint(out.Handshake.Master)
	}
	r.mu.Unlock()
	r.publish("done", func(ev *TransferEvent) {
		ev.Digest = out.Digest
		ev.OutDir = destDir
		if len(out.Files) == 1 {
			ev.OutPath = out.Path
		}
		ev.Percent = 100
	})
}

func (r *transferRun) onTransport(path string) {
	r.mu.Lock()
	r.transport = path
	r.mu.Unlock()
	r.publish("transport")
}

func (r *transferRun) onFileProgress(fileIdx int, fileBytes, _ int64) {
	r.mu.Lock()
	r.fileIdx = fileIdx
	r.fileBytes = fileBytes
	if fileIdx >= 0 && fileIdx < len(r.files) {
		r.fileSize = r.files[fileIdx].Size
		// A file is done when its acknowledged bytes reach its size.
		if fileBytes >= r.files[fileIdx].Size {
			if r.filesDone < fileIdx+1 {
				r.filesDone = fileIdx + 1
			}
		}
	}
	r.mu.Unlock()
}

func (r *transferRun) onState(st wire.TransferState) {
	r.mu.Lock()
	switch st {
	case wire.TransferPaused:
		r.paused = true
	case wire.TransferCanceled:
		r.canceled = true
	default:
		r.paused = false
	}
	r.mu.Unlock()
	r.publish("state")
}

func (r *transferRun) fail(why string) {
	r.mu.Lock()
	r.failed = true
	r.mu.Unlock()
	r.publish("error", func(ev *TransferEvent) { ev.Error = why })
}

// fingerprint renders the SAS fingerprint from the session master, matching
// the CLI exactly.
func fingerprint(master []byte) string {
	sum := sha256.Sum256(append([]byte("sendbeam/sas\x00"), master...))
	return fmt.Sprintf("%02x%02x %02x%02x", sum[0], sum[1], sum[2], sum[3])
}

// inviteLink turns the signaling URL into the web app's join link for the same
// deployment, matching the CLI (wss/ws → https/http, drop /ws, code in the
// fragment so it never hits the server).
func inviteLink(serverURL, code string) string {
	u, err := url.Parse(serverURL)
	if err != nil || u.Host == "" {
		return ""
	}
	switch u.Scheme {
	case "wss":
		u.Scheme = "https"
	case "ws":
		u.Scheme = "http"
	}
	u.Path = "/"
	u.RawQuery = ""
	u.Fragment = code
	return u.String()
}

// normalizeCode accepts a bare code or a full invite link and returns the code.
func normalizeCode(arg string) string {
	arg = strings.TrimSpace(arg)
	if i := strings.LastIndex(arg, "#"); i >= 0 {
		return arg[i+1:]
	}
	return arg
}

// qrDataURL renders the invite link as a QR PNG data URL.
func qrDataURL(link string) string {
	if link == "" {
		return ""
	}
	png, err := qrcode.Encode(link, qrcode.Medium, 320)
	if err != nil {
		return ""
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
}

// validatePaths rejects symbolic links and missing paths up front with the
// engine's rules (NewOSFileSources re-validates; this keeps picker feedback
// instant).
func validatePaths(paths []string) error {
	for _, p := range paths {
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symbolic links are not supported: %s", p)
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("not a regular file or folder: %s", p)
		}
	}
	return nil
}

// formatETA renders a duration like the CLI (e.g. "2m 5s remaining").
func formatETA(eta time.Duration) string {
	seconds := int64(math.Ceil(eta.Seconds()))
	if seconds < 60 {
		return fmt.Sprintf("%ds remaining", seconds)
	}
	return fmt.Sprintf("%dm %ds remaining", seconds/60, seconds%60)
}
