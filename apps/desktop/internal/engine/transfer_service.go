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
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/sendbeam/desktop/internal/config"
	"github.com/sendbeam/desktop/internal/lifecycle"
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
	Resumed     bool    `json:"resumed,omitempty"`

	// Terminal (kind=done/error).
	Digest  string `json:"digest,omitempty"`
	OutDir  string `json:"outDir,omitempty"`
	OutPath string `json:"outPath,omitempty"`
	Error   string `json:"error,omitempty"`
}

// DurableTransferItem describes an interrupted transfer (sender or receiver)
// surfaced to the desktop management UI.
type DurableTransferItem struct {
	TransferID     string   `json:"transferId"`
	Role           string   `json:"role"` // send | receive
	TotalBytes     int64    `json:"totalBytes"`
	CommittedBytes int64    `json:"committedBytes"`
	Files          int      `json:"files"`
	CreatedAt      int64    `json:"createdAt"`
	UpdatedAt      int64    `json:"updatedAt"`
	Status         string   `json:"status"`
	Resumable      bool     `json:"resumable"`
	Paths          []string `json:"paths,omitempty"`
}

// DurableInspectResult is the diagnostic outcome of inspecting a durable journal.
type DurableInspectResult struct {
	TransferID          string     `json:"transferId"`
	TotalBytes          int64      `json:"totalBytes"`
	CommittedBytes      int64      `json:"committedBytes"`
	CreatedAt           int64      `json:"createdAt"`
	UpdatedAt           int64      `json:"updatedAt"`
	ProtocolVersion     string     `json:"protocolVersion"`
	ManifestFingerprint string     `json:"manifestFingerprint"`
	JournalPath         string     `json:"journalPath"`
	PartialDir          string     `json:"partialDir"`
	Resumable           bool       `json:"resumable"`
	Problems            []string   `json:"problems,omitempty"`
	Files               []FileInfo `json:"files,omitempty"`
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

	configStore           *config.Store
	notifier              lifecycle.Notifier
	revealMgr             *lifecycle.RevealManager
	senderStore           *transfer.SenderStore
	durableStoreFn        func(outDir string) (*transfer.DurableStore, error)
	completedDestinations map[string]string
}

// NewTransferService builds the service. emit is the frontend sink (wails
// app.Event.Emit in production, a recorder in tests); dial is the signaling
// seam (nil uses the real wsclient).
func NewTransferService(emit func(name string, data any), dial SignalDialer) *TransferService {
	if dial == nil {
		dial = defaultDialer
	}
	cfgStore, _ := config.NewStore("", nil)
	sStoreDir, _ := transfer.SenderStoreDir()
	var sStore *transfer.SenderStore
	if sStoreDir != "" {
		sStore, _ = transfer.OpenSenderStore(sStoreDir)
	}

	return &TransferService{
		emit:                  emit,
		dial:                  dial,
		runs:                  map[string]*transferRun{},
		configStore:           cfgStore,
		notifier:              lifecycle.DefaultNotifier(),
		revealMgr:             lifecycle.NewRevealManager(nil),
		senderStore:           sStore,
		durableStoreFn:        transfer.OpenStore,
		completedDestinations: map[string]string{},
	}
}

// SetNotifier sets the notification sink.
func (s *TransferService) SetNotifier(n lifecycle.Notifier) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notifier = n
}

// SetRevealManager sets the reveal manager.
func (s *TransferService) SetRevealManager(r *lifecycle.RevealManager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revealMgr = r
}

// SetConfigStore sets the config store.
func (s *TransferService) SetConfigStore(cs *config.Store) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.configStore = cs
}

// SetSenderStore sets the sender store for tests.
func (s *TransferService) SetSenderStore(ss *transfer.SenderStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.senderStore = ss
}

// SetDurableStoreFn overrides the durable store factory for tests.
func (s *TransferService) SetDurableStoreFn(fn func(outDir string) (*transfer.DurableStore, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.durableStoreFn = fn
}

func (s *TransferService) openDurableStore(outDir string) (*transfer.DurableStore, error) {
	s.mu.Lock()
	fn := s.durableStoreFn
	s.mu.Unlock()
	if fn == nil {
		fn = transfer.OpenStore
	}
	return fn(outDir)
}

func (s *TransferService) recordCompleted(id, outPath string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.completedDestinations[id] = outPath
}

func (s *TransferService) authorizedRoots() []string {
	var roots []string
	if s.configStore != nil {
		if cfg, err := s.configStore.Load(); err == nil && cfg.DownloadDir != "" {
			roots = append(roots, cfg.DownloadDir)
		}
	}
	if userHome, err := os.UserHomeDir(); err == nil {
		roots = append(roots, filepath.Join(userHome, "Downloads"))
		roots = append(roots, filepath.Join(userHome, "Desktop"))
	}
	if wd, err := os.Getwd(); err == nil {
		roots = append(roots, wd)
	}
	if tmp := os.TempDir(); tmp != "" {
		roots = append(roots, tmp)
	}
	return roots
}

func parseTURNServer(rawURL string) (urlNoUser, username, password string) {
	trimmed := strings.TrimSpace(rawURL)
	scheme := ""
	rest := trimmed
	if strings.HasPrefix(trimmed, "turns:") {
		scheme = "turns:"
		rest = strings.TrimPrefix(trimmed, "turns:")
	} else if strings.HasPrefix(trimmed, "turn:") {
		scheme = "turn:"
		rest = strings.TrimPrefix(trimmed, "turn:")
	} else {
		return trimmed, "", ""
	}

	rest = strings.TrimPrefix(rest, "//")
	if atIdx := strings.LastIndex(rest, "@"); atIdx != -1 {
		userInfo := rest[:atIdx]
		hostPort := rest[atIdx+1:]
		if colonIdx := strings.Index(userInfo, ":"); colonIdx != -1 {
			username = userInfo[:colonIdx]
			password = userInfo[colonIdx+1:]
		} else {
			username = userInfo
		}
		urlNoUser = scheme + hostPort
		return urlNoUser, username, password
	}

	return trimmed, "", ""
}

func (s *TransferService) resolveICEServers() ([]webrtc.ICEServer, error) {
	s.mu.Lock()
	override := s.iceServers
	cs := s.configStore
	s.mu.Unlock()

	if override != nil {
		return override, nil
	}
	if cs == nil {
		return nil, nil
	}
	cfg, err := cs.Load()
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	if len(cfg.ICEServers) == 0 {
		return nil, nil
	}

	var resolved []webrtc.ICEServer
	for _, raw := range cfg.ICEServers {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if strings.HasPrefix(raw, "turn:") || strings.HasPrefix(raw, "turns:") {
			urlNoUser, username, pwd := parseTURNServer(raw)
			srv := webrtc.ICEServer{
				URLs: []string{urlNoUser},
			}
			if username != "" {
				srv.Username = username
				if pwd != "" {
					srv.Credential = pwd
					srv.CredentialType = webrtc.ICECredentialTypePassword
				} else {
					cred, err := cs.GetTurnCredential(urlNoUser, username)
					if err != nil && !errors.Is(err, config.ErrSecretStoreUnavailable) {
						cred, err = cs.GetTurnCredential(raw, username)
					}
					if err != nil {
						if errors.Is(err, config.ErrSecretStoreUnavailable) {
							return nil, fmt.Errorf("turn server %q requires credentials but protected secret store is unavailable: %w", raw, err)
						}
						return nil, fmt.Errorf("turn credential not found for %s (user %s): %w", raw, username, err)
					}
					srv.Credential = string(cred)
					srv.CredentialType = webrtc.ICECredentialTypePassword
				}
			}
			resolved = append(resolved, srv)
		} else {
			resolved = append(resolved, webrtc.ICEServer{
				URLs: []string{raw},
			})
		}
	}
	return resolved, nil
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
	resumed     bool
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
		if s.configStore != nil {
			if cfg, err := s.configStore.Load(); err == nil && cfg.ServerURL != "" {
				server = cfg.ServerURL
			}
		}
		if server == "" {
			server = DefaultServer
		}
	}
	if err := validatePaths(paths); err != nil {
		return Handle{}, err
	}
	iceServers, err := s.resolveICEServers()
	if err != nil {
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

	go r.runSend(r.ctx, server, sources, paths, iceServers)
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
		if s.configStore != nil {
			if cfg, err := s.configStore.Load(); err == nil && cfg.DownloadDir != "" {
				destDir = cfg.DownloadDir
			}
		}
		if destDir == "" {
			destDir = "."
		}
	}
	if server == "" {
		if s.configStore != nil {
			if cfg, err := s.configStore.Load(); err == nil && cfg.ServerURL != "" {
				server = cfg.ServerURL
			}
		}
		if server == "" {
			server = DefaultServer
		}
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return Handle{}, fmt.Errorf("create destination: %w", err)
	}
	iceServers, err := s.resolveICEServers()
	if err != nil {
		return Handle{}, err
	}

	id := s.newID()
	r := s.newRun(id, wire.RoleJoiner)

	go r.runReceive(r.ctx, code, destDir, server, iceServers)
	return Handle{ID: id, Role: "receive"}, nil
}

// Drop starts a send for paths dropped onto the window, mirroring Send.
func (s *TransferService) Drop(paths []string) (Handle, error) {
	return s.Send(paths, "")
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

// ListInterrupted surfaces interrupted durable receive journals and sender records.
func (s *TransferService) ListInterrupted(outDir string) ([]DurableTransferItem, error) {
	if outDir == "" {
		if s.configStore != nil {
			if cfg, err := s.configStore.Load(); err == nil && cfg.DownloadDir != "" {
				outDir = cfg.DownloadDir
			}
		}
		if outDir == "" {
			outDir = "."
		}
	}

	var items []DurableTransferItem

	// 1. Durable receive entries
	if store, err := s.openDurableStore(outDir); err == nil {
		if entries, err := store.List(); err == nil {
			for _, e := range entries {
				item := DurableTransferItem{
					TransferID:     e.TransferID,
					Role:           "receive",
					TotalBytes:     e.TotalSize,
					CommittedBytes: e.CommittedBytes,
					Files:          e.Files,
					CreatedAt:      e.UpdatedAt,
					UpdatedAt:      e.UpdatedAt,
					Status:         durableStatus(e),
					Resumable:      e.JournalOK && e.PartialOK && e.HasResumeSecret,
				}
				items = append(items, item)
			}
		}
	}

	// 2. Interrupted sender records
	s.mu.Lock()
	sstore := s.senderStore
	s.mu.Unlock()
	if sstore != nil {
		if senderEntries, err := sstore.List(); err == nil {
			for _, e := range senderEntries {
				item := DurableTransferItem{
					TransferID:     e.TransferID,
					Role:           "send",
					TotalBytes:     e.TotalSize,
					CommittedBytes: 0,
					Files:          e.Files,
					CreatedAt:      e.CreatedAt,
					UpdatedAt:      e.UpdatedAt,
					Status:         senderStatus(e),
					Resumable:      e.RecordOK && e.HasResumeSecret,
					Paths:          e.Paths,
				}
				items = append(items, item)
			}
		}
	}

	return items, nil
}

// InspectInterrupted checks the consistency of one interrupted receive journal.
func (s *TransferService) InspectInterrupted(transferID string, outDir string) (DurableInspectResult, error) {
	if transferID == "" {
		return DurableInspectResult{}, errors.New("transfer id is required")
	}
	if outDir == "" {
		if s.configStore != nil {
			if cfg, err := s.configStore.Load(); err == nil && cfg.DownloadDir != "" {
				outDir = cfg.DownloadDir
			}
		}
		if outDir == "" {
			outDir = "."
		}
	}
	store, err := s.openDurableStore(outDir)
	if err != nil {
		return DurableInspectResult{}, err
	}
	ins, err := store.Inspect(transferID)
	if err != nil {
		return DurableInspectResult{}, err
	}

	res := DurableInspectResult{
		TransferID:          ins.Journal.TransferID,
		TotalBytes:          ins.Total,
		CommittedBytes:      ins.Committed,
		CreatedAt:           ins.Journal.CreatedAt,
		UpdatedAt:           ins.Journal.UpdatedAt,
		ProtocolVersion:     ins.Journal.ProtocolVersion,
		ManifestFingerprint: ins.Journal.ManifestFingerprint,
		JournalPath:         ins.JournalPath,
		PartialDir:          ins.PartialDir,
		Resumable:           ins.Resumable,
		Problems:            ins.Problems,
	}
	for _, f := range ins.Journal.Files {
		res.Files = append(res.Files, FileInfo{Name: f.Name, Size: f.Size})
	}
	return res, nil
}

// ResumeInterrupted resumes an interrupted receive transfer using its stored credentials.
func (s *TransferService) ResumeInterrupted(transferID string, code string, destDir string, server string) (Handle, error) {
	if transferID == "" {
		return Handle{}, errors.New("transfer id is required")
	}
	if code == "" {
		return Handle{}, errors.New("an invite code from the sender is required to resume")
	}
	code = normalizeCode(code)
	if destDir == "" {
		if s.configStore != nil {
			if cfg, err := s.configStore.Load(); err == nil && cfg.DownloadDir != "" {
				destDir = cfg.DownloadDir
			}
		}
		if destDir == "" {
			destDir = "."
		}
	}
	if server == "" {
		if s.configStore != nil {
			if cfg, err := s.configStore.Load(); err == nil && cfg.ServerURL != "" {
				server = cfg.ServerURL
			}
		}
		if server == "" {
			server = DefaultServer
		}
	}

	store, err := s.openDurableStore(destDir)
	if err != nil {
		return Handle{}, err
	}
	ins, err := store.Inspect(transferID)
	if err != nil {
		return Handle{}, err
	}
	if !ins.Resumable {
		return Handle{}, fmt.Errorf("transfer %s is not resumable: %s", transferID, strings.Join(ins.Problems, "; "))
	}
	if ins.Journal.ResumeSecret == nil {
		return Handle{}, fmt.Errorf("transfer %s has no resume credential (legacy state); restart required", transferID)
	}
	secret, err := wire.DecodeResumeSecretEnvelope(&wire.ResumeSecretEnvelope{
		Version: ins.Journal.ResumeSecret.Version,
		Value:   ins.Journal.ResumeSecret.Value,
	})
	if err != nil {
		return Handle{}, fmt.Errorf("decode resume credential for %s: %w", transferID, err)
	}

	iceServers, err := s.resolveICEServers()
	if err != nil {
		return Handle{}, err
	}

	id := s.newID()
	r := s.newRun(id, wire.RoleJoiner)
	go r.runResumeReceive(r.ctx, transferID, code, destDir, server, secret, ins, iceServers)
	return Handle{ID: id, Role: "receive"}, nil
}

// DiscardInterrupted removes persistent state for one transfer id (idempotent).
func (s *TransferService) DiscardInterrupted(transferID string, outDir string) error {
	if transferID == "" {
		return errors.New("transfer id is required")
	}
	if outDir == "" {
		if s.configStore != nil {
			if cfg, err := s.configStore.Load(); err == nil && cfg.DownloadDir != "" {
				outDir = cfg.DownloadDir
			}
		}
		if outDir == "" {
			outDir = "."
		}
	}

	// Discard receive journal + partials
	if store, err := s.openDurableStore(outDir); err == nil {
		_ = store.Discard(transferID)
	}
	// Discard sender record
	s.mu.Lock()
	sstore := s.senderStore
	s.mu.Unlock()
	if sstore != nil {
		_ = sstore.Discard(transferID)
	}
	return nil
}

// DiscardAllInterrupted removes all durable transfer journals and sender records (idempotent).
func (s *TransferService) DiscardAllInterrupted(outDir string) error {
	if outDir == "" {
		if s.configStore != nil {
			if cfg, err := s.configStore.Load(); err == nil && cfg.DownloadDir != "" {
				outDir = cfg.DownloadDir
			}
		}
		if outDir == "" {
			outDir = "."
		}
	}
	if store, err := s.openDurableStore(outDir); err == nil {
		_ = store.DiscardAll()
	}
	s.mu.Lock()
	sstore := s.senderStore
	s.mu.Unlock()
	if sstore != nil {
		_ = sstore.DiscardAll()
	}
	return nil
}

// RevealCompleted reveals the verified completed transfer output in the OS file manager.
// The backend derives the path from trusted transfer state rather than arbitrary frontend input.
func (s *TransferService) RevealCompleted(id string) error {
	s.mu.Lock()
	targetPath, ok := s.completedDestinations[id]
	rm := s.revealMgr
	s.mu.Unlock()

	if !ok || targetPath == "" {
		return fmt.Errorf("no verified completed output found for transfer %q", id)
	}
	if rm == nil {
		rm = lifecycle.NewRevealManager(nil)
	}
	return rm.Reveal(targetPath, s.authorizedRoots()...)
}

// GetConfig returns the desktop persistent configuration.
func (s *TransferService) GetConfig() (config.DesktopConfig, error) {
	s.mu.Lock()
	cs := s.configStore
	s.mu.Unlock()
	if cs == nil {
		return config.DefaultConfig(), nil
	}
	return cs.Load()
}

// SaveConfig saves the desktop persistent configuration.
func (s *TransferService) SaveConfig(cfg config.DesktopConfig) error {
	s.mu.Lock()
	cs := s.configStore
	s.mu.Unlock()
	if cs == nil {
		return errors.New("config store not available")
	}
	return cs.Save(cfg)
}

// ActiveCount returns the number of in-flight transfers.
func (s *TransferService) ActiveCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.runs)
}

// OnSuspend handles OS application suspend.
func (s *TransferService) OnSuspend() {
	if s.emit != nil {
		s.emit(TransferEventName, &TransferEvent{
			Kind:  "lifecycle",
			Phase: "suspend",
		})
	}
}

// OnResume handles OS application resume from sleep.
func (s *TransferService) OnResume() {
	if s.emit != nil {
		s.emit(TransferEventName, &TransferEvent{
			Kind:  "lifecycle",
			Phase: "resume",
		})
	}
}

// OnNetworkChange handles OS network changes.
func (s *TransferService) OnNetworkChange() {
	if s.emit != nil {
		s.emit(TransferEventName, &TransferEvent{
			Kind:  "lifecycle",
			Phase: "network_change",
		})
	}
}

// Shutdown gracefully cancels active transfers and waits for bounded teardown.
func (s *TransferService) Shutdown(timeout time.Duration) error {
	s.mu.Lock()
	runs := make([]*transferRun, 0, len(s.runs))
	for _, r := range s.runs {
		runs = append(runs, r)
	}
	s.mu.Unlock()

	if len(runs) == 0 {
		return nil
	}

	for _, r := range runs {
		r.canc()
		r.mu.Lock()
		ctrl := r.controls
		r.mu.Unlock()
		if ctrl != nil {
			_ = ctrl.Cancel("application shutting down")
		}
	}

	deadline := time.Now().Add(timeout)
	for {
		s.mu.Lock()
		remaining := len(s.runs)
		s.mu.Unlock()
		if remaining == 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	return nil
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
		Resumed:     r.resumed,
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
func (r *transferRun) runSend(ctx context.Context, server string, sources []wire.FileSource, paths []string, iceServers []webrtc.ICEServer) {
	defer r.svc.remove(r)

	sig, err := r.svc.dial(ctx, server, wire.RoleOfferer)
	if err != nil {
		r.fail("dial: " + err.Error())
		if r.svc.notifier != nil {
			r.svc.notifier.NotifyFailure("Transfer Failed", "dial: "+err.Error())
		}
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

	var transferID string
	var onSendManifest func(wire.Manifest) error
	var resumeCtx *transfer.ResumeContext
	reused := false
	r.svc.mu.Lock()
	sstore := r.svc.senderStore
	r.svc.mu.Unlock()
	if sstore != nil {
		var prepErr error
		transferID, onSendManifest, reused, prepErr = transfer.PrepareSender(sstore, paths, sources)
		if prepErr != nil {
			r.fail("prepare sender: " + prepErr.Error())
			if r.svc.notifier != nil {
				r.svc.notifier.NotifyFailure("Transfer Failed", "prepare sender: "+prepErr.Error())
			}
			return
		}
		if reused {
			if srec, ok, lookupErr := sstore.Lookup(transfer.PathKey(paths)); lookupErr == nil && ok && srec.ResumeSecret != nil {
				if secret, err := wire.DecodeResumeSecretEnvelope(srec.ResumeSecret); err == nil {
					resumeCtx = &transfer.ResumeContext{
						TransferID:          srec.TransferID,
						ManifestFingerprint: srec.ManifestFingerprint,
						Role:                wire.RoleOfferer,
						ResumeSecret:        secret,
					}
				}
			}
		}
	}

	caps := rendezvous.DefaultCaps()
	if resumeCtx != nil {
		caps.Features = append(caps.Features, wire.ResumeAuthCapability)
	}

	spec := transfer.Spec{
		Session: rendezvous.Options{
			Role:      rendezvous.RoleOfferer,
			LocalCaps: &caps,
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
		TransferID:     transferID,
		OnSendManifest: onSendManifest,
		OnResumeCredential: func(manifest wire.Manifest, resumeRoot []byte) error {
			if sstore != nil {
				return sstore.AttachResumeSecret(manifest, resumeRoot, !reused)
			}
			return nil
		},
		Resume: resumeCtx,
		OnResume: func(res transfer.ResumeResult) {
			if res.Authenticated {
				r.mu.Lock()
				r.resumed = true
				r.mu.Unlock()
				r.publish("progress", func(ev *TransferEvent) { ev.Resumed = true })
			}
		},
		ForceRelay:     r.svc.forceRelay,
		ICEServers:     iceServers,
		OnTransport:    r.onTransport,
		OnConnect:      func() { r.publish("connect") },
		OnFileProgress: r.onFileProgress,
		OnResumeProgress: func(reusedBytes int64) {
			r.mu.Lock()
			r.reused = reusedBytes
			r.mu.Unlock()
		},
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
		if r.svc.notifier != nil {
			r.svc.notifier.NotifyFailure("Transfer Failed", err.Error())
		}
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
	if out.Handshake != nil {
		r.fingerprint = fingerprint(out.Handshake.Master)
	}
	r.mu.Unlock()

	if sstore != nil && transferID != "" {
		_ = sstore.Discard(transferID)
	}

	r.publish("done", func(ev *TransferEvent) {
		ev.Digest = out.Digest
		ev.Percent = 100
	})

	if r.svc.notifier != nil {
		summary := fmt.Sprintf("Sent %d file(s) (%s)", len(out.Files), humanBytes(r.totalBytes))
		r.svc.notifier.NotifySuccess("Transfer Complete", summary, "")
	}
}

// runReceive drives the joiner side of the transfer.
func (r *transferRun) runReceive(ctx context.Context, code, destDir, server string, iceServers []webrtc.ICEServer) {
	defer r.svc.remove(r)

	sig, err := r.svc.dial(ctx, server, wire.RoleJoiner)
	if err != nil {
		r.fail("dial: " + err.Error())
		if r.svc.notifier != nil {
			r.svc.notifier.NotifyFailure("Transfer Failed", "dial: "+err.Error())
		}
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
		ICEServers: iceServers,
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
		if r.svc.notifier != nil {
			r.svc.notifier.NotifyFailure("Transfer Failed", err.Error())
		}
		return
	}
	r.mu.Lock()
	r.doneBytes = out.Size
	r.filesDone = len(out.Files)
	if out.Handshake != nil {
		r.fingerprint = fingerprint(out.Handshake.Master)
	}
	r.mu.Unlock()

	outPath := out.Path
	if len(out.Files) > 1 {
		outPath = destDir
	}

	// Record verified completed destination for safe RevealCompleted
	r.svc.recordCompleted(r.id, outPath)

	r.publish("done", func(ev *TransferEvent) {
		ev.Digest = out.Digest
		ev.OutDir = destDir
		if len(out.Files) == 1 {
			ev.OutPath = out.Path
		}
		ev.Percent = 100
	})

	if r.svc.notifier != nil {
		label := out.Name
		if len(out.Files) > 1 {
			label = fmt.Sprintf("%d files", len(out.Files))
		}
		summary := fmt.Sprintf("Received %s (%s) into %s", label, humanBytes(out.Size), destDir)
		r.svc.notifier.NotifySuccess("Transfer Complete", summary, outPath)
	}
}

// runResumeReceive drives an interrupted receive transfer resumption.
func (r *transferRun) runResumeReceive(ctx context.Context, transferID, code, destDir, server string, secret []byte, ins *transfer.Inspect, iceServers []webrtc.ICEServer) {
	defer r.svc.remove(r)

	sig, err := r.svc.dial(ctx, server, wire.RoleJoiner)
	if err != nil {
		r.fail("dial: " + err.Error())
		if r.svc.notifier != nil {
			r.svc.notifier.NotifyFailure("Transfer Failed", "dial: "+err.Error())
		}
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

	caps := rendezvous.DefaultCaps()
	caps.Features = append(caps.Features, wire.ResumeAuthCapability)

	resumeCtx := &transfer.ResumeContext{
		TransferID:          transferID,
		ManifestFingerprint: ins.Journal.ManifestFingerprint,
		Role:                wire.RoleJoiner,
		ResumeSecret:        secret,
	}

	spec := transfer.Spec{
		Session: rendezvous.Options{
			Role:      rendezvous.RoleJoiner,
			Code:      code,
			LocalCaps: &caps,
			OnPhase: func(p rendezvous.Phase) {
				r.publish("phase", func(ev *TransferEvent) { ev.Phase = string(p) })
			},
		},
		DestDir:    destDir,
		ForceRelay: r.svc.forceRelay,
		ICEServers: iceServers,
		Resume:     resumeCtx,
		OnResume: func(res transfer.ResumeResult) {
			if res.Authenticated {
				r.mu.Lock()
				r.resumed = true
				r.mu.Unlock()
				r.publish("progress", func(ev *TransferEvent) { ev.Resumed = true })
			}
		},
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
		OnResumeProgress: func(reusedBytes int64) {
			r.mu.Lock()
			r.reused = reusedBytes
			r.mu.Unlock()
		},
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
			r.publish("connect")
		},
		OnStateChange: r.onState,
	}

	out, err := transfer.Run(ctx, sig, spec)
	if err != nil {
		r.fail(err.Error())
		if r.svc.notifier != nil {
			r.svc.notifier.NotifyFailure("Transfer Failed", err.Error())
		}
		return
	}
	r.mu.Lock()
	r.doneBytes = out.Size
	r.filesDone = len(out.Files)
	if out.Handshake != nil {
		r.fingerprint = fingerprint(out.Handshake.Master)
	}
	r.mu.Unlock()

	outPath := out.Path
	if len(out.Files) > 1 {
		outPath = destDir
	}

	// Record verified completed destination for safe RevealCompleted
	r.svc.recordCompleted(r.id, outPath)

	r.publish("done", func(ev *TransferEvent) {
		ev.Digest = out.Digest
		ev.OutDir = destDir
		if len(out.Files) == 1 {
			ev.OutPath = out.Path
		}
		ev.Percent = 100
	})

	if r.svc.notifier != nil {
		label := out.Name
		if len(out.Files) > 1 {
			label = fmt.Sprintf("%d files", len(out.Files))
		}
		summary := fmt.Sprintf("Received %s (%s) into %s", label, humanBytes(out.Size), destDir)
		r.svc.notifier.NotifySuccess("Transfer Complete", summary, outPath)
	}
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

// durableStatus renders receiver-side state class.
func durableStatus(entry transfer.DurableEntry) string {
	switch {
	case !entry.PartialOK:
		return "Partial data missing — inspect/discard"
	case !entry.HasResumeSecret:
		return "Legacy — restart required"
	default:
		return "Ready to resume"
	}
}

// senderStatus renders sender-side state class.
func senderStatus(entry transfer.SenderEntry) string {
	if !entry.HasResumeSecret {
		return "Legacy — restart required (no resume credential)"
	}
	return "Ready to resume (re-run to resume with receiver)"
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
// instant). Also verifies canonical relative path safety to prevent destination escape.
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
		// Validate base filename cannot contain traversal or invalid characters
		base := filepath.Base(p)
		if _, err := wire.NormalizeTransferPath(base); err != nil {
			return fmt.Errorf("invalid file path %s: %w", p, err)
		}
	}
	return nil
}

// humanBytes formats byte counts cleanly.
func humanBytes(n int64) string {
	if n >= 1<<30 {
		return fmt.Sprintf("%.2f GiB", float64(n)/float64(1<<30))
	}
	if n >= 1<<20 {
		return fmt.Sprintf("%.1f MiB", float64(n)/float64(1<<20))
	}
	if n >= 1<<10 {
		return fmt.Sprintf("%.1f KiB", float64(n)/float64(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// formatETA renders a duration like the CLI (e.g. "2m 5s remaining").
func formatETA(eta time.Duration) string {
	seconds := int64(math.Ceil(eta.Seconds()))
	if seconds < 60 {
		return fmt.Sprintf("%ds remaining", seconds)
	}
	return fmt.Sprintf("%dm %ds remaining", seconds/60, seconds%60)
}
