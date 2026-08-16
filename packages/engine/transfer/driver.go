// Package transfer wires a completed rendezvous into a direct-or-relayed file transfer: it adopts
// the open signaling socket, prefers an authenticated WebRTC DataChannel (internal/rtc), and falls
// back to the encrypted relay before running the transport-agnostic engine (packages/wire). The
// offerer sends the file and the joiner writes it to disk. It is the CLI counterpart of
// apps/web/src/lib/transfer/transfer-core.ts, adapted to Go concurrency and OS files.
package transfer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"sync"

	"github.com/pion/webrtc/v4"
	relaytransport "github.com/sendbeam/engine/relay"
	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/engine/rtc"
	"github.com/sendbeam/engine/supervisor"
	"github.com/sendbeam/wire"
)

// Signal is the live signaling connection the driver adopts for the whole exchange — first the
// handshake, then SDP/ICE negotiation or opaque relay frames. *wsclient.Client satisfies it;
// tests supply an in-memory relay.
type Signal interface {
	Send(rendezvous.Message) error
	SendBinary([]byte) error
	Run(ctx context.Context, onMessage func(rendezvous.Message), onBinary func([]byte)) error
	Close()
}

// ReconnectSetter is implemented by signals that can re-attach to the signaling room after a
// post-establishment drop (e.g. wsclient.ReconnectingSignal), so the driver can arm them with
// the room and role once the handshake settles.
type ReconnectSetter interface {
	SetResume(room int, role string)
}

// Controls is the live transfer surface exposed to terminal frontends.
type Controls interface {
	Pause() error
	Resume() error
	Cancel(reason string) error
}

// Spec configures one side of a transfer. Session carries the handshake inputs (role, code,
// caps, progress callbacks); the driver supplies its Transport. A sending (offerer) spec sets
// Source; a receiving (joiner) spec sets DestDir.
type Spec struct {
	Session rendezvous.Options
	// Source is the file to send; required for an offerer, ignored for a joiner.
	Source wire.FileSource
	// Sources is an ordered multi-file/folder set. Set either Source or Sources.
	Sources []wire.FileSource
	// DestDir is the directory the received file is written into; used by a joiner.
	DestDir string
	// TransferID, when set, is the stable id to advertise in the manifest (V13-PR04
	// sender restart): the wire layer prefers it over its mint. Empty keeps the existing
	// NewTransferID mint.
	TransferID string
	// OnSendManifest, when set, is wired into the wire sender's OnManifest hook: it runs
	// with the validated manifest strictly before its frame is transmitted, so a sender can
	// persist or verify its restart record before the id is advertised. An error aborts the
	// send without transmitting the manifest.
	OnSendManifest func(wire.Manifest) error
	// OnResumeCredential, when set, is invoked (after OnSendManifest) with the validated
	// manifest and the resume root derived from the ORIGINAL session master (V13-PR07). It
	// persists the transfer-scoped resume credential into the sender record strictly before
	// the manifest frame is transmitted; a restart's already-persisted credential is never
	// replaced.
	OnResumeCredential func(manifest wire.Manifest, resumeRoot []byte) error
	// Resume carries the local cross-session resume context (V13-PR08). It is set ONLY on a
	// peer that can actually authenticate a resume for this attempt: the sender re-using an
	// interrupted record that holds a credential, or the receiver whose user pre-selected an
	// interrupted journal holding one. Its presence makes the peer advertise resume-auth-v1;
	// durable progress from the previous session is reused only after the mutual
	// resume-auth preamble succeeds and the transfer runs under a fresh key epoch.
	Resume *ResumeContext
	// OnResume reports the cross-session resume decision (attempted/authenticated) for UX.
	OnResume func(ResumeResult)
	// ICEServers overrides rtc.DefaultICEServers. An explicit empty slice uses host candidates
	// only (loopback tests); nil takes the default STUN server.
	ICEServers []webrtc.ICEServer
	// ForceRelay skips direct negotiation and goes straight to the encrypted relay.
	ForceRelay bool
	// OnTransport reports "direct" or "relay" when the selected byte path changes.
	OnTransport func(string)
	// OnConnect fires once the DataChannel opens, before the first byte moves.
	OnConnect func()
	// OnManifest fires on the receiver when the sender's manifest arrives (file named and sized).
	OnManifest func(wire.FileEntry)
	// OnManifestSet fires once with the complete validated file set.
	OnManifestSet func(wire.Manifest)
	// OnProgress reports cumulative bytes acknowledged after verify-and-sink.
	OnProgress     func(int64)
	OnFileProgress func(fileIdx int, fileBytes, acknowledgedBytes int64)
	// OnResumeProgress reports the verified baseline reused from the authenticated durable
	// checkpoint at resume start, once, before the first new block is acknowledged. The host
	// anchors its session rate on it: sessionBytes = verified - reused (V13-PR08).
	OnResumeProgress func(int64)
	// OnControls receives the live engine after the channel opens, before bytes begin moving.
	OnControls func(Controls)
	// OnStateChange reports pause, resume, and remote cancellation.
	OnStateChange func(wire.TransferState)
	// breakDirect is a deterministic in-package integration hook.
	breakDirect <-chan struct{}
	// breakDirectRecovery simulates the peer's recovery-failure hook firing (direct recovery
	// failed) so the driver falls back to the relay. Test-only.
	breakDirectRecovery <-chan struct{}
}

// ResumeContext is the local resume context of an interrupted transfer (V13-PR08). It is
// local state only — the transfer id, the canonical manifest fingerprint, the stable role,
// and the decoded transfer-scoped credential — and is NEVER transmitted: the resume-auth
// transcript binds these values on both peers, so a mismatch fails closed without leaking
// any of them. The credential is never printed, logged, or exposed.
type ResumeContext struct {
	TransferID          string
	ManifestFingerprint string
	Role                wire.Role
	ResumeSecret        []byte
}

// ResumeResult reports the cross-session resume decision to the host for UX (V13-PR08).
// Attempted is true when both peers advertised resume-auth-v1 and the preamble ran;
// Authenticated is true only when mutual authentication completed and the transfer runs
// under a fresh resumed key epoch — the only state in which old durable progress may be
// reused. Skipped is true when the peer could not authenticate a resume (e.g. a fresh
// sender for a receiver that pre-selected a journal) and the transfer proceeds fresh with
// the local interrupted state untouched.
type ResumeResult struct {
	Attempted     bool
	Authenticated bool
	Skipped       bool
}

// Outcome is the result of a completed transfer.
type Outcome struct {
	Handshake *rendezvous.Result
	Name      string
	Size      int64
	Digest    string // whole-file SHA-256 (hex); identical on both peers
	Path      string // receiver: the written file; empty for a sender
	Files     []FileOutcome
}

// FileOutcome is one source or received destination within an Outcome.
type FileOutcome struct {
	Name   string
	Size   int64
	Digest string
	Path   string
}

// Run performs the handshake over sig and then the file transfer, returning when the transfer
// settles. It adopts sig for the whole exchange: the same socket that carries the SPAKE2
// handshake carries the sdp/ice signaling afterwards, so the read loop switches from feeding the
// session to feeding the peer once the key is established.
func Run(ctx context.Context, sig Signal, spec Spec) (*Outcome, error) {
	d := &driver{sig: sig, spec: spec, peerCh: make(chan *rtc.Peer, 1), warmSignal: make(chan struct{}, 1)}
	return d.run(ctx)
}

type driver struct {
	sig  Signal
	spec Spec

	mu   sync.Mutex // serializes every socket write (session, sendOffer, pion's ICE goroutine)
	sess *rendezvous.Session

	// peer and res are set once, by the read-loop goroutine, at establishment; peerCh publishes
	// the peer to run once it exists.
	peer   *rtc.Peer
	relay  *relaytransport.Conn
	res    *rendezvous.Result
	peerCh chan *rtc.Peer

	// pol is the adaptive direct/relay racing policy driven by the direct peer's ICE progress.
	// It is created alongside the peer in route() when direct negotiation is attempted, and
	// nil when relay-only or relay fallback. warmSignal is signalled once the policy decides
	// the relay should be warmed (buffered so a decision that fires before selectTransport
	// starts is not lost).
	pol        *AdaptivePolicy
	warmSignal chan struct{}

	// adaptive is the direct→relay cutover connection once selected (set in run()); the peer's
	// recovery-failure hook uses it to fall back to the relay. recovering reports the transient
	// ICE-disconnect recovery window for the terminal's OnTransport status. Both are guarded by mu.
	adaptive   *adaptiveConn
	recovering bool
}

// Send implements rendezvous.Sink for the handshake session and doubles as the peer's send
// callback. It serializes every socket write: the read loop (relaying an answer),
// the offerer's sendOffer goroutine, and pion's ICE-candidate goroutine can all write at once,
// and coder/websocket permits only one writer at a time.
func (d *driver) Send(m rendezvous.Message) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sig.Send(m)
}

// SendBinary serializes opaque relay writes with signaling control writes on the WebSocket.
func (d *driver) SendBinary(frame []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sig.SendBinary(frame)
}

func (d *driver) run(ctx context.Context) (*Outcome, error) {
	opts := d.spec.Session
	opts.Transport = d
	d.sess = rendezvous.New(opts)

	// On a handshake failure, close the socket so the read loop unblocks; on success keep it
	// open — WebRTC signaling still needs it.
	go func() {
		<-d.sess.Done()
		if _, err := d.sess.Result(); err != nil {
			d.sig.Close()
		}
	}()

	readErr := make(chan error, 1)
	go func() { readErr <- d.sig.Run(ctx, d.route, d.routeBinary) }()

	d.sess.Start()

	var peer *rtc.Peer
	select {
	case peer = <-d.peerCh:
	case err := <-readErr:
		// The socket ended before the peer was built: surface the handshake failure, or a raw
		// transport error if it dropped mid-handshake.
		if _, herr := d.sess.Result(); herr != nil {
			return nil, herr
		}
		if err == nil {
			err = wire.Errorf(wire.CodeConnection, "transfer: signaling closed before the channel opened")
		}
		return nil, err
	case <-ctx.Done():
		d.sess.Abort("cancelled")
		return nil, ctx.Err()
	}

	res := d.res
	conn, path, err := d.selectTransport(ctx, peer, readErr)
	if err != nil {
		if peer != nil {
			_ = peer.Close()
		}
		d.sig.Close()
		return nil, err
	}
	if d.spec.OnTransport != nil {
		d.spec.OnTransport(path)
	}
	var adaptive *adaptiveConn
	var sv *supervisor.Supervisor
	if path == "direct" {
		sv = supervisor.New()
		adaptive = newAdaptiveConn(conn.(*rtc.DataConn), d.relay, d.spec.OnTransport, sv)
		d.mu.Lock()
		d.adaptive = adaptive
		d.mu.Unlock()
		_ = sv.Register(supervisor.PathDirect, conn.(*rtc.DataConn))
		_ = sv.Warming(supervisor.PathDirect)
		_ = sv.Ready(supervisor.PathDirect)
		_, _ = sv.Activate(supervisor.PathDirect)
		_ = sv.Register(supervisor.PathRelay, d.relay)
		conn = adaptive
		if d.spec.breakDirect != nil {
			go func() {
				select {
				case <-d.spec.breakDirect:
					_ = peer.Close()
				case <-ctx.Done():
				}
			}()
		}
		if d.spec.breakDirectRecovery != nil {
			go func() {
				select {
				case <-d.spec.breakDirectRecovery:
					d.mu.Lock()
					ad := d.adaptive
					d.mu.Unlock()
					if ad != nil {
						ad.FallbackToRelay()
					}
				case <-ctx.Done():
				}
			}()
		}
	} else {
		sv = supervisor.New()
		_ = sv.Register(supervisor.PathRelay, d.relay)
		_ = sv.Warming(supervisor.PathRelay)
		_ = sv.Ready(supervisor.PathRelay)
		_, _ = sv.Activate(supervisor.PathRelay)
	}
	if d.spec.OnConnect != nil {
		d.spec.OnConnect()
	}

	transferCtx, cancelTransfer := context.WithCancel(ctx)
	type transferResult struct {
		out *Outcome
		err error
	}
	transferDone := make(chan transferResult, 1)
	go func() {
		result, transferErr := d.transfer(transferCtx, conn, sv, res)
		transferDone <- transferResult{out: result, err: transferErr}
	}()
	var out *Outcome
	var terr error
	readEnded := false
	readCh := (<-chan error)(readErr)
	for {
		select {
		case result := <-transferDone:
			out, terr = result.out, result.err
			cancelTransfer()
			goto transferSettled
		case <-ctx.Done():
			// The engine may be stuck inside Send on a stalled transport (SCTP or relay
			// credit waits have no deadline of their own); closing the connection is the
			// only thing that unblocks it, so never wait for transferDone first.
			cancelTransfer()
			_ = conn.Close()
			<-transferDone
			terr = ctx.Err()
			goto transferSettled
		case sigErr := <-readCh:
			readEnded = true
			if sigErr == nil {
				sigErr = wire.Errorf(wire.CodeConnection, "signaling closed")
			}
			if adaptive != nil && !adaptive.IsRelay() {
				adaptive.SignalingLost(sigErr)
				readCh = nil // a healthy direct channel can finish without signaling
				continue
			}
			cancelTransfer()
			_ = conn.Close()
			<-transferDone
			if ctx.Err() != nil {
				terr = ctx.Err()
			} else {
				terr = wire.Errorf(wire.CodeRelay, "transfer: relay connection lost: %v", sigErr)
			}
			goto transferSettled
		}
	}

transferSettled:

	// Drain the data channel before tearing down the peer: the first side to finish (the
	// receiver, once it has sent done) must let that final frame reach the wire, or closing the
	// PeerConnection aborts SCTP and the waiting sender never learns the transfer completed.
	_ = conn.Close()
	if peer != nil {
		_ = peer.Close()
	}
	d.sig.Close()
	if !readEnded {
		<-readErr // let the read loop drain once the socket is closed
	}

	if terr != nil {
		return nil, terr
	}
	out.Handshake = res
	return out, nil
}

type dataConn interface {
	Send([]byte) error
	OnData(func([]byte))
	Close() error
}

type rtcResult struct {
	conn *rtc.DataConn
	err  error
}

func (d *driver) selectTransport(ctx context.Context, peer *rtc.Peer, readErr <-chan error) (dataConn, string, error) {
	if d.relay == nil {
		return nil, "", wire.Errorf(wire.CodeRelay, "transfer: relay was not initialized")
	}
	direct := make(chan rtcResult, 1)
	if peer != nil && !d.spec.ForceRelay {
		go func() {
			conn, err := peer.Channel(ctx)
			direct <- rtcResult{conn: conn, err: err}
		}()
	} else if err := d.relay.Open(); err != nil {
		return nil, "", err
	}

	// Replaced the old blind ~8s fallback timer with a policy-driven decision: the relay is
	// warmed only when ICE progress shows the direct path is not viable (no server-reflexive
	// hints, ICE failure, or a bounded no-hint escalation), then raced against direct.
	warmCh := d.warmSignal
	relayWarm := false
	warmRelay := func() error {
		if relayWarm {
			return nil
		}
		if err := d.relay.Open(); err != nil {
			return wire.Errorf(wire.CodeRelay, "transfer: relay warm: %v", err)
		}
		relayWarm = true
		warmCh = nil
		return nil
	}

	for {
		select {
		case result := <-direct:
			if result.err == nil {
				// Direct won the race. The relay, if warmed, is intentionally retained as the
				// ready cutover fallback (V12-PR05 owns migration); only the losing direct peer
				// (and relay winner) release their candidates below.
				return result.conn, "direct", nil
			}
			if err := warmRelay(); err != nil {
				return nil, "", err
			}
			direct = nil
		case <-warmCh:
			if err := warmRelay(); err != nil {
				return nil, "", err
			}
		case <-d.relay.Ready():
			if peer != nil {
				_ = peer.Close()
			}
			return d.relay, "relay", nil
		case err := <-readErr:
			if err == nil {
				err = wire.Errorf(wire.CodeConnection, "signaling closed")
			}
			return nil, "", wire.Errorf(wire.CodeConnection, "transfer: signaling: %v", err)
		case <-ctx.Done():
			return nil, "", ctx.Err()
		}
	}
}

// route is the single inbound dispatch. Before establishment it feeds the handshake session;
// the instant the session establishes it builds the peer — synchronously, so the peer exists
// before the next frame (the offer, for a joiner) is read — and thereafter feeds the peer.
// Running entirely on the read-loop goroutine makes the switch race-free.
func (d *driver) route(m rendezvous.Message) {
	if d.res != nil {
		if d.relay != nil && d.relay.HandleMessage(m) {
			return
		}
		if d.peer != nil {
			d.peer.Accept(m)
		}
		return
	}
	d.sess.Handle(m)
	if d.res != nil {
		return
	}
	select {
	case <-d.sess.Done():
	default:
		return // still handshaking
	}
	res, err := d.sess.Result()
	if err != nil {
		return // handshake failed; the watcher goroutine closes the socket
	}
	var peer *rtc.Peer
	if !d.spec.ForceRelay {
		var perr error
		d.pol = NewAdaptivePolicy(0)
		peer, perr = rtc.NewPeer(rtc.PeerOptions{
			Role:       res.Role,
			Auth:       rtc.FromSession(res.Role, res.Room, res.Spake2),
			Send:       d.Send,
			ICEServers: d.spec.ICEServers,
			OnICEState: func(s rtc.ICEState) {
				ev := AdaptiveEvent{
					Gathering:          adaptiveGathering(s.Gathering.String()),
					Connection:         adaptiveConnection(s.Connection.String()),
					HasServerReflexive: s.HasServerReflexive,
					HasAnyCandidate:    s.HasAnyCandidate,
				}
				if d.pol.Observe(ev) == DecisionWarmRelay {
					select {
					case d.warmSignal <- struct{}{}:
					default:
					}
				}
			},
			OnRecovering: func(rec bool) { d.reportRecovering(rec) },
			OnRecoverFailed: func() {
				d.mu.Lock()
				ad := d.adaptive
				d.mu.Unlock()
				if ad != nil {
					ad.FallbackToRelay()
				}
			},
		})
		if perr != nil {
			d.sig.Close()
			return
		}
	}
	d.res = res
	// Arm a reconnect-capable signal with the room/role once the handshake settles, so a later
	// signaling drop can re-attach to the room (V12-PR04 signaling recovery).
	if rs, ok := d.sig.(ReconnectSetter); ok {
		rs.SetResume(res.Room, string(res.Role))
	}
	d.relay = relaytransport.New(d)
	d.peer = peer
	d.peerCh <- peer
}

func (d *driver) routeBinary(frame []byte) {
	if d.relay != nil {
		d.relay.HandleBinary(frame)
	}
}

// reportRecovering exposes the direct path's transient ICE-disconnect recovery window as a
// distinct transport status ("recovering"), and returns to "direct" once the path recovers.
// A recovery that never returns to connected transfers to the relay via the fallback hook, so
// reporting "direct" here only fires while the byte path is still direct.
func (d *driver) reportRecovering(rec bool) {
	if rec {
		d.mu.Lock()
		d.recovering = true
		d.mu.Unlock()
		if d.spec.OnTransport != nil {
			d.spec.OnTransport("recovering")
		}
		return
	}
	d.mu.Lock()
	d.recovering = false
	ad := d.adaptive
	d.mu.Unlock()
	if ad == nil || ad.IsRelay() {
		return
	}
	if d.spec.OnTransport != nil {
		d.spec.OnTransport("direct")
	}
}

// transfer runs the engine over the open channel: the offerer sends its file, the joiner
// receives one. Counters continue from the handshake so the AES-GCM nonce is never reused, and
// block/frame sizes are the min of the two peers' announced caps. Canceling ctx aborts the
// in-flight transfer.
//
// V13-PR08: when both peers can authenticate a cross-session resume, the resume preamble
// runs over the sealed session channel strictly before the engine starts — the engine is
// then constructed with the FRESH resumed key epoch (new keys, new salts, counters 0), so
// no Manifest/ResumeState/BlockData/Complete can flow before mutual resume authentication.
func (d *driver) transfer(ctx context.Context, conn dataConn, sv *supervisor.Supervisor, res *rendezvous.Result) (*Outcome, error) {
	sendDir, recvDir := directionalKeys(res)
	preamble, err := d.prepareResumePreamble(conn, res, sendDir, recvDir)
	if err != nil {
		return nil, err
	}
	sendStart, recvStart := res.SendCounter, res.RecvCounter
	if res.Role == wire.RoleOfferer {
		return d.send(ctx, conn, sv, res, sendDir, recvDir, sendStart, recvStart, preamble)
	}
	return d.receive(ctx, conn, sv, res, sendDir, recvDir, sendStart, recvStart, preamble)
}

// prepareResumePreamble decides whether this session performs an authenticated cross-session
// resume (V13-PR08). It returns a preamble to run when BOTH the local peer has resume
// context (Spec.Resume) and the remote peer advertised resume-auth-v1. The security
// invariant: capability absent/stripped/untrusted ⇒ the interrupted transfer id is never
// reused — the offerer fails closed before anything is sent, and a receiver whose
// pre-selected resume does not materialize proceeds as a fresh receive with its journal
// untouched.
func (d *driver) prepareResumePreamble(conn dataConn, res *rendezvous.Result, sendDir, recvDir wire.DirectionalKey) (*wire.ResumePreamble, error) {
	if d.spec.Resume == nil {
		return nil, nil
	}
	// Role binding (V13-PR08 review): the persisted/host resume role MUST equal the actual
	// rendezvous role of this session. A mismatched role is a hard failure — never silently
	// ignored — because the resume-auth transcript binds the role, and a wrong claim can
	// only come from misusing local interrupted state across a different session shape.
	if d.spec.Resume.Role != res.Role {
		return nil, wire.Errorf(wire.CodeProtocol,
			"transfer: resume role mismatch: the interrupted %s state cannot resume in this %s session; nothing was sent or received — restart the resume with the matching side",
			d.spec.Resume.Role, res.Role)
	}
	if !wire.NegotiateResumeAuth([]string{wire.ResumeAuthCapability}, res.RemoteCaps.Features) {
		if res.Role == wire.RoleOfferer {
			return nil, wire.Errorf(wire.CodeCompat,
				"transfer: the receiver did not advertise authenticated resume (resume-auth-v1); the interrupted transfer id %s cannot be reused without it — nothing was sent. Have the receiver join with %q, or discard the sender record to send fresh",
				d.spec.Resume.TransferID, "sendbeam transfers resume <id> --code <fresh-code>")
		}
		// The sender started a fresh transfer (no resume context): the receiver's
		// pre-selected journal stays untouched and the receive proceeds fresh.
		if d.spec.OnResume != nil {
			d.spec.OnResume(ResumeResult{Skipped: true})
		}
		return nil, nil
	}
	if d.spec.OnResume != nil {
		d.spec.OnResume(ResumeResult{Attempted: true})
	}
	preamble, err := wire.NewResumePreamble(wire.ResumePreambleOptions{
		Role:         res.Role,
		TransferID:   d.spec.Resume.TransferID,
		Fingerprint:  d.spec.Resume.ManifestFingerprint,
		ResumeSecret: d.spec.Resume.ResumeSecret,
		Send:         conn.Send,
		SendDir:      sendDir,
		RecvDir:      recvDir,
		SendCounter:  res.SendCounter,
		RecvCounter:  res.RecvCounter,
	})
	if err != nil {
		return nil, wire.Errorf(wire.CodeAuth, "transfer: prepare resume preamble: %v", err)
	}
	return preamble, nil
}

// runPreamble drives the resume preamble to completion (bounded by ctx), returning the
// fresh resumed key epoch. It is called with the inbound router already wired to the
// preamble, so responses flow while we wait. A failed handshake aborts the transfer before
// the manifest.
func runPreamble(ctx context.Context, preamble *wire.ResumePreamble) (*wire.ResumeAuthResult, error) {
	if preamble == nil {
		return nil, nil
	}
	if err := preamble.Start(); err != nil {
		return nil, err
	}
	select {
	case <-preamble.Done():
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return preamble.Result()
}

// engineRouter hands inbound frames to the resume preamble while it is in flight, then to
// the transfer engine. Frames arriving between the preamble settling and the engine being
// installed (the peer may send its manifest the moment its own preamble settles) are
// queued and replayed in order, so no frame is ever dropped or misrouted.
type engineRouter struct {
	mu      sync.Mutex
	pending [][]byte
	engine  func([]byte)
}

func (r *engineRouter) route(preamble *wire.ResumePreamble, frame []byte) {
	if preamble != nil && !preamble.Settled() {
		preamble.Handle(frame)
		return
	}
	r.mu.Lock()
	if r.engine == nil {
		r.pending = append(r.pending, frame)
		r.mu.Unlock()
		return
	}
	engine := r.engine
	r.mu.Unlock()
	engine(frame)
}

func (r *engineRouter) install(engine func([]byte)) {
	r.mu.Lock()
	r.engine = engine
	pending := r.pending
	r.pending = nil
	r.mu.Unlock()
	for _, frame := range pending {
		engine(frame)
	}
}

// resumedDirs selects the directional keys of a fresh resumed key epoch for this role.
func resumedDirs(role wire.Role, result *wire.ResumeAuthResult) (send, recv wire.DirectionalKey) {
	if role == wire.RoleOfferer {
		return result.Keys.O2J, result.Keys.J2O
	}
	return result.Keys.J2O, result.Keys.O2J
}

func (d *driver) send(ctx context.Context, conn dataConn, sv *supervisor.Supervisor, res *rendezvous.Result, sendDir, recvDir wire.DirectionalKey, sendStart, recvStart uint64, preamble *wire.ResumePreamble) (*Outcome, error) {
	if (d.spec.Source == nil) == (len(d.spec.Sources) == 0) {
		return nil, errors.New("transfer: exactly one of Source or Sources is required to send")
	}
	sources := d.spec.Sources
	if len(sources) == 0 {
		sources = []wire.FileSource{d.spec.Source}
	}
	needsFolders := len(sources) > 1
	for _, source := range sources {
		if strings.Contains(source.Meta().Name, "/") {
			needsFolders = true
		}
	}
	if needsFolders && !containsString(res.RemoteCaps.Features, "folders") {
		return nil, wire.Errorf(wire.CodeCompat, "transfer: receiver does not support files or folders as a set")
	}
	// V13-PR07: the transfer-scoped resume credential derives from the ORIGINAL session
	// master, so it is available only after the handshake. The driver derives the narrow
	// resume root here and hands it to the host seam, which persists the credential into the
	// sender record strictly before the manifest frame is transmitted.
	resumeRoot, err := wire.ResumeRoot(res.Master)
	if err != nil {
		return nil, wire.Errorf(wire.CodeAuth, "transfer: derive resume root: %v", err)
	}
	onManifest := d.spec.OnSendManifest
	onResumeCredential := d.spec.OnResumeCredential
	// V13-PR08: the resume preamble runs strictly before the manifest may go out. The inbound
	// router is wired to the preamble FIRST (so challenge/ready responses flow while we
	// wait); the engine is constructed only AFTER mutual authentication, using the fresh
	// resumed key epoch when one was derived (never the session keys for the transfer).
	router := &engineRouter{}
	if sv != nil {
		sv.OnData(func(frame []byte) { router.route(preamble, frame) })
	} else {
		conn.OnData(func(frame []byte) { router.route(preamble, frame) })
	}
	if preamble != nil {
		result, err := runPreamble(ctx, preamble)
		if err != nil {
			return nil, err
		}
		sendDir, recvDir = resumedDirs(res.Role, result)
		sendStart, recvStart = result.SendCounter, result.RecvCounter
		if d.spec.OnResume != nil {
			d.spec.OnResume(ResumeResult{Attempted: true, Authenticated: true})
		}
	}
	sender := wire.NewSender(wire.SenderOptions{
		Files:            sources,
		Send:             conn.Send,
		SendDir:          sendDir,
		RecvDir:          recvDir,
		SendCounterStart: sendStart,
		RecvCounterStart: recvStart,
		BlockSize:        negotiate(res.LocalCaps.BlockSize, res.RemoteCaps.BlockSize, wire.DefaultBlockBytes),
		FrameSize:        negotiate(res.LocalCaps.MaxFrame, res.RemoteCaps.MaxFrame, wire.DefaultFrameBytes),
		// Advertise a stable random id in the manifest so a receiver that crashes mid-file
		// can journal its verified progress and resume it (V13-PR02); the wire layer mints
		// and validates it without any protocol change. A restart (V13-PR04) reuses the
		// record's id, which the wire layer prefers over the mint.
		TransferID:    d.spec.TransferID,
		NewTransferID: newTransferID,
		OnManifest: func(manifest wire.Manifest) error {
			// The record (stable id + source identity) is persisted first; only then is the
			// resume credential attached — both strictly before the manifest frame goes out.
			if onManifest != nil {
				if err := onManifest(manifest); err != nil {
					return err
				}
			}
			if onResumeCredential != nil {
				return onResumeCredential(manifest, resumeRoot)
			}
			return nil
		},
		OnProgress:     d.spec.OnProgress,
		OnFileProgress: d.spec.OnFileProgress,
		OnResume:       d.spec.OnResumeProgress,
		OnStateChange:  d.spec.OnStateChange,
	})
	if sv != nil {
		sv.SetOnSwitch(sender.TransportChanged)
	}
	router.install(sender.Handle)
	if d.spec.OnControls != nil {
		d.spec.OnControls(sender)
	}
	digest, err := sender.Run(ctx)
	if err != nil {
		return nil, err
	}
	files := make([]FileOutcome, len(sources))
	var total int64
	for i, source := range sources {
		meta := source.Meta()
		files[i] = FileOutcome{Name: meta.Name, Size: meta.Size}
		total += meta.Size
	}
	return &Outcome{Name: files[0].Name, Size: total, Digest: digest, Files: files}, nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func (d *driver) receive(ctx context.Context, conn dataConn, sv *supervisor.Supervisor, res *rendezvous.Result, sendDir, recvDir wire.DirectionalKey, sendStart, recvStart uint64, preamble *wire.ResumePreamble) (*Outcome, error) {
	destination, err := NewDurableDestination(d.spec.DestDir)
	if err != nil {
		return nil, wire.NewTransferError(wire.FailSinkError, err.Error())
	}
	// V13-PR08: an explicit resume attempt pre-selects its interrupted journal locally; its
	// verified progress is reused only after resume-auth succeeds in this session.
	if d.spec.Resume != nil {
		destination.ExpectResume(d.spec.Resume.TransferID)
	}
	// The inbound router is wired BEFORE the preamble runs: the offerer's resume_init may
	// arrive the moment its own preamble starts, and the transport buffers it until a
	// handler is registered. Frames arriving between the preamble settling and the engine
	// being installed (the manifest, sent once the offerer's own preamble settled) are
	// queued by the router in order.
	router := &engineRouter{}
	if sv != nil {
		sv.OnData(func(frame []byte) { router.route(preamble, frame) })
	} else {
		conn.OnData(func(frame []byte) { router.route(preamble, frame) })
	}
	if preamble != nil {
		result, err := runPreamble(ctx, preamble)
		if err != nil {
			return nil, err
		}
		destination.SetResumeAuthorized()
		sendDir, recvDir = resumedDirs(res.Role, result)
		sendStart, recvStart = result.SendCounter, result.RecvCounter
		if d.spec.OnResume != nil {
			d.spec.OnResume(ResumeResult{Attempted: true, Authenticated: true})
		}
	}
	// sharedResume is filled from OnManifestSet, before the wire layer applies the resume
	// seed: when the authenticated manifest matches a durable journal, the driver rebuilds
	// per-file high-water marks and digest prefixes from the persisted partials. A zero
	// value (or a TransferID mismatch) means a fresh receive, exactly as the wire layer
	// documents for ReceiverResume.
	var sharedResume wire.ReceiverResume
	receiver := wire.NewReceiver(wire.ReceiverOptions{
		Send:             conn.Send,
		SendDir:          sendDir,
		RecvDir:          recvDir,
		SendCounterStart: sendStart,
		RecvCounterStart: recvStart,
		Destination:      destination,
		Resume:           &sharedResume,
		OnProgress:       d.spec.OnProgress,
		OnFileProgress:   d.spec.OnFileProgress,
		OnResume:         d.spec.OnResumeProgress,
		OnStateChange:    d.spec.OnStateChange,
		OnManifestSet: func(manifest wire.Manifest) error {
			if d.spec.OnManifestSet != nil {
				d.spec.OnManifestSet(manifest)
			}
			// Fail closed when the journal's claims cannot be backed by durable partial
			// data; nothing is deleted and the transfer stops with guidance.
			resume, err := destination.ResumeStateFor(manifest)
			if err != nil {
				return err
			}
			if resume != nil {
				sharedResume = *resume
			}
			// V13-PR07: the transfer-scoped resume credential derives from the ORIGINAL
			// session master, so it is available only after the handshake. The driver
			// derives the narrow resume root here and persists the credential into the
			// receive journal — after the manifest validated and bound to it, strictly
			// before that credential can authorize a future cross-session resume.
			resumeRoot, rootErr := wire.ResumeRoot(res.Master)
			if rootErr != nil {
				return wire.Errorf(wire.CodeAuth, "transfer: derive resume root: %v", rootErr)
			}
			if attachErr := destination.AttachResumeSecret(manifest, resumeRoot); attachErr != nil {
				return attachErr
			}
			return nil
		},
		OnManifest: func(file wire.FileEntry) error {
			if d.spec.OnManifest != nil {
				d.spec.OnManifest(file)
			}
			return nil
		},
	})
	if sv != nil {
		sv.SetOnSwitch(receiver.TransportChanged)
	}
	router.install(receiver.Handle)
	if d.spec.OnControls != nil {
		d.spec.OnControls(receiver)
	}
	result, err := receiver.Wait(ctx)
	if err != nil {
		return nil, err
	}
	files := make([]FileOutcome, len(result.Files))
	for i, file := range result.Files {
		files[i] = FileOutcome{Name: file.Name, Size: file.Size, Digest: result.Digests[i], Path: destination.Path(file.Idx)}
	}
	return &Outcome{
		Name: result.File.Name, Size: result.TotalSize, Digest: result.Digest,
		Path: destination.Path(result.File.Idx), Files: files,
	}, nil
}

// newTransferID mints a random 128-bit lowercase hex id so the manifest opts into
// resumption (a manifest without one never has a durable journal). crypto/rand failure is
// catastrophic but effectively impossible; returning empty would silently disable
// resumption, so it is preferred over panicking the transfer.
func newTransferID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// directionalKeys selects the seal/open keys for this peer's role, mirroring the session's
// sendDir/recvDir: the offerer sends on O2J and receives on J2O; the joiner is the mirror.
func directionalKeys(res *rendezvous.Result) (send, recv wire.DirectionalKey) {
	if res.Role == wire.RoleOfferer {
		return res.Keys.O2J, res.Keys.J2O
	}
	return res.Keys.J2O, res.Keys.O2J
}

// negotiate picks the smaller of the two announced sizes, falling back to def if either side did
// not announce a positive value. Both peers compute the same result from the same caps.
func negotiate(local, remote, def int) int {
	m := local
	if remote < m {
		m = remote
	}
	if m <= 0 {
		return def
	}
	return m
}
