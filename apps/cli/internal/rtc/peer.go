package rtc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/sendbeam/cli/internal/rendezvous"
	"github.com/sendbeam/wire"
)

// This file brings up the WebRTC DataChannel between two paired CLI peers over the
// already-authenticated signaling channel. It is the Go twin of
// apps/web/src/lib/transfer/peer.ts: the offerer creates the "sendbeam" channel and the offer,
// the joiner answers, and both trickle ICE. Every SDP/ICE frame is signed and verified with the
// SPAKE2 key (see [SignalAuthenticator]); an unverifiable frame is dropped, so a malicious
// signaling server can pair sockets but can neither inject a peer nor tamper with the
// negotiation. Confidentiality still rests on the AES-GCM frame layer that rides the channel.

// DefaultICEServers covers the common NAT case. It matches DEFAULT_ICE_SERVERS in the browser
// peer so both ends gather comparably.
var DefaultICEServers = []webrtc.ICEServer{{URLs: []string{"stun:stun.l.google.com:19302"}}}

// PeerOptions configures a Peer.
type PeerOptions struct {
	Role wire.Role
	Auth *SignalAuthenticator
	// Send forwards a signed sdp/ice message over the adopted signaling socket.
	Send func(rendezvous.Message) error
	// ICEServers overrides DefaultICEServers; pass an explicit (possibly empty) slice to use
	// host candidates only, e.g. for an in-process loopback test.
	ICEServers []webrtc.ICEServer
	// API optionally supplies a pre-built webrtc.API (e.g. with a SettingEngine); nil uses the
	// package default.
	API *webrtc.API
	// OnICEState, if set, is invoked as ICE gathering/connection state transitions occur.
	// Useful for diagnostics and adaptive selection; see Peer.Diagnostics.
	OnICEState func(ICEState)
	// OnRecovering, if set, is invoked with true when an established direct path enters the
	// transient-disconnected recovery window (an ICE restart is under way) and false when it
	// recovers back to connected. Used to expose a distinct "recovering connection" state.
	OnRecovering func(recovering bool)
	// OnRecoverFailed, if set, is invoked when the recovery window elapses (or the ICE restart
	// fails) without returning to connected, meaning the direct path is gone and the caller
	// should fall back to the relay without resetting transfer progress.
	OnRecoverFailed func()
	// RecoverWindow bounds how long the peer observes a transient disconnect before giving up
	// and failing recovery. Zero uses the production default.
	RecoverWindow time.Duration
}

// DefaultRecoverWindow is the default bound for observing a transient ICE disconnect before the
// direct path is declared unrecoverable and the caller falls back to the relay.
const DefaultRecoverWindow = 6 * time.Second

// ICEState is a snapshot of ICE gathering/connection telemetry for one peer.
type ICEState struct {
	Gathering  webrtc.ICEGatheringState
	Connection webrtc.ICEConnectionState
	// HasServerReflexive reports whether any candidate gathered so far is a server-reflexive,
	// peer-reflexive, or relayed candidate — i.e. the NAT is not fully blocking a direct path.
	// It is the strongest available hint that a direct connection is viable and drives the
	// adaptive direct/relay racing policy.
	HasServerReflexive bool
	// HasAnyCandidate reports whether any candidate at all (including host) has been gathered.
	// Zero candidates means there is no direct path to attempt.
	HasAnyCandidate bool
}

// Peer owns one PeerConnection and drives it to an open DataChannel. Construct it with NewPeer;
// feed inbound signaling with Accept; await the channel with Channel; release with Close.
type Peer struct {
	pc   *webrtc.PeerConnection
	role wire.Role
	auth *SignalAuthenticator
	send func(rendezvous.Message) error

	connCh chan *DataConn // buffered(1): the channel once open
	errCh  chan error     // buffered(1): first fatal negotiation error

	onICEState      func(ICEState)
	onRecovering    func(recovering bool)
	onRecoverFailed func()
	recoverWindow   time.Duration

	// telemetry holds ICE setup instrumentation. It is guarded by mu and is safe to read once
	// the peer settles.
	telemetry telemetry

	mu          sync.Mutex
	settled     bool
	closed      bool
	remoteReady bool
	pendingICE  []webrtc.ICECandidateInit

	// recovering is true while an established direct path is in the transient-disconnect
	// recovery window. recoverTimer bounds that window. Both are guarded by mu.
	recovering   bool
	recoverTimer *time.Timer
}

// telemetry records ICE gathering/connection history and setup timing for Diagnostics.
type telemetry struct {
	StartAt     time.Time
	ConnectedAt time.Time // zero until the DataChannel opens
	Gathering   []webrtc.ICEGatheringState
	Connection  []webrtc.ICEConnectionState
	// anyCandidate is set once any candidate (including host) has been gathered.
	anyCandidate bool
	// anyViableCandidate is set once a srflx/prflx/relay candidate has been gathered.
	anyViableCandidate bool
}

// Diagnostic is a sanitized snapshot of a peer's ICE setup for diagnostics/telemetry output.
type Diagnostic struct {
	// SetupDuration is the time from NewPeer to the DataChannel opening (0 if not yet open).
	SetupDuration time.Duration
	// GatheringStates is the ordered gathering-state history.
	GatheringStates []webrtc.ICEGatheringState
	// ConnectionStates is the ordered ICE-connection-state history.
	ConnectionStates []webrtc.ICEConnectionState
	// SelectedCandidatePairType is the type of the currently selected candidate pair, or ""
	// if none is selected yet (e.g. "host", "srflx", "prflx", "relay").
	SelectedCandidatePairType string
}

// NewPeer creates the PeerConnection and starts negotiation. For an offerer it immediately
// creates the "sendbeam" channel and sends a signed offer; a joiner waits for the offer via
// Accept. The call returns as soon as negotiation is under way — await the result with Channel.
func NewPeer(opts PeerOptions) (*Peer, error) {
	iceServers := opts.ICEServers
	if iceServers == nil {
		iceServers = DefaultICEServers
	}
	recoverWindow := opts.RecoverWindow
	if recoverWindow <= 0 {
		recoverWindow = DefaultRecoverWindow
	}
	var newPC func(webrtc.Configuration) (*webrtc.PeerConnection, error)
	if opts.API != nil {
		newPC = opts.API.NewPeerConnection
	} else {
		// Observe a transient disconnect promptly and bound the failed state so recovery (or
		// fallback) is decided within a controlled window rather than Pion's long defaults.
		s := webrtc.SettingEngine{}
		s.SetICETimeouts(3*time.Second, 8*time.Second, 2*time.Second)
		api := webrtc.NewAPI(webrtc.WithSettingEngine(s))
		newPC = api.NewPeerConnection
	}
	pc, err := newPC(webrtc.Configuration{ICEServers: iceServers})
	if err != nil {
		return nil, fmt.Errorf("rtc: new peer connection: %w", err)
	}

	p := &Peer{
		pc:              pc,
		role:            opts.Role,
		auth:            opts.Auth,
		send:            opts.Send,
		connCh:          make(chan *DataConn, 1),
		errCh:           make(chan error, 1),
		onICEState:      opts.OnICEState,
		onRecovering:    opts.OnRecovering,
		onRecoverFailed: opts.OnRecoverFailed,
		recoverWindow:   recoverWindow,
		telemetry: telemetry{
			StartAt:    time.Now(),
			Gathering:  []webrtc.ICEGatheringState{pc.ICEGatheringState()},
			Connection: []webrtc.ICEConnectionState{pc.ICEConnectionState()},
		},
	}

	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return // end-of-candidates
		}
		p.mu.Lock()
		p.telemetry.anyCandidate = true
		// A server-reflexive (or peer-reflexive/relayed) candidate is the signal that a direct
		// path through NAT is plausible; record it for the adaptive racing policy.
		if c.Typ == webrtc.ICECandidateTypeSrflx ||
			c.Typ == webrtc.ICECandidateTypePrflx || c.Typ == webrtc.ICECandidateTypeRelay {
			p.telemetry.anyViableCandidate = true
		}
		p.mu.Unlock()
		body, err := json.Marshal(c.ToJSON())
		if err != nil {
			p.fail(fmt.Errorf("rtc: marshal ice candidate: %w", err))
			return
		}
		if err := p.send(p.auth.SignICE(string(body))); err != nil {
			p.fail(fmt.Errorf("rtc: send ice candidate: %w", err))
		}
	})
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		if s == webrtc.PeerConnectionStateFailed {
			p.mu.Lock()
			established := p.settled
			p.mu.Unlock()
			if established {
				_ = p.pc.Close() // DataConn.OnClose publishes the active-path failure.
			} else {
				p.fail(errors.New("rtc: peer connection failed"))
			}
		}
	})
	pc.OnICEGatheringStateChange(func(s webrtc.ICEGatheringState) {
		p.mu.Lock()
		p.telemetry.Gathering = append(p.telemetry.Gathering, s)
		now := p.snapshotLocked()
		cb := p.onICEState
		p.mu.Unlock()
		if cb != nil {
			cb(now)
		}
	})
	pc.OnICEConnectionStateChange(func(s webrtc.ICEConnectionState) {
		p.mu.Lock()
		p.telemetry.Connection = append(p.telemetry.Connection, s)
		now := p.snapshotLocked()
		settled := p.settled
		p.mu.Unlock()
		if p.onICEState != nil {
			p.onICEState(now)
		}
		// Recovery applies only to an established direct path (the channel already opened).
		// Before settlement, disconnected/failed continue to fail the peer outright.
		if !settled {
			return
		}
		switch s {
		case webrtc.ICEConnectionStateDisconnected:
			p.enterRecover()
		case webrtc.ICEConnectionStateConnected, webrtc.ICEConnectionStateCompleted:
			p.exitRecover()
		case webrtc.ICEConnectionStateFailed:
			p.failRecover()
		}
	})

	if opts.Role == wire.RoleOfferer {
		ch, err := pc.CreateDataChannel("sendbeam", &webrtc.DataChannelInit{Ordered: boolPtr(true)})
		if err != nil {
			_ = pc.Close()
			return nil, fmt.Errorf("rtc: create data channel: %w", err)
		}
		p.wireChannel(ch)
		go p.sendOffer()
	} else {
		pc.OnDataChannel(p.wireChannel)
	}
	return p, nil
}

// Channel blocks until the DataChannel is open, negotiation fails, or ctx is done.
func (p *Peer) Channel(ctx context.Context) (*DataConn, error) {
	select {
	case conn := <-p.connCh:
		return conn, nil
	case err := <-p.errCh:
		return nil, err
	case <-ctx.Done():
		p.fail(ctx.Err())
		return nil, ctx.Err()
	}
}

// Accept feeds one inbound signaling message. Unverifiable messages are dropped silently, so a
// tampering server cannot steer the negotiation; a genuine message that then fails to apply
// (malformed SDP, bad candidate) fails the peer.
func (p *Peer) Accept(msg rendezvous.Message) {
	if err := p.auth.Verify(msg); err != nil {
		return // drop: forged, replayed, or reordered
	}
	if err := p.handle(msg); err != nil {
		p.fail(err)
	}
}

// Close tears down the PeerConnection. It is idempotent and safe to call after a failure.
func (p *Peer) Close() error {
	p.mu.Lock()
	p.settled = true
	p.closed = true
	if p.recoverTimer != nil {
		p.recoverTimer.Stop()
		p.recoverTimer = nil
	}
	p.mu.Unlock()
	return p.pc.Close()
}

// --- internal ---------------------------------------------------------------

func (p *Peer) sendOffer() {
	offer, err := p.pc.CreateOffer(nil)
	if err != nil {
		p.fail(fmt.Errorf("rtc: create offer: %w", err))
		return
	}
	if err := p.pc.SetLocalDescription(offer); err != nil {
		p.fail(fmt.Errorf("rtc: set local offer: %w", err))
		return
	}
	if err := p.send(p.auth.SignSDP(offer.SDP)); err != nil {
		p.fail(fmt.Errorf("rtc: send offer: %w", err))
	}
}

// handle applies a verified sdp/ice message: SDP drives the offer/answer exchange (the remote
// type is implied by our role, exactly as the browser does), ICE is added once the remote
// description is set and buffered until then.
func (p *Peer) handle(msg rendezvous.Message) error {
	switch msg.Type {
	case string(wire.SignalSDP):
		if p.role == wire.RoleOfferer {
			return p.applyRemoteDescription(webrtc.SDPTypeAnswer, msg.Sdp)
		}
		if err := p.applyRemoteDescription(webrtc.SDPTypeOffer, msg.Sdp); err != nil {
			return err
		}
		answer, err := p.pc.CreateAnswer(nil)
		if err != nil {
			return fmt.Errorf("rtc: create answer: %w", err)
		}
		if err := p.pc.SetLocalDescription(answer); err != nil {
			return fmt.Errorf("rtc: set local answer: %w", err)
		}
		return p.send(p.auth.SignSDP(answer.SDP))
	case string(wire.SignalICE):
		var cand webrtc.ICECandidateInit
		if err := json.Unmarshal([]byte(msg.Cand), &cand); err != nil {
			return fmt.Errorf("rtc: parse ice candidate: %w", err)
		}
		return p.addICE(cand)
	default:
		return fmt.Errorf("rtc: unexpected signaling type %q", msg.Type)
	}
}

func (p *Peer) applyRemoteDescription(typ webrtc.SDPType, sdp string) error {
	if err := p.pc.SetRemoteDescription(webrtc.SessionDescription{Type: typ, SDP: sdp}); err != nil {
		return fmt.Errorf("rtc: set remote description: %w", err)
	}
	p.mu.Lock()
	p.remoteReady = true
	pending := p.pendingICE
	p.pendingICE = nil
	p.mu.Unlock()
	for _, c := range pending {
		if err := p.pc.AddICECandidate(c); err != nil {
			return fmt.Errorf("rtc: add buffered ice candidate: %w", err)
		}
	}
	return nil
}

// addICE adds a candidate now if the remote description is set, else buffers it. Remote ICE can
// arrive before the description (network reorder, or a peer trickling early).
func (p *Peer) addICE(cand webrtc.ICECandidateInit) error {
	p.mu.Lock()
	if !p.remoteReady {
		p.pendingICE = append(p.pendingICE, cand)
		p.mu.Unlock()
		return nil
	}
	p.mu.Unlock()
	if err := p.pc.AddICECandidate(cand); err != nil {
		return fmt.Errorf("rtc: add ice candidate: %w", err)
	}
	return nil
}

// wireChannel binds the DataChannel's lifecycle: it resolves Channel on open and fails the peer
// on a channel error.
func (p *Peer) wireChannel(dc *webrtc.DataChannel) {
	conn := newDataConn(dc)
	dc.OnOpen(func() {
		p.mu.Lock()
		if p.settled {
			p.mu.Unlock()
			return
		}
		if p.telemetry.ConnectedAt.IsZero() {
			p.telemetry.ConnectedAt = time.Now()
		}
		p.settled = true
		p.mu.Unlock()
		p.connCh <- conn
	})
	dc.OnError(func(error) {
		conn.shutdown()
		_ = p.pc.Close()
	})
}

// snapshotLocked builds the current ICEState from telemetry. Caller must hold p.mu.
func (p *Peer) snapshotLocked() ICEState {
	g := webrtc.ICEGatheringStateNew
	if len(p.telemetry.Gathering) > 0 {
		g = p.telemetry.Gathering[len(p.telemetry.Gathering)-1]
	}
	c := webrtc.ICEConnectionStateNew
	if len(p.telemetry.Connection) > 0 {
		c = p.telemetry.Connection[len(p.telemetry.Connection)-1]
	}
	return ICEState{Gathering: g, Connection: c, HasServerReflexive: p.telemetry.anyViableCandidate, HasAnyCandidate: p.telemetry.anyCandidate}
}

// Recovering reports whether the established direct path is currently in the
// transient-disconnect recovery window.
func (p *Peer) Recovering() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.recovering
}

// enterRecover starts recovery for an established direct path that has gone transiently
// disconnected: it reports the recovering state, has the offerer issue an ICE restart over
// signaling, and bounds the observation window so a path that cannot return to connected fails
// over to the relay rather than stalling forever.
func (p *Peer) enterRecover() {
	p.mu.Lock()
	if p.closed || p.recovering {
		p.mu.Unlock()
		return
	}
	p.recovering = true
	restart := p.role == wire.RoleOfferer
	onRecovering := p.onRecovering
	p.mu.Unlock()

	if onRecovering != nil {
		onRecovering(true)
	}
	if restart {
		if err := p.restartOffer(); err != nil {
			p.failRecover()
			return
		}
	}
	p.mu.Lock()
	if p.closed || p.recoverTimer != nil {
		p.mu.Unlock()
		return
	}
	p.recoverTimer = time.AfterFunc(p.recoverWindow, func() { p.failRecover() })
	p.mu.Unlock()
}

// restartOffer performs an ICE restart as the offerer: a new offer with ICERestart set, sent
// over signaling so the partner answers and both sides re-establish the ICE transport while the
// existing data channel (and therefore the transfer progress) stays alive.
func (p *Peer) restartOffer() error {
	offer, err := p.pc.CreateOffer(&webrtc.OfferOptions{ICERestart: true})
	if err != nil {
		return fmt.Errorf("rtc: create restart offer: %w", err)
	}
	if err := p.pc.SetLocalDescription(offer); err != nil {
		return fmt.Errorf("rtc: set restart offer: %w", err)
	}
	return p.send(p.auth.SignSDP(offer.SDP))
}

// exitRecover clears the recovery state once the path returns to connected. Idempotent.
func (p *Peer) exitRecover() {
	p.mu.Lock()
	if !p.recovering {
		p.mu.Unlock()
		return
	}
	p.recovering = false
	if p.recoverTimer != nil {
		p.recoverTimer.Stop()
		p.recoverTimer = nil
	}
	onRecovering := p.onRecovering
	p.mu.Unlock()
	if onRecovering != nil {
		onRecovering(false)
	}
}

// failRecover gives up on the direct path after the observation window elapsed (or the ICE
// restart failed) without returning to connected: it reports recovery failure and closes the
// PeerConnection so the DataConn teardown notifies the active-path failure and the caller falls
// back to the relay. Idempotent and safe to call from the timer and ICE callbacks.
func (p *Peer) failRecover() {
	p.mu.Lock()
	if p.closed || !p.recovering {
		p.mu.Unlock()
		return
	}
	p.recovering = false
	if p.recoverTimer != nil {
		p.recoverTimer.Stop()
		p.recoverTimer = nil
	}
	onRecoverFailed := p.onRecoverFailed
	p.mu.Unlock()
	if onRecoverFailed != nil {
		onRecoverFailed()
	}
	_ = p.pc.Close()
}

// Diagnostics returns a sanitized snapshot of the peer's ICE setup for telemetry. It never
// exposes invite codes, IPs, SDP, or credentials. It is safe to call before settlement (the
// SelectedCandidatePairType may be ""), and after teardown.
func (p *Peer) Diagnostics() Diagnostic {
	p.mu.Lock()
	d := Diagnostic{
		GatheringStates:           append([]webrtc.ICEGatheringState(nil), p.telemetry.Gathering...),
		ConnectionStates:          append([]webrtc.ICEConnectionState(nil), p.telemetry.Connection...),
		SelectedCandidatePairType: "",
	}
	if !p.telemetry.ConnectedAt.IsZero() {
		d.SetupDuration = p.telemetry.ConnectedAt.Sub(p.telemetry.StartAt)
	}
	p.mu.Unlock()

	// Query pion's selected pair without holding p.mu so we never risk a lock inversion
	// between our mutex and pion's internal transport locks.
	if pair, err := p.selectedCandidatePair(); err == nil && pair != nil {
		if c := pair.Local; c != nil {
			d.SelectedCandidatePairType = c.Typ.String()
		}
	}
	return d
}

// selectedCandidatePair reaches pion's selected ICE candidate pair through the transport
// chain (SCTP -> DTLS -> ICE). Returns nil when no pair is selected yet.
func (p *Peer) selectedCandidatePair() (*webrtc.ICECandidatePair, error) {
	sctp := p.pc.SCTP()
	if sctp == nil {
		return nil, nil
	}
	dtls := sctp.Transport()
	if dtls == nil {
		return nil, nil
	}
	ice := dtls.ICETransport()
	if ice == nil {
		return nil, nil
	}
	return ice.GetSelectedCandidatePair()
}

// fail records the first fatal error and closes the PeerConnection; later calls are no-ops.
func (p *Peer) fail(err error) {
	p.mu.Lock()
	if p.settled {
		p.mu.Unlock()
		return
	}
	p.settled = true
	p.mu.Unlock()
	select {
	case p.errCh <- err:
	default:
	}
	_ = p.pc.Close()
}

func boolPtr(b bool) *bool { return &b }
