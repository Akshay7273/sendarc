package rtc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/pion/webrtc/v4"
	"github.com/sendarc/cli/internal/rendezvous"
	"github.com/sendarc/wire"
)

// This file brings up the WebRTC DataChannel between two paired CLI peers over the
// already-authenticated signaling channel. It is the Go twin of
// apps/web/src/lib/transfer/peer.ts: the offerer creates the "sendarc" channel and the offer,
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

	mu          sync.Mutex
	settled     bool
	remoteReady bool
	pendingICE  []webrtc.ICECandidateInit
}

// NewPeer creates the PeerConnection and starts negotiation. For an offerer it immediately
// creates the "sendarc" channel and sends a signed offer; a joiner waits for the offer via
// Accept. The call returns as soon as negotiation is under way — await the result with Channel.
func NewPeer(opts PeerOptions) (*Peer, error) {
	iceServers := opts.ICEServers
	if iceServers == nil {
		iceServers = DefaultICEServers
	}
	newPC := webrtc.NewPeerConnection
	if opts.API != nil {
		newPC = opts.API.NewPeerConnection
	}
	pc, err := newPC(webrtc.Configuration{ICEServers: iceServers})
	if err != nil {
		return nil, fmt.Errorf("rtc: new peer connection: %w", err)
	}

	p := &Peer{
		pc:     pc,
		role:   opts.Role,
		auth:   opts.Auth,
		send:   opts.Send,
		connCh: make(chan *DataConn, 1),
		errCh:  make(chan error, 1),
	}

	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return // end-of-candidates
		}
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

	if opts.Role == wire.RoleOfferer {
		ch, err := pc.CreateDataChannel("sendarc", &webrtc.DataChannelInit{Ordered: boolPtr(true)})
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
		p.settled = true
		p.mu.Unlock()
		p.connCh <- conn
	})
	dc.OnError(func(error) {
		conn.shutdown()
		_ = p.pc.Close()
	})
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
