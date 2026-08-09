// Package rtc drives the CLI peer's WebRTC leg of a direct transfer (design §4): it
// authenticates the SDP/ICE signaling with the SPAKE2-derived confirmation keys, negotiates a
// pion PeerConnection, and exposes the ordered, reliable "sendarc" DataChannel the transfer
// engine rides on.
//
// This file is the signaling authenticator — the Go twin of
// apps/web/src/lib/transfer/authed-signaling.ts. A blind rendezvous server relays sdp/ice
// bodies verbatim, so a malicious server could otherwise substitute its own SDP and
// man-in-the-middle the DataChannel. Every sdp/ice message therefore carries an authmac tag
// keyed by k_auth: a peer signs with its own confirmation key and verifies with the peer's, so
// a substituted body is rejected before it reaches pion. seq is monotonic per sender across
// both message kinds, and the verifier rejects any non-increasing seq, defeating replay and
// reorder. Confidentiality still rests on the AES-GCM frame layer; this is defense-in-depth for
// the negotiation itself.
package rtc

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	"github.com/sendarc/cli/internal/rendezvous"
	"github.com/sendarc/wire"
)

// SignalAuthenticator signs one peer's outbound sdp/ice messages and verifies the peer's
// inbound ones. It is safe for concurrent use: pion delivers local ICE candidates on its own
// goroutine while an answer is being signed, and inbound messages arrive on the signaling read
// loop, so the per-sender counters are mutex-guarded (the TypeScript original relies on the
// single-threaded event loop instead).
type SignalAuthenticator struct {
	room uint32
	keys wire.SignalAuthKeys

	mu     sync.Mutex
	outSeq int // next sequence number to sign
	inSeq  int // highest sequence number accepted; -1 before the first message
}

// NewSignalAuthenticator builds an authenticator for a room from an already-selected signing
// and verifying key pair.
func NewSignalAuthenticator(room int, keys wire.SignalAuthKeys) *SignalAuthenticator {
	return &SignalAuthenticator{room: uint32(room), keys: keys, inSeq: -1}
}

// FromSession derives the authenticator from a completed handshake, selecting the peer's
// confirmation keys by role (the offerer signs with KcA and verifies with KcB; the joiner is
// the mirror). It is the twin of SignalAuthenticator.fromSession.
func FromSession(role wire.Role, room int, spake2 *wire.Spake2Output) *SignalAuthenticator {
	return NewSignalAuthenticator(room, wire.AuthKeys(role, spake2))
}

// SignSDP returns a signed sdp message carrying the offer/answer, consuming the next sequence
// number.
func (a *SignalAuthenticator) SignSDP(sdp string) rendezvous.Message {
	seq, mac := a.sign(wire.SignalSDP, sdp)
	return rendezvous.NewSDP(seq, sdp, mac)
}

// SignICE returns a signed ice message carrying one trickled candidate, consuming the next
// sequence number.
func (a *SignalAuthenticator) SignICE(cand string) rendezvous.Message {
	seq, mac := a.sign(wire.SignalICE, cand)
	return rendezvous.NewICE(seq, cand, mac)
}

// sign computes the tag over body under the next outbound sequence number and returns both.
func (a *SignalAuthenticator) sign(typ wire.SignalMacType, body string) (int, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	seq := a.outSeq
	a.outSeq++
	mac := wire.SignSignal(a.keys.Sign, typ, a.room, uint32(seq), body)
	return seq, base64.RawURLEncoding.EncodeToString(mac)
}

// Verify authenticates an inbound sdp/ice message and enforces strictly increasing seq. It
// returns nil when the message is genuine and in order; otherwise a descriptive error and no
// state change, so a forged message at seq N never blocks the genuine one. On success the
// sender's window advances past seq, so a replay or an out-of-order delivery is rejected.
func (a *SignalAuthenticator) Verify(msg rendezvous.Message) error {
	typ, body, err := signalBody(msg)
	if err != nil {
		return err
	}
	if msg.Seq == nil {
		return errors.New("missing seq")
	}
	seq := *msg.Seq

	a.mu.Lock()
	defer a.mu.Unlock()
	if seq <= a.inSeq {
		return fmt.Errorf("non-increasing seq %d", seq)
	}
	mac, err := base64.RawURLEncoding.DecodeString(msg.Mac)
	if err != nil {
		return errors.New("malformed mac")
	}
	if !wire.VerifySignal(a.keys.Verify, typ, a.room, uint32(seq), body, mac) {
		return errors.New("bad mac")
	}
	a.inSeq = seq
	return nil
}

// signalBody maps a message to its authmac type and the body the tag covers, rejecting
// anything that is not an sdp/ice signaling message.
func signalBody(msg rendezvous.Message) (wire.SignalMacType, string, error) {
	switch msg.Type {
	case string(wire.SignalSDP):
		return wire.SignalSDP, msg.Sdp, nil
	case string(wire.SignalICE):
		return wire.SignalICE, msg.Cand, nil
	default:
		return "", "", fmt.Errorf("not a signaling message: %q", msg.Type)
	}
}
