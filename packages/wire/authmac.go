package wire

import (
	"crypto/hmac"
	"encoding/binary"
)

// Signaling-message authentication (M2 design §4.2). Each sdp/ice signaling message is
// MAC'd so a malicious rendezvous server cannot substitute its own SDP to man-in-the-middle
// the DataChannel:
//
//	mac = HMAC-SHA256(k_auth, utf8(type) || ":" || u32be(room) || ":" || u32be(seq) || ":" || body)
//
// k_auth is the SPAKE2 key-confirmation material M1 retains: each peer signs with its own
// confirmation key and verifies with the peer's. This is defense-in-depth for the direct
// path — confidentiality still rests on the AES-GCM frame layer keyed by K. This is the Go
// twin of packages/protocol/src/authmac.ts and produces byte-identical MACs.

// SignalMacType is the kind of signaling message being authenticated.
type SignalMacType string

const (
	// SignalSDP authenticates an SDP offer/answer body.
	SignalSDP SignalMacType = "sdp"
	// SignalICE authenticates a trickled ICE-candidate body.
	SignalICE SignalMacType = "ice"
)

// U32BE encodes n as 4 big-endian bytes — the fixed-width room/seq encoding in the MAC input.
func U32BE(n uint32) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, n)
	return out
}

// SignalMacInput is the exact byte string the signaling MAC is computed over (design §4.2).
func SignalMacInput(typ SignalMacType, room, seq uint32, body string) []byte {
	const colon = ':'
	out := make([]byte, 0, len(typ)+1+4+1+4+1+len(body))
	out = append(out, string(typ)...)
	out = append(out, colon)
	out = append(out, U32BE(room)...)
	out = append(out, colon)
	out = append(out, U32BE(seq)...)
	out = append(out, colon)
	out = append(out, body...)
	return out
}

// SignSignal computes the authentication MAC for a signaling message.
func SignSignal(kAuth []byte, typ SignalMacType, room, seq uint32, body string) []byte {
	return hmacSHA256(kAuth, SignalMacInput(typ, room, seq, body))
}

// VerifySignal recomputes the MAC and compares it in constant time. A false result means the
// message is forged or corrupted and the session must abort.
func VerifySignal(kAuth []byte, typ SignalMacType, room, seq uint32, body string, mac []byte) bool {
	return hmac.Equal(SignSignal(kAuth, typ, room, seq, body), mac)
}

// SignalAuthKeys are one peer's signaling keys: it signs outgoing messages with Sign and
// verifies the peer's messages with Verify.
type SignalAuthKeys struct {
	Sign   []byte
	Verify []byte
}

// AuthKeys selects the signing/verifying confirmation keys for a role. The offerer (RFC party
// "A") signs with KcA and verifies with KcB; the joiner is the mirror, so each peer's Sign
// equals the other's Verify.
func AuthKeys(role Role, out *Spake2Output) SignalAuthKeys {
	if role == RoleOfferer {
		return SignalAuthKeys{Sign: out.KcA, Verify: out.KcB}
	}
	return SignalAuthKeys{Sign: out.KcB, Verify: out.KcA}
}
