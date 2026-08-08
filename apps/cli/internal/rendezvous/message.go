// Package rendezvous drives one CLI peer through the SendArc M1 handshake over the blind
// signaling channel (plan.md §5.2): create/join → peer-joined → pake → confirm → an
// AEAD-sealed caps round-trip, ending with a shared master key and both directional
// transfer keys.
//
// It is the Go mirror of packages/protocol/src/rendezvous.ts and speaks the identical
// signaling envelope, so a CLI peer and a browser peer interoperate through the same
// server. The state machine is transport-agnostic: it writes outbound messages to an
// injected Sink and is fed inbound ones via [Session.Handle], which keeps it unit-testable
// (two sessions can be wired mouth-to-ear with no socket) and independent of the WebSocket
// client in internal/wsclient.
package rendezvous

import "encoding/json"

// Signaling message type tags (plan.md §6.1). These match the string tags in
// packages/protocol/src/signaling.ts exactly; the server forwards the peer→peer bodies
// verbatim, so a mismatch here would break interop with a browser peer.
const (
	typeCreate     = "create"
	typeCreated    = "created"
	typeJoin       = "join"
	typePeerJoined = "peer-joined"
	typePake       = "pake"
	typeConfirm    = "confirm"
	typeCaps       = "caps"
	typeBye        = "bye"
	typeError      = "error"
)

// Message is the SendArc signaling envelope. One flat struct covers every message type;
// the fields used depend on Type, and omitempty keeps each serialized frame minimal and
// byte-compatible with the TypeScript union in signaling.ts. The word code is never a
// field here — only the SPAKE2 share, the confirmation MAC, and the sealed caps travel.
type Message struct {
	Type string `json:"type"`
	// Room is set on join (client→server) and created (server→client).
	Room *int `json:"room,omitempty"`
	// Role is the peer's routing role, echoed by the server on peer-joined.
	Role string `json:"role,omitempty"`
	// Msg carries the base64url SPAKE2 share on pake, and the human text on error.
	Msg string `json:"msg,omitempty"`
	// Mac is the base64url RFC 9382 key-confirmation MAC on confirm.
	Mac string `json:"mac,omitempty"`
	// Frame is the base64url AEAD-sealed frame on caps.
	Frame string `json:"frame,omitempty"`
	// Reason is the optional detail on bye.
	Reason string `json:"reason,omitempty"`
	// Code is the machine-readable error code on error.
	Code string `json:"code,omitempty"`
}

// Sink is the outbound half of the signaling channel the session drives.
type Sink interface {
	Send(Message) error
}

// SinkFunc adapts a plain function to a Sink.
type SinkFunc func(Message) error

func (f SinkFunc) Send(m Message) error { return f(m) }

// MarshalMessage encodes a signaling message to its JSON wire form.
func MarshalMessage(m Message) ([]byte, error) { return json.Marshal(m) }

// UnmarshalMessage decodes a JSON signaling frame. A frame missing a type is rejected so
// the session can fail cleanly rather than act on an empty tag.
func UnmarshalMessage(data []byte) (Message, error) {
	var m Message
	if err := json.Unmarshal(data, &m); err != nil {
		return Message{}, err
	}
	return m, nil
}
