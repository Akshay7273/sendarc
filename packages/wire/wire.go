// Package wire is the Go mirror of the @sendarc/protocol crypto core: the SPAKE2
// handshake, the key schedule, and the AES-256-GCM frame codec that secure a SendArc
// transfer. The web client runs the TypeScript implementation; the server and CLI run
// this one. The two are kept byte-identical — only the elliptic-curve point arithmetic
// uses a third-party library (filippo.io/nistec here, @noble/curves in TS); the hash,
// HKDF, and MAC use each language's standard library. Both are verified against the
// RFC 9382 Appendix B vectors and a shared set of deterministic SendArc vectors under
// test-vectors/.
package wire

// Role identifies the two ends of a transfer. The offerer sends the invite and plays
// RFC 9382 party "A"; the joiner accepts it and plays party "B".
type Role string

// The two roles, as they appear on the wire.
const (
	RoleOfferer Role = "offerer"
	RoleJoiner  Role = "joiner"
)

// ProtocolVersion is embedded in the handshake transcript and the caps message. It must
// match PROTOCOL_VERSION in packages/protocol/src/constants.ts.
const ProtocolVersion = "sendarc/1"

// The RFC transcript identity strings SendArc binds into every handshake.
const (
	IdentityOfferer = ProtocolVersion + " offerer"
	IdentityJoiner  = ProtocolVersion + " joiner"
)

// AES-256-GCM parameters for the frame AEAD (see aead.go).
const (
	aeadKeyBytes      = 32
	aeadNonceBytes    = 12
	aeadTagBytes      = 16
	aeadSaltBytes     = 4
	frameCounterBytes = 8
)

// HKDF info strings. confirmationKeys is fixed by RFC 9382 §4 and must not change; the
// rest are SendArc's own key schedule layered on the RFC output.
const (
	infoSpake2W          = ProtocolVersion + " spake2 w"
	infoConfirmationKeys = "ConfirmationKeys"
	infoMaster           = ProtocolVersion + " master"
	infoDirOffererJoiner = ProtocolVersion + " o2j"
	infoDirJoinerOfferer = ProtocolVersion + " j2o"
)

// spake2WHKDFBytes is the HKDF output length reduced mod n to form the scalar w. 48 bytes
// (384 bits) reduced into the 256-bit scalar field leaves negligible modular bias.
const spake2WHKDFBytes = 48
