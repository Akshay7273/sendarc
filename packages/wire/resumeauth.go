package wire

// Cross-session authenticated resume protocol (V13-PR07). Design: docs/adr/0005.
//
// This module derives the transfer-scoped resume credential from the ORIGINAL authenticated
// session master, persists it as an opaque 256-bit envelope, and runs the transport-agnostic
// mutual-authentication handshake that lets the same original sender and receiver resume a
// transfer after the original process/session is gone — without persisting the master, the
// directional keys, the AEAD salts/counters, or the invite code.
//
// The engine is deliberately independent of the transport that carries its messages (PR08
// owns discovery/reconnection): both sides already know the transferId, the canonical
// manifest fingerprint, their stable role, and the resumeSecret; the transferId and
// fingerprint are NEVER transmitted — they enter only through the canonical transcript.
// The server/network cannot forge a resume authentication: proofs are HMAC-SHA256 under
// role-separated subkeys over a transcript bound to fresh per-attempt nonces, the
// transferId, the manifest fingerprint, and the resume-auth version.
//
// Go and TypeScript (packages/protocol/src/resume-auth.ts) must produce byte-identical
// outputs; pinned by docs/test-vectors/resume-auth.json.

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sync"
)

// ResumeAuthVersion is the version of the cross-session resume-auth protocol. It is bound
// into the secret derivation and the transcript; a future incompatible protocol bumps it
// and defines its own messages. It is independent of JournalSchemaVersion and of the wire
// ProtocolVersion.
const ResumeAuthVersion = 1

// ResumeAuthCapability is the capability name announced in caps (a `features` entry) that
// gates the resume-auth protocol within sendbeam/1. It is defined, documented, and
// negotiation-tested here but deliberately NOT advertised in production defaults: automatic
// cross-session resume stays disabled until PR08 / lead approval.
const ResumeAuthCapability = "resume-auth-v1"

// Lengths of the resume-auth protocol fields.
const (
	// resumeNonceBytes is the fresh challenge nonce length, one per peer per attempt.
	resumeNonceBytes = 32
	// resumeProofBytes is the HMAC-SHA256 proof length.
	resumeProofBytes = 32
	// resumeSecretBytes is the derived transfer-scoped credential length (256 bits).
	resumeSecretBytes = 32
	// masterBytes is the authenticated session master length (the SendBeam handshake
	// always derives a 32-byte master; ResumeRoot refuses anything else).
	masterBytes = 32
	// MaxResumeAuthMessageBytes is the shared semantic ceiling for one resume-auth wire
	// message, mirrored in TypeScript. The largest legitimate message is resume_challenge:
	// ~two 43-char base64url fields plus JSON framing, well under 256 bytes. 1024 bounds
	// attacker-controlled payloads before any JSON/base64 allocation while leaving ample
	// headroom for future versioned fields.
	MaxResumeAuthMessageBytes = 1024
)

// b64urlLen is the canonical unpadded base64url length of n bytes: 4*ceil(n/3) minus the
// padding that unpadded encoding omits. For 32 bytes that is exactly 43 ASCII chars; a
// nonce/proof string of any other length is rejected before any base64 decoding.
func b64urlLen(n int) int {
	groups := (n + 2) / 3
	pad := (3 - n%3) % 3
	return 4*groups - pad
}

// Domain-separated HKDF info strings for the resume protocol (ADR 0005 §3/§6.4/§7).
const (
	infoResumeRoot         = ProtocolVersion + " resume root"
	infoResumeSecret       = ProtocolVersion + " resume secret"
	infoResumeProofOfferer = ProtocolVersion + " resume offerer proof"
	infoResumeProofJoiner  = ProtocolVersion + " resume joiner proof"
	infoResumeMaster       = ProtocolVersion + " resume master"
	resumeTranscriptDomain = ProtocolVersion + " resume-auth"
)

// Proof tags append a fixed byte to the canonical transcript so the three proofs of one
// attempt are mutually distinct and cannot be substituted for each other (ADR 0005 §6.4).
const (
	resumeProofTagJoiner  = 0x01 // resume_challenge
	resumeProofTagOfferer = 0x02 // resume_confirm
	resumeProofTagReady   = 0x03 // resume_ready
)

// ResumeRoot derives the transient, transfer-scoped resume root from the ORIGINAL
// authenticated session master: HKDF-SHA256(master, nil, "sendbeam/1 resume root", 32).
//
// The root is deliberately narrow: it exists only to derive transfer-specific resume
// secrets and must never be persisted, logged, or returned to the UI. The original master
// cannot be recovered from it (HKDF one-wayness), which is what lets a browser pass the
// root into the transfer worker without leaking the session master.
func ResumeRoot(master []byte) ([]byte, error) {
	// The SendBeam handshake master is exactly 32 bytes (DeriveMaster outLen). Anything
	// else is a miswired caller, not a valid master: reject it rather than derive a
	// low-entropy or wrong-length root from it.
	if len(master) != masterBytes {
		return nil, Errorf(CodeAuth, "resume: original session master must be %d bytes, got %d", masterBytes, len(master))
	}
	return hkdfSHA256(master, nil, []byte(infoResumeRoot), resumeSecretBytes)
}

// ResumeSecret derives the 256-bit transfer-scoped resume credential from the resume root:
//
//	HKDF-SHA256(resumeRoot, nil,
//	    "sendbeam/1 resume secret" || u32be(version) || transferId(16) || manifestFingerprint(32),
//	    32)
//
// transferId must be validated 32 lowercase hex chars and manifestFingerprint validated 64
// lowercase hex chars; anything else is rejected before any derivation. The version, the
// transfer id, and the manifest fingerprint are bound with explicit fixed-width binary
// fields (no ambiguous delimiters, no ad-hoc string concatenation).
func ResumeSecret(resumeRoot []byte, version int, transferID, manifestFingerprint string) ([]byte, error) {
	// The resume root is the 32-byte output of ResumeRoot; a different length means the
	// caller passed something else (a raw master, a string, an empty slice).
	if len(resumeRoot) != resumeSecretBytes {
		return nil, Errorf(CodeAuth, "resume: resume root must be %d bytes, got %d", resumeSecretBytes, len(resumeRoot))
	}
	if version != ResumeAuthVersion {
		return nil, Errorf(CodeCompat, "resume: unsupported resume-auth version %d", version)
	}
	if !isLowerHex(transferID, 32) {
		return nil, Errorf(CodeAuth, "resume: transferId must be 32 lowercase hex characters")
	}
	if !isLowerHex(manifestFingerprint, 64) {
		return nil, Errorf(CodeAuth, "resume: manifestFingerprint must be 64 lowercase hex characters")
	}
	tid, _ := hex.DecodeString(transferID)
	fp, _ := hex.DecodeString(manifestFingerprint)
	info := concat([]byte(infoResumeSecret), U32BE(uint32(version)), tid, fp)
	return hkdfSHA256(resumeRoot, nil, info, resumeSecretBytes)
}

// ResumeSecretEnvelope is the persisted shape of the transfer-scoped credential (ADR 0005
// §4): an opaque versioned envelope whose value is exactly 64 lowercase hex characters (32
// bytes). It mirrors the journal's JournalResumeSecret; the sender records use the same
// shape. Nothing but this envelope is ever persisted.
type ResumeSecretEnvelope struct {
	Version int    `json:"version"`
	Value   string `json:"value"`
}

// EncodeResumeSecretEnvelope wraps a derived 32-byte secret into its persisted envelope.
func EncodeResumeSecretEnvelope(secret []byte) (*ResumeSecretEnvelope, error) {
	if len(secret) != resumeSecretBytes {
		return nil, Errorf(CodeStorage, "resume: resume secret must be %d bytes", resumeSecretBytes)
	}
	return &ResumeSecretEnvelope{Version: ResumeAuthVersion, Value: hex.EncodeToString(secret)}, nil
}

// DecodeResumeSecretEnvelope strictly decodes a persisted envelope: version must be exactly
// ResumeAuthVersion and the value exactly 64 lowercase hex characters (32 bytes). An
// arbitrary old opaque value is never reinterpreted as a valid key.
func DecodeResumeSecretEnvelope(e *ResumeSecretEnvelope) ([]byte, error) {
	if e == nil {
		return nil, Errorf(CodeStorage, "resume: missing resume secret envelope")
	}
	if e.Version != ResumeAuthVersion {
		return nil, Errorf(CodeCompat, "resume: unsupported resume secret version %d", e.Version)
	}
	if !isLowerHex(e.Value, 64) {
		return nil, Errorf(CodeStorage, "resume: resume secret must be 64 lowercase hex characters")
	}
	out, err := hex.DecodeString(e.Value)
	if err != nil || len(out) != resumeSecretBytes {
		return nil, Errorf(CodeStorage, "resume: malformed resume secret value")
	}
	return out, nil
}

// ResumeTranscript builds the canonical binary transcript for one resume-auth attempt
// (ADR 0005 §6.3):
//
//	"sendbeam/1 resume-auth" || u32be(version) || transferId(16) || manifestFingerprint(32)
//	|| offererNonce(32) || joinerNonce(32)
//
// Both peers compute the same bytes; the nonce positions are role-fixed, which is part of
// the role binding. Lengths are validated before construction.
func ResumeTranscript(version int, transferID, manifestFingerprint string, offererNonce, joinerNonce []byte) ([]byte, error) {
	if version != ResumeAuthVersion {
		return nil, Errorf(CodeCompat, "resume: unsupported resume-auth version %d", version)
	}
	if !isLowerHex(transferID, 32) {
		return nil, Errorf(CodeAuth, "resume: transferId must be 32 lowercase hex characters")
	}
	if !isLowerHex(manifestFingerprint, 64) {
		return nil, Errorf(CodeAuth, "resume: manifestFingerprint must be 64 lowercase hex characters")
	}
	if len(offererNonce) != resumeNonceBytes {
		return nil, Errorf(CodeProtocol, "resume: offerer nonce must be %d bytes", resumeNonceBytes)
	}
	if len(joinerNonce) != resumeNonceBytes {
		return nil, Errorf(CodeProtocol, "resume: joiner nonce must be %d bytes", resumeNonceBytes)
	}
	tid, _ := hex.DecodeString(transferID)
	fp, _ := hex.DecodeString(manifestFingerprint)
	return concat(
		[]byte(resumeTranscriptDomain),
		U32BE(uint32(version)),
		tid, fp,
		offererNonce, joinerNonce,
	), nil
}

// resumeProofKey derives one role-separated HMAC subkey from the resume secret.
func resumeProofKey(secret []byte, info string) ([]byte, error) {
	if len(secret) != resumeSecretBytes {
		return nil, Errorf(CodeAuth, "resume: resume secret must be %d bytes", resumeSecretBytes)
	}
	return hkdfSHA256(secret, nil, []byte(info), resumeProofBytes)
}

// ResumeOffererProof computes the offerer's proof over the transcript:
// HMAC-SHA256(K_offerer, transcript || 0x02). See ADR 0005 §6.4.
func ResumeOffererProof(secret, transcript []byte) ([]byte, error) {
	key, err := resumeProofKey(secret, infoResumeProofOfferer)
	if err != nil {
		return nil, err
	}
	return hmacSHA256(key, append(append([]byte(nil), transcript...), resumeProofTagOfferer)), nil
}

// ResumeJoinerProof computes the joiner's proof over the transcript:
// HMAC-SHA256(K_joiner, transcript || 0x01). See ADR 0005 §6.4.
func ResumeJoinerProof(secret, transcript []byte) ([]byte, error) {
	key, err := resumeProofKey(secret, infoResumeProofJoiner)
	if err != nil {
		return nil, err
	}
	return hmacSHA256(key, append(append([]byte(nil), transcript...), resumeProofTagJoiner)), nil
}

// ResumeReadyProof computes the joiner's final key-confirmation over the transcript:
// HMAC-SHA256(K_joiner, transcript || 0x03). See ADR 0005 §6.4.
func ResumeReadyProof(secret, transcript []byte) ([]byte, error) {
	key, err := resumeProofKey(secret, infoResumeProofJoiner)
	if err != nil {
		return nil, err
	}
	return hmacSHA256(key, append(append([]byte(nil), transcript...), resumeProofTagReady)), nil
}

// ResumeSessionMaster derives the fresh resumed session master after MUTUAL authentication:
// HKDF-SHA256(resumeSecret, nil, "sendbeam/1 resume master" || transcript, 32). The caller
// feeds it into DeriveTransferKeys to obtain the fresh directional keys (ADR 0005 §7).
func ResumeSessionMaster(secret, transcript []byte) ([]byte, error) {
	if len(secret) != resumeSecretBytes {
		return nil, Errorf(CodeAuth, "resume: resume secret must be %d bytes", resumeSecretBytes)
	}
	info := append([]byte(infoResumeMaster), transcript...)
	return hkdfSHA256(secret, nil, info, resumeSecretBytes)
}

// ---------------------------------------------------------------------------
// Message codec (strict, bounded)
// ---------------------------------------------------------------------------

// ResumeMsgType is one resume-auth message tag.
type ResumeMsgType string

// The four resume-auth message tags (ADR 0005 §6.1).
const (
	ResumeMsgInit      ResumeMsgType = "resume_init"
	ResumeMsgChallenge ResumeMsgType = "resume_challenge"
	ResumeMsgConfirm   ResumeMsgType = "resume_confirm"
	ResumeMsgReady     ResumeMsgType = "resume_ready"
)

// ResumeMessage is one resume-auth message. Nonce and Proof are base64url (no padding);
// every field is validated strictly on decode (exact version, exact role per type, exact
// 32-byte nonce/proof lengths, no unknown fields, no trailing data).
type ResumeMessage struct {
	Type    ResumeMsgType `json:"type"`
	Version int           `json:"version"`
	Role    Role          `json:"role,omitempty"`
	Nonce   string        `json:"nonce,omitempty"`
	Proof   string        `json:"proof,omitempty"`
}

// resumeRawMessage mirrors ResumeMessage with pointer fields so a missing key is
// distinguishable from a legitimate value (matching the TS num()/str() presence checks).
type resumeRawMessage struct {
	Type    *string `json:"type"`
	Version *int    `json:"version"`
	Role    *string `json:"role"`
	Nonce   *string `json:"nonce"`
	Proof   *string `json:"proof"`
}

// EncodeResumeMessage serializes one resume-auth message to its canonical wire JSON
// (no HTML escaping, no trailing newline — byte-identical to JSON.stringify, like the
// control codec).
func EncodeResumeMessage(m *ResumeMessage) ([]byte, error) {
	if m == nil {
		return nil, Errorf(CodeProtocol, "resume: nil message")
	}
	if err := validateResumeMessage(m); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, Errorf(CodeProtocol, "resume: encode: %v", err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// validateResumeMessage enforces the exact field contract per message type before any
// serialization: version must be ResumeAuthVersion; the role must match the message type;
// nonce (init/challenge) must be present and exactly 32 bytes; proof (challenge/confirm/
// ready) must be present and exactly 32 bytes.
func validateResumeMessage(m *ResumeMessage) error {
	if m.Version != ResumeAuthVersion {
		return Errorf(CodeCompat, "resume: unsupported resume-auth version %d", m.Version)
	}
	switch m.Type {
	case ResumeMsgInit:
		if m.Role != RoleOfferer {
			return Errorf(CodeProtocol, "resume: resume_init must carry role %q", RoleOfferer)
		}
		if !validB64Len(m.Nonce, resumeNonceBytes) {
			return Errorf(CodeProtocol, "resume: resume_init nonce must be %d bytes", resumeNonceBytes)
		}
		if m.Proof != "" {
			return Errorf(CodeProtocol, "resume: resume_init must not carry a proof")
		}
	case ResumeMsgChallenge:
		if m.Role != RoleJoiner {
			return Errorf(CodeProtocol, "resume: resume_challenge must carry role %q", RoleJoiner)
		}
		if !validB64Len(m.Nonce, resumeNonceBytes) {
			return Errorf(CodeProtocol, "resume: resume_challenge nonce must be %d bytes", resumeNonceBytes)
		}
		if !validB64Len(m.Proof, resumeProofBytes) {
			return Errorf(CodeProtocol, "resume: resume_challenge proof must be %d bytes", resumeProofBytes)
		}
	case ResumeMsgConfirm:
		if m.Role != RoleOfferer {
			return Errorf(CodeProtocol, "resume: resume_confirm must carry role %q", RoleOfferer)
		}
		if m.Nonce != "" {
			return Errorf(CodeProtocol, "resume: resume_confirm must not carry a nonce")
		}
		if !validB64Len(m.Proof, resumeProofBytes) {
			return Errorf(CodeProtocol, "resume: resume_confirm proof must be %d bytes", resumeProofBytes)
		}
	case ResumeMsgReady:
		if m.Role != RoleJoiner {
			return Errorf(CodeProtocol, "resume: resume_ready must carry role %q", RoleJoiner)
		}
		if m.Nonce != "" {
			return Errorf(CodeProtocol, "resume: resume_ready must not carry a nonce")
		}
		if !validB64Len(m.Proof, resumeProofBytes) {
			return Errorf(CodeProtocol, "resume: resume_ready proof must be %d bytes", resumeProofBytes)
		}
	default:
		return Errorf(CodeProtocol, "resume: unknown message type %q", m.Type)
	}
	return nil
}

// DecodeResumeMessage strictly decodes one resume-auth message, rejecting unknown fields,
// missing fields, wrong types, invalid versions/roles, non-canonical or malformed encodings,
// wrong nonce/proof lengths, and trailing data. There are no attacker-controlled unbounded
// allocations: the payload ceiling is enforced BEFORE any JSON parsing, and every binary
// field's canonical base64url length is enforced before any base64 decoding.
func DecodeResumeMessage(payload []byte) (*ResumeMessage, error) {
	if len(payload) > MaxResumeAuthMessageBytes {
		return nil, Errorf(CodeProtocol, "resume: message exceeds %d bytes", MaxResumeAuthMessageBytes)
	}
	var raw resumeRawMessage
	if err := unmarshalStrict(payload, &raw); err != nil {
		return nil, Errorf(CodeProtocol, "resume: malformed message: %v", err)
	}
	if raw.Type == nil {
		return nil, Errorf(CodeProtocol, "resume: missing type")
	}
	if raw.Version == nil {
		return nil, Errorf(CodeProtocol, "resume: missing version")
	}
	m := &ResumeMessage{
		Type:    ResumeMsgType(*raw.Type),
		Version: *raw.Version,
	}
	if raw.Role != nil {
		m.Role = Role(*raw.Role)
	}
	if raw.Nonce != nil {
		m.Nonce = *raw.Nonce
	}
	if raw.Proof != nil {
		m.Proof = *raw.Proof
	}
	// validateResumeMessage already enforced the exact canonical base64url length (via
	// validB64Len) for every nonce/proof, so no further decoding happens here.
	if err := validateResumeMessage(m); err != nil {
		return nil, err
	}
	return m, nil
}

// validB64Len reports whether s is the canonical base64url (no padding) encoding of exactly
// n bytes. The expected string length is checked FIRST — before any base64 decoding — so a
// huge nonce/proof string is rejected without allocation; then the string is decoded,
// length-checked, and re-encoded to reject padded or otherwise non-canonical spellings.
func validB64Len(s string, n int) bool {
	if len(s) != b64urlLen(n) {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(decoded) != n {
		return false
	}
	return base64.RawURLEncoding.EncodeToString(decoded) == s
}

func b64enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

// ResumeAuthContext is the local resume context one peer supplies. Both sides already know
// the transfer they intend to resume; transferId and manifestFingerprint are never sent.
type ResumeAuthContext struct {
	// Version is the resume-auth protocol version (ResumeAuthVersion).
	Version int
	// TransferID is the stable 128-bit hex id of the transfer being resumed.
	TransferID string
	// ManifestFingerprint is the canonical manifest fingerprint of the transfer.
	ManifestFingerprint string
	// Role is this peer's stable role: offerer (sender) or joiner (receiver).
	Role Role
	// ResumeSecret is the 32-byte transfer-scoped credential derived from the ORIGINAL
	// authenticated session. It is held only in memory for the handshake.
	ResumeSecret []byte
	// NonceSource generates cryptographically strong random bytes (32) for fresh
	// challenges. Nil uses crypto/rand; tests inject a deterministic source. It must
	// never be a PRNG, timestamp, or old counter.
	NonceSource func(n int) ([]byte, error)
}

// ResumeAuthResult is the all-or-nothing outcome of a successful mutual authentication: the
// fresh resumed traffic keys (already fed through the standard directional derivation) and
// the fresh-session counter start. It is exposed only after mutual authentication completes.
type ResumeAuthResult struct {
	Role        Role
	TransferID  string
	Keys        TransferKeys
	SendCounter uint64
	RecvCounter uint64
}

// resumeAuthState is the engine's current state (ADR 0005 §6.5).
type resumeAuthState int

const (
	resumeStateIdle resumeAuthState = iota
	// offerer: init sent, awaiting the joiner's challenge.
	resumeStateAwaitChallenge
	// offerer: challenge accepted, awaiting the joiner's ready.
	resumeStateAwaitReady
	// joiner: challenge sent, awaiting the offerer's confirm.
	resumeStateAwaitConfirm
	// mutual authentication complete.
	resumeStateDone
	resumeStateFailed
)

// ResumeAuthSession is one transport-agnostic mutual-authentication attempt. Start it (the
// offerer emits resume_init; the joiner waits), feed inbound messages with Handle, and
// read the result from Handle's return. The same engine drives both roles.
type ResumeAuthSession struct {
	ctx ResumeAuthContext

	mu    sync.Mutex
	state resumeAuthState

	// offererNonce/joinerNonce are the fresh challenge nonces of this attempt.
	offererNonce []byte
	joinerNonce  []byte
	// transcript is the canonical transcript once both nonces are known.
	transcript []byte
	// result is the fresh keys once mutual authentication completes.
	result *ResumeAuthResult
	// steps is a small fixed snapshot per handshake step: the canonical encoding of each
	// accepted inbound message plus the exact outbound snapshot generated for it (nil when
	// the accepted message had no response). An exact duplicate of any accepted message is
	// idempotently re-answered with the SAME snapshot for the rest of the session (including
	// after done) — never a fresh nonce/proof for a retry; any other message of a type that
	// was already accepted is a conflicting duplicate and fails closed.
	steps []acceptedStep
	// settledErr is the terminal failure, if any.
	settledErr error
}

// acceptedStep is one handshake step's idempotency snapshot.
type acceptedStep struct {
	accepted  []byte // canonical encoding of the accepted inbound message
	responded []byte // canonical outbound snapshot (nil when the step produced no response)
}

// NewResumeAuthSession builds a session for one attempt. The context must carry the
// transfer-scoped resume secret; a missing/invalid secret is rejected up front.
func NewResumeAuthSession(ctx ResumeAuthContext) (*ResumeAuthSession, error) {
	// No implicit version: a security protocol must be explicit. Version 0 (the zero
	// value) fails exactly like any other wrong version in both Go and TypeScript.
	if ctx.Version != ResumeAuthVersion {
		return nil, Errorf(CodeCompat, "resume: unsupported resume-auth version %d", ctx.Version)
	}
	if !isLowerHex(ctx.TransferID, 32) {
		return nil, Errorf(CodeAuth, "resume: transferId must be 32 lowercase hex characters")
	}
	if !isLowerHex(ctx.ManifestFingerprint, 64) {
		return nil, Errorf(CodeAuth, "resume: manifestFingerprint must be 64 lowercase hex characters")
	}
	if ctx.Role != RoleOfferer && ctx.Role != RoleJoiner {
		return nil, Errorf(CodeAuth, "resume: invalid role %q", ctx.Role)
	}
	if len(ctx.ResumeSecret) != resumeSecretBytes {
		return nil, Errorf(CodeStorage, "resume: missing or invalid resume secret (%d bytes)", len(ctx.ResumeSecret))
	}
	return &ResumeAuthSession{ctx: ctx, state: resumeStateIdle}, nil
}

// Start begins the handshake. The offerer generates its fresh nonce and returns resume_init;
// the joiner has nothing to send and returns nil.
func (s *ResumeAuthSession) Start() (*ResumeMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != resumeStateIdle {
		return nil, Errorf(CodeProtocol, "resume: Start called in state %d", s.state)
	}
	if s.ctx.Role == RoleJoiner {
		// The joiner cannot initiate: it waits for the offerer's resume_init.
		return nil, Errorf(CodeProtocol, "resume: joiner cannot start the handshake")
	}
	nonce, err := s.randomNonce()
	if err != nil {
		s.failLocked(err)
		return nil, err
	}
	s.offererNonce = nonce
	msg := &ResumeMessage{Type: ResumeMsgInit, Version: ResumeAuthVersion, Role: RoleOfferer, Nonce: b64enc(nonce)}
	s.state = resumeStateAwaitChallenge
	return msg, nil
}

// Handle feeds one inbound message. It returns the outbound message to send (if any) and,
// when mutual authentication completes, the fresh resumed keys. A message from an
// impossible state, a conflicting duplicate, or a failed proof settles the session failed.
func (s *ResumeAuthSession) Handle(payload []byte) (*ResumeMessage, *ResumeAuthResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == resumeStateFailed {
		return nil, nil, s.settledErr
	}
	msg, err := DecodeResumeMessage(payload)
	if err != nil {
		s.failLocked(err)
		return nil, nil, err
	}
	// Idempotent replay first: an exact duplicate of ANY accepted message (current or
	// settled step) is re-answered with the SAME snapshot for the rest of the session —
	// including after done — so a lost response is retransmitted identically, never with a
	// fresh nonce/proof. A snapshot with no response (offerer's accepted ready) is a
	// settled no-op; a snapshot that produced a response re-answers it with the same bytes.
	if step, ok := s.findStep(payload); ok {
		if step.responded == nil {
			return nil, s.result, nil
		}
		out, err := DecodeResumeMessage(step.responded)
		if err != nil {
			s.failLocked(err)
			return nil, nil, err
		}
		return out, s.result, nil
	}
	switch s.ctx.Role {
	case RoleOfferer:
		return s.handleOfferer(msg, payload)
	default:
		return s.handleJoiner(msg, payload)
	}
}

// findStep returns the snapshot of the accepted message whose canonical encoding exactly
// equals payload, if any.
func (s *ResumeAuthSession) findStep(payload []byte) (acceptedStep, bool) {
	for _, step := range s.steps {
		if bytes.Equal(payload, step.accepted) {
			return step, true
		}
	}
	return acceptedStep{}, false
}

// handleOfferer processes an inbound message on the offerer side.
func (s *ResumeAuthSession) handleOfferer(msg *ResumeMessage, payload []byte) (*ResumeMessage, *ResumeAuthResult, error) {
	switch msg.Type {
	case ResumeMsgChallenge:
		// A challenge that is not an exact duplicate of the accepted one is a conflicting
		// duplicate (challenge replacement after proof is forbidden).
		if s.state != resumeStateAwaitChallenge {
			s.failLocked(Errorf(CodeAuth, "resume: conflicting duplicate resume_challenge"))
			return nil, nil, s.settledErr
		}
		return s.acceptChallenge(msg, payload)
	case ResumeMsgReady:
		if s.state != resumeStateAwaitReady {
			s.failLocked(Errorf(CodeProtocol, "resume: unexpected resume_ready in state %d", s.state))
			return nil, nil, s.settledErr
		}
		proof, _ := base64.RawURLEncoding.DecodeString(msg.Proof)
		if !verifyResumeProof(proof, s.ctx.ResumeSecret, s.transcript, resumeProofTagReady, infoResumeProofJoiner) {
			s.failLocked(Errorf(CodeAuth, "resume: joiner ready proof verification failed"))
			return nil, nil, s.settledErr
		}
		// Snapshot the accepted ready (no outbound response): an exact duplicate after
		// done is a settled no-op; a different ready is a conflicting duplicate that fails.
		s.steps = append(s.steps, acceptedStep{accepted: append([]byte(nil), payload...)})
		s.state = resumeStateDone
		result, err := s.buildResult()
		if err != nil {
			s.failLocked(err)
			return nil, nil, err
		}
		s.result = result
		return nil, s.result, nil
	default:
		s.failLocked(Errorf(CodeProtocol, "resume: offerer received unexpected %q", msg.Type))
		return nil, nil, s.settledErr
	}
}

// acceptChallenge verifies the joiner's proof and emits the offerer's confirm.
func (s *ResumeAuthSession) acceptChallenge(msg *ResumeMessage, payload []byte) (*ResumeMessage, *ResumeAuthResult, error) {
	joinerNonce, err := base64.RawURLEncoding.DecodeString(msg.Nonce)
	if err != nil {
		s.failLocked(Errorf(CodeProtocol, "resume: malformed joiner nonce"))
		return nil, nil, s.settledErr
	}
	s.joinerNonce = joinerNonce
	transcript, err := ResumeTranscript(s.ctx.Version, s.ctx.TransferID, s.ctx.ManifestFingerprint, s.offererNonce, s.joinerNonce)
	if err != nil {
		s.failLocked(err)
		return nil, nil, err
	}
	s.transcript = transcript
	proof, _ := base64.RawURLEncoding.DecodeString(msg.Proof)
	if !verifyResumeProof(proof, s.ctx.ResumeSecret, transcript, resumeProofTagJoiner, infoResumeProofJoiner) {
		s.failLocked(Errorf(CodeAuth, "resume: joiner proof verification failed"))
		return nil, nil, s.settledErr
	}
	offererProof, err := ResumeOffererProof(s.ctx.ResumeSecret, transcript)
	if err != nil {
		s.failLocked(err)
		return nil, nil, err
	}
	confirm := &ResumeMessage{Type: ResumeMsgConfirm, Version: ResumeAuthVersion, Role: RoleOfferer, Proof: b64enc(offererProof)}
	// Snapshot both the accepted challenge and the generated confirm so a retransmission is
	// re-answered with the SAME proof (never a fresh nonce/proof).
	s.steps = append(s.steps, acceptedStep{
		accepted:  append([]byte(nil), payload...),
		responded: mustEncodeMessage(confirm),
	})
	s.state = resumeStateAwaitReady
	return confirm, nil, nil
}

// handleJoiner processes an inbound message on the joiner side.
func (s *ResumeAuthSession) handleJoiner(msg *ResumeMessage, payload []byte) (*ResumeMessage, *ResumeAuthResult, error) {
	switch msg.Type {
	case ResumeMsgInit:
		// A second, different init (challenge replacement after proof is forbidden) is a
		// conflicting duplicate; an exact duplicate was already re-answered above.
		if s.state != resumeStateIdle {
			s.failLocked(Errorf(CodeAuth, "resume: conflicting duplicate resume_init"))
			return nil, nil, s.settledErr
		}
		return s.acceptInit(msg, payload)
	case ResumeMsgConfirm:
		if s.state != resumeStateAwaitConfirm {
			s.failLocked(Errorf(CodeAuth, "resume: conflicting duplicate resume_confirm"))
			return nil, nil, s.settledErr
		}
		proof, _ := base64.RawURLEncoding.DecodeString(msg.Proof)
		if !verifyResumeProof(proof, s.ctx.ResumeSecret, s.transcript, resumeProofTagOfferer, infoResumeProofOfferer) {
			s.failLocked(Errorf(CodeAuth, "resume: offerer proof verification failed"))
			return nil, nil, s.settledErr
		}
		readyProof, err := ResumeReadyProof(s.ctx.ResumeSecret, s.transcript)
		if err != nil {
			s.failLocked(err)
			return nil, nil, err
		}
		ready := &ResumeMessage{Type: ResumeMsgReady, Version: ResumeAuthVersion, Role: RoleJoiner, Proof: b64enc(readyProof)}
		// Snapshot the accepted confirm and its ready response: the settled joiner re-answers
		// an exact duplicate confirm with the SAME ready (a lost ready never stalls the
		// offerer); a different confirm is a conflicting duplicate that fails.
		s.steps = append(s.steps, acceptedStep{
			accepted:  append([]byte(nil), payload...),
			responded: mustEncodeMessage(ready),
		})
		s.state = resumeStateDone
		result, err := s.buildResult()
		if err != nil {
			s.failLocked(err)
			return nil, nil, err
		}
		s.result = result
		return ready, s.result, nil
	default:
		s.failLocked(Errorf(CodeProtocol, "resume: joiner received unexpected %q", msg.Type))
		return nil, nil, s.settledErr
	}
}

// acceptInit verifies the init and emits the joiner's challenge with a fresh nonce and the
// joiner proof over the complete transcript.
func (s *ResumeAuthSession) acceptInit(msg *ResumeMessage, payload []byte) (*ResumeMessage, *ResumeAuthResult, error) {
	offererNonce, err := base64.RawURLEncoding.DecodeString(msg.Nonce)
	if err != nil {
		s.failLocked(Errorf(CodeProtocol, "resume: malformed offerer nonce"))
		return nil, nil, s.settledErr
	}
	s.offererNonce = offererNonce
	nonce, err := s.randomNonce()
	if err != nil {
		s.failLocked(err)
		return nil, nil, err
	}
	s.joinerNonce = nonce
	transcript, err := ResumeTranscript(s.ctx.Version, s.ctx.TransferID, s.ctx.ManifestFingerprint, s.offererNonce, s.joinerNonce)
	if err != nil {
		s.failLocked(err)
		return nil, nil, err
	}
	s.transcript = transcript
	joinerProof, err := ResumeJoinerProof(s.ctx.ResumeSecret, transcript)
	if err != nil {
		s.failLocked(err)
		return nil, nil, err
	}
	challenge := &ResumeMessage{
		Type: ResumeMsgChallenge, Version: ResumeAuthVersion, Role: RoleJoiner,
		Nonce: b64enc(nonce), Proof: b64enc(joinerProof),
	}
	s.steps = append(s.steps, acceptedStep{
		accepted:  append([]byte(nil), payload...),
		responded: mustEncodeMessage(challenge),
	})
	s.state = resumeStateAwaitConfirm
	return challenge, nil, nil
}

// buildResult derives the fresh directional keys. It runs only after mutual authentication
// completed, so the keys are never exposed earlier; a failed attempt abandons them.
func (s *ResumeAuthSession) buildResult() (*ResumeAuthResult, error) {
	master, err := ResumeSessionMaster(s.ctx.ResumeSecret, s.transcript)
	if err != nil {
		return nil, err
	}
	keys, err := DeriveTransferKeys(master)
	if err != nil {
		return nil, err
	}
	return &ResumeAuthResult{
		Role:        s.ctx.Role,
		TransferID:  s.ctx.TransferID,
		Keys:        keys,
		SendCounter: 0,
		RecvCounter: 0,
	}, nil
}

func (s *ResumeAuthSession) randomNonce() ([]byte, error) {
	if s.ctx.NonceSource != nil {
		b, err := s.ctx.NonceSource(resumeNonceBytes)
		if err != nil {
			return nil, Errorf(CodeAuth, "resume: nonce source failed: %v", err)
		}
		if len(b) != resumeNonceBytes {
			return nil, Errorf(CodeAuth, "resume: nonce source returned %d bytes, want %d", len(b), resumeNonceBytes)
		}
		return b, nil
	}
	b := make([]byte, resumeNonceBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, Errorf(CodeAuth, "resume: generate nonce: %v", err)
	}
	return b, nil
}

func (s *ResumeAuthSession) failLocked(err error) {
	if s.settledErr == nil {
		s.settledErr = err
	}
	s.state = resumeStateFailed
}

// verifyResumeProof recomputes the expected proof and compares in constant time.
func verifyResumeProof(got, secret, transcript []byte, tag byte, info string) bool {
	if len(got) != resumeProofBytes {
		return false
	}
	key, err := resumeProofKey(secret, info)
	if err != nil {
		return false
	}
	expected := hmacSHA256(key, append(append([]byte(nil), transcript...), tag))
	return hmac.Equal(expected, got)
}

func mustEncodeMessage(m *ResumeMessage) []byte {
	encoded, err := EncodeResumeMessage(m)
	if err != nil {
		panic(err) // only reachable with a message already validated
	}
	return encoded
}

// NegotiateResumeAuth reports whether both peers advertised the resume-auth-v1 capability.
// The security invariant that MUST hold (ADR 0005 §2/§9) is: capability absent, stripped,
// or otherwise untrusted => authenticated cross-session resume is UNAVAILABLE — never a
// fallback to unauthenticated durable progress reuse. PR08 owns the discovery path that
// obtains the authenticated capability state for a cross-session attempt; this predicate
// only computes the boolean from whatever features are presented.
func NegotiateResumeAuth(localFeatures, remoteFeatures []string) bool {
	return containsFeature(localFeatures, ResumeAuthCapability) && containsFeature(remoteFeatures, ResumeAuthCapability)
}

func containsFeature(features []string, want string) bool {
	for _, f := range features {
		if f == want {
			return true
		}
	}
	return false
}
