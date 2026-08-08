package rendezvous

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"

	"github.com/sendarc/wire"
)

// Phase is where a session is in the handshake. It advances monotonically until
// PhaseEstablished or PhaseFailed. The values mirror RendezvousPhase in rendezvous.ts.
type Phase string

// The handshake phases, in the order a session advances through them.
const (
	PhaseIdle           Phase = "idle"
	PhaseAllocating     Phase = "allocating"      // offerer: sent create, awaiting the room number
	PhaseWaiting        Phase = "waiting"         // awaiting the other peer to join
	PhaseHandshaking    Phase = "handshaking"     // paired; SPAKE2 share sent, awaiting the peer's
	PhaseConfirming     Phase = "confirming"      // shared point derived; MAC sent, awaiting the peer's
	PhaseExchangingCaps Phase = "exchanging-caps" // key confirmed; caps sent, awaiting the peer's
	PhaseEstablished    Phase = "established"     // both caps exchanged; keys ready
	PhaseFailed         Phase = "failed"
)

// Error codes for a failed rendezvous: the client-side handshake failures plus any server
// error code relayed on an error message.
const (
	CodeConfirmationFailed = "confirmation_failed"
	CodeBadPeerMessage     = "bad_peer_message"
	CodePeerLeft           = "peer_left"
	CodeAborted            = "aborted"
	CodeProtocol           = "protocol"
)

// Error is a typed rendezvous failure carrying a stable Code.
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return fmt.Sprintf("rendezvous: %s: %s", e.Code, e.Msg) }

// Role identifies which end of the handshake this peer plays.
type Role = wire.Role

// The two roles, re-exported from the wire package for callers of this package.
const (
	RoleOfferer = wire.RoleOfferer
	RoleJoiner  = wire.RoleJoiner
)

// Result is everything a completed handshake yields — enough to run the M2 transfer under
// the same key. The caps exchange consumed frame counter 0 in each direction, so both
// counters are 1: the transfer must continue from here without resetting, or it would
// reuse an AES-GCM nonce.
type Result struct {
	Role        Role
	Room        int
	Code        string // the full normalized invite code (<room>-<words>); the SPAKE2 password
	Master      []byte
	Keys        wire.TransferKeys
	Spake2      *wire.Spake2Output // retained for the M2 SDP/ICE MAC keys (KcA/KcB)
	LocalCaps   Caps
	RemoteCaps  Caps
	SendCounter uint64
	RecvCounter uint64
}

// Options configures a session. Exactly one role is built per session; Code is required for
// a joiner, Words/WordCount apply only to an offerer.
type Options struct {
	Role      Role
	Transport Sink
	// Joiner only: the invite code to pair into.
	Code string
	// Offerer only: fixed words (mainly for tests) and/or a word count. Empty Words means
	// generate WordCount words; zero WordCount means the protocol default.
	Words     string
	WordCount int
	// LocalCaps overrides the announced capabilities. Nil uses DefaultCaps.
	LocalCaps *Caps
	// OnPhase and OnCode are optional progress callbacks, invoked while a state transition
	// holds the session lock — they must not call back into the session.
	OnPhase func(Phase)
	OnCode  func(string)
}

// Session is a transport-agnostic rendezvous state machine. Start it once, feed inbound
// messages with Handle, and Wait for the result. All state transitions are serialized by a
// mutex, so Handle may be called from the socket read loop while Wait blocks elsewhere.
type Session struct {
	role      Role
	sink      Sink
	localCaps Caps
	onPhase   func(Phase)
	onCode    func(string)

	// joiner input / offerer generation
	joinCode string
	words    string

	mu      sync.Mutex
	phase   Phase
	code    string
	room    int
	w       *big.Int // SPAKE2 password scalar
	secret  *big.Int // ephemeral secret (x for offerer, y for joiner)
	shared  bool     // our SPAKE2 share has been sent
	spake2  *wire.Spake2Output
	keys    wire.TransferKeys
	master  []byte
	sendCtr uint64
	recvCtr uint64

	settled bool
	result  *Result
	err     error
	done    chan struct{}
}

// New builds a session for the configured role. It does not touch the network until Start.
func New(opts Options) *Session {
	caps := DefaultCaps()
	if opts.LocalCaps != nil {
		caps = *opts.LocalCaps
	}
	return &Session{
		role:      opts.Role,
		sink:      opts.Transport,
		localCaps: caps,
		onPhase:   opts.OnPhase,
		onCode:    opts.OnCode,
		joinCode:  opts.Code,
		words:     opts.Words,
		phase:     PhaseIdle,
		room:      -1,
		done:      make(chan struct{}),
	}
}

// Phase returns the current handshake phase.
func (s *Session) Phase() Phase {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.phase
}

// Code returns the invite code once known (empty for an offerer until the room is allocated).
func (s *Session) Code() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.code
}

// Done is closed when the session settles, successfully or not.
func (s *Session) Done() <-chan struct{} { return s.done }

// Result blocks until the session settles, then returns the keys or the failure.
func (s *Session) Result() (*Result, error) {
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.result, s.err
}

// Start begins the handshake: an offerer sends create, a joiner sends join.
func (s *Session) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.settled || s.phase != PhaseIdle {
		return
	}
	secret, err := wire.RandomScalar()
	if err != nil {
		s.fail(&Error{CodeProtocol, "generate secret: " + err.Error()})
		return
	}
	s.secret = secret

	if s.role == RoleJoiner {
		parsed, err := wire.ParseCode(s.joinCode)
		if err != nil {
			s.fail(&Error{CodeProtocol, "invalid code: " + err.Error()})
			return
		}
		s.room = parsed.Room
		s.words = parsed.Words
		s.code = wire.FormatCode(parsed.Room, parsed.Words)
		if s.w, err = wire.PasswordToScalar(wire.NormalizeCode(s.code)); err != nil {
			s.fail(&Error{CodeProtocol, "derive w: " + err.Error()})
			return
		}
		if s.onCode != nil {
			s.onCode(s.code)
		}
		if !s.emit(Message{Type: typeJoin, Room: &s.room}) {
			return
		}
		s.setPhase(PhaseWaiting)
		return
	}

	// Offerer: generate the words now; the room number arrives in created.
	if s.words == "" {
		w, err := wire.GenerateWords(wordCountOrDefault(0))
		if err != nil {
			s.fail(&Error{CodeProtocol, "generate words: " + err.Error()})
			return
		}
		s.words = w
	}
	if !s.emit(Message{Type: typeCreate}) {
		return
	}
	s.setPhase(PhaseAllocating)
}

// Handle feeds one inbound signaling message.
func (s *Session) Handle(msg Message) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.settled {
		return
	}
	switch msg.Type {
	case typeCreated:
		s.onCreated(msg)
	case typePeerJoined:
		s.onPeerJoined(msg)
	case typePake:
		s.onPake(msg)
	case typeConfirm:
		s.onConfirm(msg)
	case typeCaps:
		s.onCaps(msg)
	case typeBye:
		s.fail(&Error{CodePeerLeft, orDefault(msg.Reason, "peer left")})
	case typeError:
		s.fail(&Error{orDefault(msg.Code, CodeProtocol), orDefault(msg.Msg, msg.Code)})
	default:
		s.fail(&Error{CodeProtocol, "unexpected " + msg.Type + " in " + string(s.phase)})
	}
}

// Abort notifies the peer with bye and fails the session. Safe to call concurrently and
// more than once.
func (s *Session) Abort(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.settled {
		return
	}
	_ = s.sink.Send(Message{Type: typeBye, Reason: reason}) // best-effort
	s.fail(&Error{CodeAborted, orDefault(reason, "aborted")})
}

// Fail settles the session with a transport-level error (e.g. the socket dropped). It does
// not send bye, since the transport is already gone.
func (s *Session) Fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if re, ok := err.(*Error); ok {
		s.fail(re)
		return
	}
	s.fail(&Error{CodePeerLeft, err.Error()})
}

// --- handlers (all run under s.mu) ------------------------------------------

func (s *Session) onCreated(msg Message) {
	if s.role != RoleOfferer || s.phase != PhaseAllocating || msg.Room == nil {
		s.fail(&Error{CodeProtocol, "unexpected created"})
		return
	}
	s.room = *msg.Room
	s.code = wire.FormatCode(s.room, s.words)
	w, err := wire.PasswordToScalar(wire.NormalizeCode(s.code))
	if err != nil {
		s.fail(&Error{CodeProtocol, "derive w: " + err.Error()})
		return
	}
	s.w = w
	if s.onCode != nil {
		s.onCode(s.code)
	}
	s.setPhase(PhaseWaiting)
}

func (s *Session) onPeerJoined(msg Message) {
	if s.phase != PhaseWaiting || Role(msg.Role) != s.role {
		s.fail(&Error{CodeProtocol, "unexpected peer-joined"})
		return
	}
	// Paired. Send our SPAKE2 share; the peer sends theirs independently (one round trip).
	share, err := wire.ComputeShare(s.role, s.w, s.secret)
	if err != nil {
		s.fail(&Error{CodeProtocol, "compute share: " + err.Error()})
		return
	}
	s.shared = true
	if !s.emit(Message{Type: typePake, Msg: b64encode(share)}) {
		return
	}
	s.setPhase(PhaseHandshaking)
}

func (s *Session) onPake(msg Message) {
	if !s.shared {
		s.fail(&Error{CodeProtocol, "pake before pairing"})
		return
	}
	peerShare, err := b64decode(msg.Msg)
	if err != nil {
		s.fail(&Error{CodeBadPeerMessage, "malformed pake"})
		return
	}
	// Finish decodes and validates the peer's point; an off-curve share errors here.
	out, err := wire.Finish(s.role, s.w, s.secret, peerShare)
	if err != nil {
		s.fail(&Error{CodeBadPeerMessage, "invalid pake share"})
		return
	}
	s.spake2 = out
	ownConfirm := out.ConfirmA
	if s.role == RoleJoiner {
		ownConfirm = out.ConfirmB
	}
	if !s.emit(Message{Type: typeConfirm, Mac: b64encode(ownConfirm)}) {
		return
	}
	s.setPhase(PhaseConfirming)
}

func (s *Session) onConfirm(msg Message) {
	if s.spake2 == nil {
		s.fail(&Error{CodeProtocol, "confirm before pake"})
		return
	}
	got, err := b64decode(msg.Mac)
	if err != nil {
		s.fail(&Error{CodeBadPeerMessage, "malformed confirm"})
		return
	}
	expected := s.spake2.ConfirmB
	if s.role == RoleJoiner {
		expected = s.spake2.ConfirmA
	}
	if !hmac.Equal(got, expected) {
		// Wrong code or a MITM: fail closed (RFC 9382 §4). This is the core M1 guarantee.
		s.fail(&Error{CodeConfirmationFailed, "key confirmation failed"})
		return
	}
	// Confirmed. Derive the transfer keys and send our encrypted caps.
	master, err := wire.DeriveMaster(s.spake2.Ke, s.spake2.Transcript)
	if err != nil {
		s.fail(&Error{CodeProtocol, "derive master: " + err.Error()})
		return
	}
	s.master = master
	keys, err := wire.DeriveTransferKeys(master)
	if err != nil {
		s.fail(&Error{CodeProtocol, "derive transfer keys: " + err.Error()})
		return
	}
	s.keys = keys

	payload, err := json.Marshal(s.localCaps)
	if err != nil {
		s.fail(&Error{CodeProtocol, "marshal caps: " + err.Error()})
		return
	}
	frame, err := wire.Seal(s.sendDir(), s.sendCtr, capsHeader(), payload)
	if err != nil {
		s.fail(&Error{CodeProtocol, "seal caps: " + err.Error()})
		return
	}
	s.sendCtr++
	if !s.emit(Message{Type: typeCaps, Frame: b64encode(frame)}) {
		return
	}
	s.setPhase(PhaseExchangingCaps)
}

func (s *Session) onCaps(msg Message) {
	if s.keys.O2J.Key == nil {
		s.fail(&Error{CodeProtocol, "caps before key confirmation"})
		return
	}
	frame, err := b64decode(msg.Frame)
	if err != nil {
		s.fail(&Error{CodeBadPeerMessage, "malformed caps"})
		return
	}
	opened, err := wire.Open(s.recvDir(), s.recvCtr, frame)
	if err != nil {
		s.fail(&Error{CodeBadPeerMessage, "caps failed to decrypt"})
		return
	}
	s.recvCtr++
	if opened.Header.Type != wire.FrameCaps {
		s.fail(&Error{CodeBadPeerMessage, "first frame is not caps"})
		return
	}
	var remote Caps
	if err := json.Unmarshal(opened.Plaintext, &remote); err != nil {
		s.fail(&Error{CodeBadPeerMessage, "malformed caps payload"})
		return
	}
	s.succeed(&Result{
		Role:        s.role,
		Room:        s.room,
		Code:        s.code,
		Master:      s.master,
		Keys:        s.keys,
		Spake2:      s.spake2,
		LocalCaps:   s.localCaps,
		RemoteCaps:  remote,
		SendCounter: s.sendCtr,
		RecvCounter: s.recvCtr,
	})
}

// --- helpers (all run under s.mu) -------------------------------------------

func (s *Session) sendDir() wire.DirectionalKey {
	if s.role == RoleOfferer {
		return s.keys.O2J
	}
	return s.keys.J2O
}

func (s *Session) recvDir() wire.DirectionalKey {
	if s.role == RoleOfferer {
		return s.keys.J2O
	}
	return s.keys.O2J
}

// emit sends an outbound message, failing the session if the transport rejects it. It
// returns false if the session failed, so callers stop advancing.
func (s *Session) emit(msg Message) bool {
	if err := s.sink.Send(msg); err != nil {
		s.fail(&Error{CodePeerLeft, "send " + msg.Type + ": " + err.Error()})
		return false
	}
	return true
}

func (s *Session) setPhase(p Phase) {
	s.phase = p
	if s.onPhase != nil {
		s.onPhase(p)
	}
}

func (s *Session) fail(err *Error) {
	if s.settled {
		return
	}
	s.settled = true
	s.err = err
	s.setPhase(PhaseFailed)
	close(s.done)
}

func (s *Session) succeed(r *Result) {
	if s.settled {
		return
	}
	s.settled = true
	s.result = r
	s.setPhase(PhaseEstablished)
	close(s.done)
}

func wordCountOrDefault(n int) int {
	if n > 0 {
		return n
	}
	return 2 // DEFAULT_WORD_COUNT (constants.ts)
}

func orDefault(v, fallback string) string {
	if v != "" {
		return v
	}
	return fallback
}

// base64url without padding (RFC 4648 §5), matching bytesToBase64url in the TS core.
func b64encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func b64decode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
