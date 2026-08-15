package wire

// Resume preamble (V13-PR08): the product integration of the reviewed PR07 resume-auth
// engine. It runs the transport-agnostic mutual-authentication handshake over the sealed
// session channel — strictly BEFORE the transfer engine starts — so durable progress from a
// previous authenticated session is never reused under session keys, and no
// Manifest/ResumeState/BlockData/Complete frame can flow before the peers authenticated
// continuity with each other.
//
// The resume-auth messages travel as FrameResumeAuth frames sealed under the SESSION
// directional keys (the keys the SPAKE2 handshake just derived): the session key epoch is
// used ONLY to carry the four resume-auth messages, and the transfer itself runs under the
// FRESH key epoch derived from the mutually authenticated resume master (ADR 0005 §7). The
// PR07 engine is unchanged: transferId + manifest fingerprint + role + resume secret are
// local context (never transmitted), the transcript binds them, and the fresh nonces make
// every attempt a new key epoch.
//
// Fail-closed rules: any inbound frame that is not a well-formed resume-auth frame (wrong
// type, wrong counter, torn, tampered, oversized, malformed) settles the preamble failed
// before the transfer could start. An exact duplicate of the last accepted frame (a
// transport-level re-send with the same counter) is re-opened and re-answered idempotently
// from the engine's snapshots — never with a fresh nonce or proof. There is no challenge
// replacement, no nonce/proof/role/version mutation, and no unbounded history.

import (
	"bytes"
	"errors"
	"sync"
)

// ResumePreambleOptions configures one resume-auth exchange over the sealed session channel.
type ResumePreambleOptions struct {
	// Role is this peer's stable role: offerer (sender) or joiner (receiver).
	Role Role
	// TransferID and Fingerprint are the LOCAL resume context — the stable transfer id and
	// canonical manifest fingerprint of the interrupted transfer. They are never transmitted;
	// the engine binds them into the transcript.
	TransferID  string
	Fingerprint string
	// ResumeSecret is the decoded 32-byte transfer-scoped credential from the local sender
	// record or receiver journal (ADR 0005 §4). Never printed, logged, or exposed.
	ResumeSecret []byte
	// Send transmits one sealed frame (the same callback the transfer engine will use).
	Send func(frame []byte) error
	// SendDir/RecvDir are the SESSION directional keys. Resume-auth frames are sealed under
	// them; the transfer itself later uses the fresh resumed key epoch.
	SendDir DirectionalKey
	RecvDir DirectionalKey
	// SendCounter is the first frame counter for this peer's resume-auth frames (continues
	// the session handshake counters); RecvCounter is the expected first counter of the
	// peer's resume-auth frames.
	SendCounter uint64
	RecvCounter uint64
	// NonceSource injects deterministic fresh nonces in tests; nil uses crypto/rand.
	NonceSource func(n int) ([]byte, error)
}

// ResumePreamble is one in-flight resume-auth exchange. The driver wires Handle as the
// inbound data hook, calls Start (offerer only), and waits on Done; Result exposes the
// fresh resumed key epoch only after mutual authentication completes. Any failure is
// terminal and preserved.
type ResumePreamble struct {
	opts ResumePreambleOptions
	sess *ResumeAuthSession

	mu          sync.Mutex
	sendCounter uint64
	recvCounter uint64
	started     bool
	done        chan struct{}
	result      *ResumeAuthResult
	err         error
	// lastAccepted is the canonical payload of the last accepted inbound message, kept so an
	// exact duplicate retransmission (same counter) is re-opened and re-answered idempotently.
	lastAccepted []byte
}

// NewResumePreamble validates the local resume context and builds the PR07 session. A
// missing or invalid secret, role, or context fails before anything is sent.
func NewResumePreamble(opts ResumePreambleOptions) (*ResumePreamble, error) {
	sess, err := NewResumeAuthSession(ResumeAuthContext{
		Version:             ResumeAuthVersion,
		TransferID:          opts.TransferID,
		ManifestFingerprint: opts.Fingerprint,
		Role:                opts.Role,
		ResumeSecret:        opts.ResumeSecret,
		NonceSource:         opts.NonceSource,
	})
	if err != nil {
		return nil, err
	}
	if opts.Send == nil {
		return nil, Errorf(CodeProtocol, "resume: preamble requires a Send callback")
	}
	return &ResumePreamble{
		opts:        opts,
		sess:        sess,
		sendCounter: opts.SendCounter,
		recvCounter: opts.RecvCounter,
		done:        make(chan struct{}),
	}, nil
}

// Start begins the handshake: the offerer emits resume_init (sealed under the session send
// key at the continuing counter); the joiner has nothing to send and returns nil.
func (p *ResumePreamble) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.started {
		return Errorf(CodeProtocol, "resume: preamble already started")
	}
	p.started = true
	if p.opts.Role == RoleJoiner {
		return nil
	}
	msg, err := p.sess.Start()
	if err != nil {
		p.failLocked(err)
		return err
	}
	return p.sendLocked(msg)
}

// Handle feeds one inbound sealed frame. It is called from the read loop and is fully
// serialized; a malformed, wrong-type, replayed, or otherwise invalid frame settles the
// preamble failed (terminal) before the transfer could start.
func (p *ResumePreamble) Handle(frame []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil || p.result != nil {
		return // settled: ignore late frames
	}
	payload, err := p.openLocked(frame)
	if err != nil {
		p.failLocked(err)
		return
	}
	out, result, err := p.sess.Handle(payload)
	if err != nil {
		p.failLocked(err)
		return
	}
	p.lastAccepted = append([]byte(nil), payload...)
	// The final step (the joiner's accept of resume_confirm) returns BOTH the outbound
	// resume_ready AND the result: the ready must go out before the side is announced
	// settled, or the offerer would wait forever for a message that was never sent.
	if out != nil {
		if err := p.sendLocked(out); err != nil {
			p.failLocked(err)
			return
		}
	}
	if result != nil {
		p.result = result
		close(p.done)
	}
}

// openLocked opens one inbound frame under the session recv key at the expected counter,
// requiring the FrameResumeAuth tag. An exact duplicate of the last accepted frame (the
// same counter as the previous frame, re-sent by the transport) is re-opened and accepted
// idempotently so a lost response is retransmitted identically; any other replay fails.
func (p *ResumePreamble) openLocked(frame []byte) ([]byte, error) {
	opened, err := OpenSequenced(p.opts.RecvDir, p.recvCounter, frame)
	if err != nil {
		if errors.Is(err, ErrFrameReplay) && p.recvCounter > 0 && len(p.lastAccepted) > 0 {
			// Exact-duplicate re-send: the frame carries the previous counter and must be
			// byte-identical to the last accepted message to be answered idempotently.
			prev, prevErr := Open(p.opts.RecvDir, p.recvCounter-1, frame)
			if prevErr == nil && prev.Header.Type == FrameResumeAuth &&
				bytes.Equal(prev.Plaintext, p.lastAccepted) {
				return prev.Plaintext, nil
			}
		}
		return nil, Errorf(CodeProtocol, "resume: inbound frame rejected: %v", err)
	}
	if opened.Header.Type != FrameResumeAuth {
		return nil, Errorf(CodeProtocol,
			"resume: inbound frame type %d before resume authentication completed", opened.Header.Type)
	}
	p.recvCounter = opened.Counter + 1
	return opened.Plaintext, nil
}

// sendLocked seals and transmits one resume-auth message under the session send key at the
// continuing counter. The counter advances exactly once per sent frame.
func (p *ResumePreamble) sendLocked(msg *ResumeMessage) error {
	payload, err := EncodeResumeMessage(msg)
	if err != nil {
		return err
	}
	frame, err := Seal(p.opts.SendDir, p.sendCounter, FrameHeaderInput{
		Version: FrameVersion, Type: FrameResumeAuth,
	}, payload)
	if err != nil {
		return Errorf(CodeProtocol, "resume: seal preamble frame: %v", err)
	}
	if err := p.opts.Send(frame); err != nil {
		return Errorf(CodeConnection, "resume: send preamble frame: %v", err)
	}
	p.sendCounter++
	return nil
}

// Done resolves when the preamble settles (mutual authentication succeeded or failed).
func (p *ResumePreamble) Done() <-chan struct{} { return p.done }

// Settled reports whether the preamble has settled (success or terminal failure).
func (p *ResumePreamble) Settled() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.result != nil || p.err != nil
}

// Result returns the fresh resumed key epoch after mutual authentication, or the terminal
// error. The keys are exposed only after the handshake completed; a failed attempt abandons
// the candidate key material (ADR 0005 §7).
func (p *ResumePreamble) Result() (*ResumeAuthResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return nil, p.err
	}
	if p.result == nil {
		return nil, Errorf(CodeProtocol, "resume: preamble has not settled")
	}
	return p.result, nil
}

func (p *ResumePreamble) failLocked(err error) {
	if p.err == nil {
		p.err = err
	}
	if p.result == nil {
		close(p.done)
	}
}
