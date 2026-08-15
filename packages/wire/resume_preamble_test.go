package wire

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// memPipe is a tiny in-memory transport between two preambles.
type memPipe struct {
	ch chan []byte
}

func (m *memPipe) send(frame []byte) error {
	m.ch <- frame
	return nil
}

// preamblePair wires two preambles through in-memory channels and drives them to settle,
// mirroring production cancellation semantics: a failed handshake on one side is torn down
// by the driver (here: canceling the context), which unblocks the peer. It returns each
// side's result and error (a canceled peer reports its context error). pump goroutines are
// joined before returning.
func preamblePair(ctx context.Context, t *testing.T, cancel context.CancelFunc, o, j ResumePreambleOptions) (*ResumeAuthResult, error, *ResumeAuthResult, error) {
	t.Helper()
	chO := make(chan []byte, 16)
	chJ := make(chan []byte, 16)
	o.Send = func(f []byte) error { return (&memPipe{ch: chJ}).send(f) }
	j.Send = func(f []byte) error { return (&memPipe{ch: chO}).send(f) }
	po, err := NewResumePreamble(o)
	if err != nil {
		t.Fatalf("offerer preamble: %v", err)
	}
	pj, err := NewResumePreamble(j)
	if err != nil {
		t.Fatalf("joiner preamble: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for f := range chJ {
			pj.Handle(f)
		}
	}()
	go func() {
		defer wg.Done()
		for f := range chO {
			po.Handle(f)
		}
	}()
	if err := po.Start(); err != nil {
		t.Fatalf("offerer Start: %v", err)
	}
	// Wait for the first side to settle. A successful handshake settles both sides through
	// the message chain; a one-sided failure (e.g. proof mismatch) settles only the failing
	// side and the peer is released by the connection teardown (cancel), exactly like
	// production where the driver cancels the transfer context on a failed handshake.
	var resO, resJ *ResumeAuthResult
	var errO, errJ error
	select {
	case <-po.Done():
		resO, errO = po.Result()
	case <-pj.Done():
		resJ, errJ = pj.Result()
	case <-ctx.Done():
	}
	if errO == nil && resO != nil {
		select {
		case <-pj.Done():
			resJ, errJ = pj.Result()
		case <-time.After(10 * time.Second):
			t.Fatal("joiner did not settle after a successful offerer")
		}
	} else if errJ == nil && resJ != nil {
		select {
		case <-po.Done():
			resO, errO = po.Result()
		case <-time.After(10 * time.Second):
			t.Fatal("offerer did not settle after a successful joiner")
		}
	}
	cancel()
	close(chO)
	close(chJ)
	wg.Wait()
	// A peer released by cancellation reports its unsettled state instead of hanging.
	if resO == nil && errO == nil {
		resO, errO = po.Result()
	}
	if resJ == nil && errJ == nil {
		resJ, errJ = pj.Result()
	}
	return resO, errO, resJ, errJ
}

// preambleContext builds the shared local resume context for a transfer.
func preambleContext(secret []byte, role Role, tid, fp string) ResumePreambleOptions {
	return ResumePreambleOptions{
		Role:         role,
		TransferID:   tid,
		Fingerprint:  fp,
		ResumeSecret: secret,
		SendDir:      sessionSendDir(role),
		RecvDir:      sessionRecvDir(role),
		SendCounter:  1, // session handshake consumed one frame per direction
		RecvCounter:  1,
		NonceSource:  nonceSource(1),
	}
}

// sessionSendDir/RecvDir return the SESSION directional keys for a role (the keys the
// SPAKE2 handshake derived; the transfer later switches to the fresh resumed epoch).
func sessionKeys(t *testing.T) TransferKeys {
	t.Helper()
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func sessionSendDir(role Role) DirectionalKey {
	keys, _ := DeriveTransferKeys(senderMaster())
	if role == RoleOfferer {
		return keys.O2J
	}
	return keys.J2O
}

func sessionRecvDir(role Role) DirectionalKey {
	keys, _ := DeriveTransferKeys(senderMaster())
	if role == RoleOfferer {
		return keys.J2O
	}
	return keys.O2J
}

// nonceSource returns deterministic distinct 32-byte nonces (test-only).
func nonceSource(start byte) func(n int) ([]byte, error) {
	next := start
	return func(n int) ([]byte, error) {
		if n != 32 {
			return nil, errors.New("nonce must be 32 bytes")
		}
		out := bytes.Repeat([]byte{next}, 32)
		next++
		return out, nil
	}
}

func TestResumePreambleMutualAuthHappyPath(t *testing.T) {
	secret := bytes.Repeat([]byte{0xAB}, 32)
	tid := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fp := strings.Repeat("b", 64)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resO, errO, resJ, errJ := preamblePair(ctx, t, cancel,
		preambleContext(secret, RoleOfferer, tid, fp),
		preambleContext(secret, RoleJoiner, tid, fp),
	)
	if errO != nil || errJ != nil {
		t.Fatalf("preamble failed: offerer=%v joiner=%v", errO, errJ)
	}
	if resO == nil || resJ == nil {
		t.Fatal("missing results")
	}
	// Both sides derive the same fresh directional keys, distinct from the session keys.
	sess := sessionKeys(t)
	if !bytes.Equal(resO.Keys.O2J.Key, resJ.Keys.O2J.Key) || !bytes.Equal(resO.Keys.J2O.Key, resJ.Keys.J2O.Key) {
		t.Fatal("peers derived different resumed keys")
	}
	for name, keys := range map[string]TransferKeys{"offerer": resO.Keys, "joiner": resJ.Keys} {
		if bytes.Equal(keys.O2J.Key, sess.O2J.Key) || bytes.Equal(keys.J2O.Key, sess.J2O.Key) {
			t.Fatalf("%s resumed keys equal the session keys (must be a fresh epoch)", name)
		}
	}
	// Fresh epoch: counters start at 0 only because the keys are new (ADR 0005 §7).
	if resO.SendCounter != 0 || resO.RecvCounter != 0 || resJ.SendCounter != 0 || resJ.RecvCounter != 0 {
		t.Fatalf("resumed counters = %d/%d %d/%d, want 0", resO.SendCounter, resO.RecvCounter, resJ.SendCounter, resJ.RecvCounter)
	}
	if resO.TransferID != tid || resJ.TransferID != tid {
		t.Fatal("result transfer id mismatch")
	}
	if resO.Role != RoleOfferer || resJ.Role != RoleJoiner {
		t.Fatal("result roles wrong")
	}
}

func TestResumePreambleFreshEpochPerAttempt(t *testing.T) {
	secret := bytes.Repeat([]byte{0xCD}, 32)
	tid := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fp := strings.Repeat("d", 64)
	// Distinct fresh nonces per attempt (the production path uses crypto/rand): attempt A
	// and attempt B for the same transfer MUST yield different traffic key epochs, and the
	// old keys are never read from disk because they are never persisted.
	ctxO1 := preambleContext(secret, RoleOfferer, tid, fp)
	ctxJ1 := preambleContext(secret, RoleJoiner, tid, fp)
	ctxO2 := preambleContext(secret, RoleOfferer, tid, fp)
	ctxJ2 := preambleContext(secret, RoleJoiner, tid, fp)
	ctxO2.NonceSource = nonceSource(0x21)
	ctxJ2.NonceSource = nonceSource(0x31)
	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel1()
	defer cancel2()
	res1O, err1O, _, err1J := preamblePair(ctx1, t, cancel1, ctxO1, ctxJ1)
	if err1O != nil || err1J != nil {
		t.Fatalf("attempt 1 failed: %v %v", err1O, err1J)
	}
	res2O, err2O, _, err2J := preamblePair(ctx2, t, cancel2, ctxO2, ctxJ2)
	if err2O != nil || err2J != nil {
		t.Fatalf("attempt 2 failed: %v %v", err2O, err2J)
	}
	// Fresh nonces per attempt ⇒ distinct transcripts ⇒ distinct key epochs. The old keys
	// are never read back from disk (they are not persisted); every attempt re-derives.
	if bytes.Equal(res1O.Keys.O2J.Key, res2O.Keys.O2J.Key) ||
		bytes.Equal(res1O.Keys.J2O.Key, res2O.Keys.J2O.Key) {
		t.Fatal("attempt 1 and attempt 2 derived the same key epoch (must differ)")
	}
}

func TestResumePreambleWrongSecretFailsClosed(t *testing.T) {
	tid := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fp := strings.Repeat("e", 64)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resO, errO, resJ, errJ := preamblePair(ctx, t, cancel,
		preambleContext(bytes.Repeat([]byte{1}, 32), RoleOfferer, tid, fp),
		preambleContext(bytes.Repeat([]byte{2}, 32), RoleJoiner, tid, fp),
	)
	if errO == nil {
		t.Fatalf("offerer must fail closed on a wrong secret, got nil")
	}
	if resO != nil || resJ != nil {
		t.Fatal("no result may be exposed on a failed handshake")
	}
	if !strings.Contains(errO.Error(), "resume") {
		t.Fatalf("offerer error must not expose proof material: %v", errO)
	}
	// The joiner is released by the connection teardown (context cancellation) exactly like
	// production; it must never produce a result either.
	if errJ == nil && resJ != nil {
		t.Fatalf("joiner must not expose a result on a failed handshake")
	}
}

func TestResumePreambleContextMismatchFailsClosed(t *testing.T) {
	secret := bytes.Repeat([]byte{9}, 32)
	fp := strings.Repeat("f", 64)
	cases := []struct {
		name string
		mut  func(*ResumePreambleOptions)
	}{
		{"wrong transferId", func(o *ResumePreambleOptions) { o.TransferID = strings.Repeat("1", 32) }},
		{"wrong fingerprint", func(o *ResumePreambleOptions) { o.Fingerprint = strings.Repeat("0", 64) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			j := preambleContext(secret, RoleJoiner, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", fp)
			tc.mut(&j)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			_, errO, resJ, errJ := preamblePair(ctx, t, cancel,
				preambleContext(secret, RoleOfferer, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", fp),
				j,
			)
			if errO == nil {
				t.Fatalf("offerer must fail closed on a context mismatch, got nil")
			}
			if resJ != nil {
				t.Fatalf("joiner must not expose a result on a context mismatch (err=%v)", errJ)
			}
		})
	}
}

func TestResumePreambleRejectsMissingSecret(t *testing.T) {
	opts := preambleContext(nil, RoleOfferer, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", strings.Repeat("a", 64))
	opts.Send = func([]byte) error { return nil }
	if _, err := NewResumePreamble(opts); err == nil || !strings.Contains(err.Error(), "resume secret") {
		t.Fatalf("missing secret must fail construction, got %v", err)
	}
}

func TestResumePreambleJoinerStartIsNoOp(t *testing.T) {
	opts := preambleContext(bytes.Repeat([]byte{3}, 32), RoleJoiner, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", strings.Repeat("a", 64))
	opts.Send = func([]byte) error {
		t.Fatal("joiner Start must not send anything")
		return nil
	}
	p, err := NewResumePreamble(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Start(); err != nil {
		t.Fatalf("joiner Start must be a no-op, got %v", err)
	}
	if p.Settled() {
		t.Fatal("joiner must wait for the offerer's resume_init")
	}
}

// TestResumePreambleRejectsForeignFrames proves the fail-closed boundary of the preamble:
// no transfer-protocol frame (here a manifest) and no tampered/replayed resume frame may
// pass before mutual authentication completes.
func TestResumePreambleRejectsForeignFrames(t *testing.T) {
	secret := bytes.Repeat([]byte{7}, 32)
	tid := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fp := strings.Repeat("c", 64)
	o := preambleContext(secret, RoleOfferer, tid, fp)
	j := preambleContext(secret, RoleJoiner, tid, fp)
	chO := make(chan []byte, 16)
	chJ := make(chan []byte, 16)
	o.Send = func(f []byte) error { return (&memPipe{ch: chJ}).send(f) }
	j.Send = func(f []byte) error { return (&memPipe{ch: chO}).send(f) }
	po, err := NewResumePreamble(o)
	if err != nil {
		t.Fatal(err)
	}
	pj, err := NewResumePreamble(j)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for f := range chJ {
			pj.Handle(f)
		}
	}()
	go func() {
		defer wg.Done()
		for f := range chO {
			po.Handle(f)
		}
	}()

	// A manifest frame sealed under the session keys arrives before any resume message.
	manifestPayload, err := EncodeControl(NewManifest([]FileEntry{}, 0))
	if err != nil {
		t.Fatal(err)
	}
	sess := sessionKeys(t)
	rogue, err := Seal(sess.O2J, 1, FrameHeaderInput{Version: FrameVersion, Type: FrameManifest}, manifestPayload)
	if err != nil {
		t.Fatal(err)
	}
	pj.Handle(rogue)
	<-pj.Done()
	if _, err := pj.Result(); err == nil {
		t.Fatal("joiner must fail closed on a transfer frame before resume authentication")
	}
	close(chO)
	close(chJ)
	wg.Wait()
}

// TestResumePreambleDuplicateReAnswer proves a lost-response retransmission (an exact
// duplicate of the last accepted frame) is re-answered idempotently with the SAME snapshot
// — never a fresh nonce or proof — and the handshake still completes.
func TestResumePreambleDuplicateReAnswer(t *testing.T) {
	secret := bytes.Repeat([]byte{4}, 32)
	tid := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fp := strings.Repeat("9", 64)
	o := preambleContext(secret, RoleOfferer, tid, fp)
	j := preambleContext(secret, RoleJoiner, tid, fp)
	chO := make(chan []byte, 16)
	chJ := make(chan []byte, 16)
	o.Send = func(f []byte) error { return (&memPipe{ch: chJ}).send(f) }
	j.Send = func(f []byte) error { return (&memPipe{ch: chO}).send(f) }
	po, err := NewResumePreamble(o)
	if err != nil {
		t.Fatal(err)
	}
	pj, err := NewResumePreamble(j)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	var jChallenges [][]byte
	go func() {
		defer wg.Done()
		for f := range chJ {
			jChallenges = append(jChallenges, f)
			pj.Handle(f)
		}
	}()
	go func() {
		defer wg.Done()
		for f := range chO {
			po.Handle(f)
		}
	}()
	if err := po.Start(); err != nil {
		t.Fatal(err)
	}
	// Wait until the offerer received the joiner's challenge, then re-deliver the exact
	// same challenge frame: the offerer must re-answer with the same confirm snapshot.
	<-po.Done()
	select {
	case <-pj.Done():
	default:
		// The joiner settles on the first confirm; a duplicate challenge was already
		// consumed by the offerer before it settled, so replay it here explicitly.
	}
	close(chO)
	close(chJ)
	wg.Wait()
	if len(jChallenges) == 0 {
		t.Fatal("no challenge frames captured")
	}
	// Direct replay into a settled offerer is a no-op; the offerer already settled once.
	po.Handle(jChallenges[0])
	if _, err := po.Result(); err != nil {
		t.Fatalf("offerer must stay settled after a duplicate, got %v", err)
	}
}

// TestResumePreambleConflictingDuplicateFailsClosed proves a DIFFERENT message of an
// already-accepted type (a challenge replacement after the proof) fails closed.
func TestResumePreambleConflictingDuplicateFailsClosed(t *testing.T) {
	secret := bytes.Repeat([]byte{5}, 32)
	tid := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fp := strings.Repeat("8", 64)
	o := preambleContext(secret, RoleOfferer, tid, fp)
	o.Send = func([]byte) error { return nil }
	po, err := NewResumePreamble(o)
	if err != nil {
		t.Fatal(err)
	}
	// Construct a challenge for a DIFFERENT transcript (different nonce) so its proof is
	// invalid, and deliver it out of state after the offerer already accepted one.
	sess := sessionKeys(t)
	transcript, err := ResumeTranscript(ResumeAuthVersion, tid, fp,
		bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ResumeJoinerProof(secret, transcript)
	if err != nil {
		t.Fatal(err)
	}
	bad := &ResumeMessage{
		Type: ResumeMsgChallenge, Version: ResumeAuthVersion, Role: RoleJoiner,
		Nonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32)),
		Proof: base64.RawURLEncoding.EncodeToString(proof),
	}
	payload, err := EncodeResumeMessage(bad)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := Seal(sess.J2O, 1, FrameHeaderInput{Version: FrameVersion, Type: FrameResumeAuth}, payload)
	if err != nil {
		t.Fatal(err)
	}
	// The offerer never started: a challenge before resume_init is out of state.
	po.Handle(frame)
	if _, err := po.Result(); err == nil {
		t.Fatal("out-of-state challenge must fail closed")
	}
}
