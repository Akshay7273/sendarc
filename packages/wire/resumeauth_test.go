package wire

import (
	"bytes"
	"strings"
	"testing"
)

// Fixed public KAT inputs, matching docs/test-vectors/resume-auth.json (never real
// credentials).
var (
	resumeTestMaster = bytesRange(0x00, 0x20)
	resumeTestSecret = func() []byte {
		root, err := ResumeRoot(resumeTestMaster)
		if err != nil {
			panic(err)
		}
		secret, err := ResumeSecret(root, ResumeAuthVersion, resumeVectorTransfer, resumeVectorFinger)
		if err != nil {
			panic(err)
		}
		return secret
	}()
)

// resumeTestContext builds a deterministic session context for one role.
func resumeTestContext(role Role, over func(*ResumeAuthContext)) ResumeAuthContext {
	ctx := ResumeAuthContext{
		Version:             ResumeAuthVersion,
		TransferID:          resumeVectorTransfer,
		ManifestFingerprint: resumeVectorFinger,
		Role:                role,
		ResumeSecret:        resumeTestSecret,
	}
	if role == RoleOfferer {
		ctx.NonceSource = fixedNonce(resumeVectorOfferer)
	} else {
		ctx.NonceSource = fixedNonce(resumeVectorJoiner)
	}
	if over != nil {
		over(&ctx)
	}
	return ctx
}

func fixedNonce(nonce []byte) func(int) ([]byte, error) {
	return func(n int) ([]byte, error) {
		if n != len(nonce) {
			return nil, Errorf(CodeAuth, "nonce source returned %d bytes, want %d", len(nonce), n)
		}
		return append([]byte(nil), nonce...), nil
	}
}

func encodeMsg(t *testing.T, m *ResumeMessage) []byte {
	t.Helper()
	encoded, err := EncodeResumeMessage(m)
	if err != nil {
		t.Fatalf("encode message: %v", err)
	}
	return encoded
}

// runResumeHandshake drives a full exchange between offerer and joiner sessions; both
// sessions must settle with results (fresh keys).
func runResumeHandshake(t *testing.T, offererCtx, joinerCtx ResumeAuthContext) (*ResumeAuthResult, *ResumeAuthResult) {
	t.Helper()
	offerer, err := NewResumeAuthSession(offererCtx)
	if err != nil {
		t.Fatalf("offerer session: %v", err)
	}
	joiner, err := NewResumeAuthSession(joinerCtx)
	if err != nil {
		t.Fatalf("joiner session: %v", err)
	}
	init, err := offerer.Start()
	if err != nil {
		t.Fatalf("offerer start: %v", err)
	}
	challenge, _, err := joiner.Handle(encodeMsg(t, init))
	if err != nil {
		t.Fatalf("joiner handle init: %v", err)
	}
	confirm, _, err := offerer.Handle(encodeMsg(t, challenge))
	if err != nil {
		t.Fatalf("offerer handle challenge: %v", err)
	}
	ready, joinerResult, err := joiner.Handle(encodeMsg(t, confirm))
	if err != nil {
		t.Fatalf("joiner handle confirm: %v", err)
	}
	_, offererResult, err := offerer.Handle(encodeMsg(t, ready))
	if err != nil {
		t.Fatalf("offerer handle ready: %v", err)
	}
	if offererResult == nil || joinerResult == nil {
		t.Fatal("handshake completed without results")
	}
	return offererResult, joinerResult
}

func TestResumeSecretDerivation(t *testing.T) {
	root, err := ResumeRoot(resumeTestMaster)
	if err != nil {
		t.Fatalf("ResumeRoot: %v", err)
	}
	secret, err := ResumeSecret(root, ResumeAuthVersion, resumeVectorTransfer, resumeVectorFinger)
	if err != nil {
		t.Fatalf("ResumeSecret: %v", err)
	}
	// Different transferId / fingerprint → different secret.
	other, err := ResumeSecret(root, ResumeAuthVersion, strings.Repeat("aa", 16), resumeVectorFinger)
	if err != nil {
		t.Fatalf("ResumeSecret other transfer: %v", err)
	}
	if bytes.Equal(secret, other) {
		t.Fatal("different transferId must yield a different resume secret")
	}
	other2, err := ResumeSecret(root, ResumeAuthVersion, resumeVectorTransfer, strings.Repeat("ff", 32))
	if err != nil {
		t.Fatalf("ResumeSecret other fingerprint: %v", err)
	}
	if bytes.Equal(secret, other2) {
		t.Fatal("different manifest fingerprint must yield a different resume secret")
	}
	// Malformed context rejected before any derivation.
	for _, bad := range []struct {
		name string
		fn   func() error
	}{
		{"empty master", func() error { _, err := ResumeRoot(nil); return err }},
		{"bad transferId", func() error { _, err := ResumeSecret(root, ResumeAuthVersion, "xyz", resumeVectorFinger); return err }},
		{"bad fingerprint", func() error { _, err := ResumeSecret(root, ResumeAuthVersion, resumeVectorTransfer, "xyz"); return err }},
		{"bad version", func() error { _, err := ResumeSecret(root, 2, resumeVectorTransfer, resumeVectorFinger); return err }},
	} {
		if err := bad.fn(); err == nil {
			t.Fatalf("%s must be rejected", bad.name)
		}
	}
	// The secret is 32 bytes and the envelope round-trips.
	if len(secret) != resumeSecretBytes {
		t.Fatalf("secret length %d", len(secret))
	}
	env, err := EncodeResumeSecretEnvelope(secret)
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	if env.Version != ResumeAuthVersion || len(env.Value) != 64 {
		t.Fatalf("bad envelope: %+v", env)
	}
	decoded, err := DecodeResumeSecretEnvelope(env)
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if !bytes.Equal(decoded, secret) {
		t.Fatal("envelope round-trip changed the secret")
	}
	for _, bad := range []*ResumeSecretEnvelope{
		{Version: 2, Value: env.Value},
		{Version: 1, Value: "00"},
		{Version: 1, Value: strings.Repeat("ab", 33)},
		{Version: 1, Value: strings.ToUpper(env.Value)},
		{Version: 1, Value: "not hex!!"},
		{Version: 1, Value: ""},
		nil,
	} {
		if _, err := DecodeResumeSecretEnvelope(bad); err == nil {
			t.Fatalf("malformed envelope %+v must be rejected", bad)
		}
	}
}

func TestResumeMessageCodecStrict(t *testing.T) {
	nonce32 := strings.Repeat("A", 43) // canonical base64url of 32 zero bytes
	valid := []*ResumeMessage{
		{Type: ResumeMsgInit, Version: 1, Role: RoleOfferer, Nonce: nonce32},
		{Type: ResumeMsgChallenge, Version: 1, Role: RoleJoiner, Nonce: nonce32, Proof: nonce32},
		{Type: ResumeMsgConfirm, Version: 1, Role: RoleOfferer, Proof: nonce32},
		{Type: ResumeMsgReady, Version: 1, Role: RoleJoiner, Proof: nonce32},
	}
	for _, msg := range valid {
		decoded, err := DecodeResumeMessage(encodeMsg(t, msg))
		if err != nil {
			t.Fatalf("round-trip %s: %v", msg.Type, err)
		}
		if decoded.Type != msg.Type || decoded.Version != msg.Version || decoded.Role != msg.Role ||
			decoded.Nonce != msg.Nonce || decoded.Proof != msg.Proof {
			t.Fatalf("round-trip lost fields: %+v", decoded)
		}
	}
	bad := []*ResumeMessage{
		{Type: ResumeMsgInit, Version: 2, Role: RoleOfferer, Nonce: nonce32},
		{Type: ResumeMsgInit, Version: 1, Role: RoleJoiner, Nonce: nonce32},
		{Type: ResumeMsgInit, Version: 1, Role: RoleOfferer, Nonce: "AA"},          // 1 byte
		{Type: ResumeMsgInit, Version: 1, Role: RoleOfferer, Nonce: nonce32 + "A"}, // 33 bytes
		{Type: ResumeMsgInit, Version: 1, Role: RoleOfferer},                       // missing nonce
		{Type: ResumeMsgInit, Version: 1, Role: RoleOfferer, Nonce: nonce32, Proof: nonce32},
		{Type: ResumeMsgChallenge, Version: 1, Role: RoleJoiner, Nonce: nonce32, Proof: "AA"},
		{Type: ResumeMsgConfirm, Version: 1, Role: RoleOfferer, Nonce: nonce32, Proof: nonce32},
		{Type: ResumeMsgReady, Version: 1, Role: RoleOfferer, Proof: nonce32},
		{Type: ResumeMsgType("resume_unknown"), Version: 1, Role: RoleOfferer},
		{Type: ResumeMsgInit, Version: 1, Role: RoleOfferer, Nonce: nonce32 + "="}, // non-canonical
	}
	for _, msg := range bad {
		if err := validateResumeMessage(msg); err == nil {
			t.Fatalf("invalid message %+v must be rejected", msg)
		}
	}
	// Unknown fields and trailing data fail closed on decode.
	payload := append(encodeMsg(t, valid[0]), []byte(`{"extra":1}`)...)
	if _, err := DecodeResumeMessage(payload); err == nil {
		t.Fatal("trailing data must be rejected")
	}
	tampered := strings.Replace(string(encodeMsg(t, valid[0])), `"nonce"`, `"extra"`, 1)
	if _, err := DecodeResumeMessage([]byte(tampered)); err == nil {
		t.Fatal("unknown field must be rejected")
	}
}

func TestResumeHandshakeHappyPath(t *testing.T) {
	offererResult, joinerResult := runResumeHandshake(t,
		resumeTestContext(RoleOfferer, nil), resumeTestContext(RoleJoiner, nil))
	// Both sides derive identical fresh directional keys with fresh-session counters.
	if !bytes.Equal(offererResult.Keys.O2J.Key, joinerResult.Keys.O2J.Key) ||
		!bytes.Equal(offererResult.Keys.O2J.Salt, joinerResult.Keys.O2J.Salt) ||
		!bytes.Equal(offererResult.Keys.J2O.Key, joinerResult.Keys.J2O.Key) ||
		!bytes.Equal(offererResult.Keys.J2O.Salt, joinerResult.Keys.J2O.Salt) {
		t.Fatalf("keys diverged: %+v vs %+v", offererResult.Keys, joinerResult.Keys)
	}
	if offererResult.SendCounter != 0 || offererResult.RecvCounter != 0 {
		t.Fatalf("fresh counters must start at 0, got %d/%d", offererResult.SendCounter, offererResult.RecvCounter)
	}
	if offererResult.TransferID != resumeVectorTransfer {
		t.Fatalf("transferId lost: %s", offererResult.TransferID)
	}
}

func TestResumeHandshakeFreshKeysEveryAttempt(t *testing.T) {
	// Attempt A (vector nonces) vs attempt B (different nonces): different traffic keys.
	a, _ := runResumeHandshake(t, resumeTestContext(RoleOfferer, nil), resumeTestContext(RoleJoiner, nil))
	b, _ := runResumeHandshake(t,
		resumeTestContext(RoleOfferer, func(ctx *ResumeAuthContext) { ctx.NonceSource = fixedNonce(bytesRange(0x80, 0xa0)) }),
		resumeTestContext(RoleJoiner, func(ctx *ResumeAuthContext) { ctx.NonceSource = fixedNonce(bytesRange(0xa0, 0xc0)) }),
	)
	if bytes.Equal(a.Keys.O2J.Key, b.Keys.O2J.Key) || bytes.Equal(a.Keys.O2J.Salt, b.Keys.O2J.Salt) ||
		bytes.Equal(a.Keys.J2O.Key, b.Keys.J2O.Key) {
		t.Fatal("fresh nonces must produce different traffic keys")
	}
	// The resumed keys differ from the original session keys and between directions.
	original, err := DeriveTransferKeys(resumeTestMaster)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.Keys.O2J.Key, original.O2J.Key) || bytes.Equal(a.Keys.J2O.Key, original.J2O.Key) {
		t.Fatal("resumed keys must differ from the original session keys")
	}
	if bytes.Equal(a.Keys.O2J.Key, a.Keys.J2O.Key) || bytes.Equal(a.Keys.O2J.Salt, a.Keys.J2O.Salt) {
		t.Fatal("directional keys must differ")
	}
}

func TestResumeHandshakeFailsClosed(t *testing.T) {
	// Wrong secret.
	_, _, err := runHandshakeErr(t,
		resumeTestContext(RoleOfferer, nil),
		resumeTestContext(RoleJoiner, func(ctx *ResumeAuthContext) { ctx.ResumeSecret = bytesRange(0x80, 0xa0) }))
	if err == nil || !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("wrong secret must fail verification, got %v", err)
	}
	// Wrong transferId / fingerprint.
	expectHandshakeFail(t,
		resumeTestContext(RoleOfferer, nil),
		resumeTestContext(RoleJoiner, func(ctx *ResumeAuthContext) { ctx.TransferID = strings.Repeat("aa", 16) }))
	expectHandshakeFail(t,
		resumeTestContext(RoleOfferer, nil),
		resumeTestContext(RoleJoiner, func(ctx *ResumeAuthContext) { ctx.ManifestFingerprint = strings.Repeat("ff", 32) }))
	// Wrong version is rejected up front.
	if _, err := NewResumeAuthSession(resumeTestContext(RoleOfferer, func(ctx *ResumeAuthContext) { ctx.Version = 2 })); err == nil {
		t.Fatal("wrong version must be rejected")
	}
	// Missing secret / malformed context rejected up front.
	if _, err := NewResumeAuthSession(resumeTestContext(RoleOfferer, func(ctx *ResumeAuthContext) { ctx.ResumeSecret = nil })); err == nil {
		t.Fatal("missing secret must be rejected")
	}
	if _, err := NewResumeAuthSession(resumeTestContext(RoleOfferer, func(ctx *ResumeAuthContext) { ctx.TransferID = "bad" })); err == nil {
		t.Fatal("malformed transferId must be rejected")
	}
}

func runHandshakeErr(t *testing.T, offererCtx, joinerCtx ResumeAuthContext) (*ResumeAuthResult, *ResumeAuthResult, error) {
	t.Helper()
	offerer, err := NewResumeAuthSession(offererCtx)
	if err != nil {
		return nil, nil, err
	}
	joiner, err := NewResumeAuthSession(joinerCtx)
	if err != nil {
		return nil, nil, err
	}
	init, err := offerer.Start()
	if err != nil {
		return nil, nil, err
	}
	challenge, _, err := joiner.Handle(encodeMsg(t, init))
	if err != nil {
		return nil, nil, err
	}
	confirm, _, err := offerer.Handle(encodeMsg(t, challenge))
	if err != nil {
		return nil, nil, err
	}
	ready, joinerResult, err := joiner.Handle(encodeMsg(t, confirm))
	if err != nil {
		return nil, nil, err
	}
	_, offererResult, err := offerer.Handle(encodeMsg(t, ready))
	return offererResult, joinerResult, err
}

func expectHandshakeFail(t *testing.T, offererCtx, joinerCtx ResumeAuthContext) error {
	t.Helper()
	_, _, err := runHandshakeErr(t, offererCtx, joinerCtx)
	if err == nil {
		t.Fatal("handshake must fail closed")
	}
	return err
}

func TestResumeHandshakeIdempotentDuplicates(t *testing.T) {
	offerer, err := NewResumeAuthSession(resumeTestContext(RoleOfferer, nil))
	if err != nil {
		t.Fatal(err)
	}
	joiner, err := NewResumeAuthSession(resumeTestContext(RoleJoiner, nil))
	if err != nil {
		t.Fatal(err)
	}
	init, err := offerer.Start()
	if err != nil {
		t.Fatal(err)
	}
	initBytes := encodeMsg(t, init)

	first, _, err := joiner.Handle(initBytes)
	if err != nil {
		t.Fatal(err)
	}
	dup, _, err := joiner.Handle(initBytes)
	if err != nil {
		t.Fatal(err)
	}
	// The duplicate is re-answered with the SAME challenge bytes (same nonce + proof).
	if !bytes.Equal(encodeMsg(t, dup), encodeMsg(t, first)) {
		t.Fatal("duplicate init must be re-answered with the identical challenge")
	}

	confirm, _, err := offerer.Handle(encodeMsg(t, first))
	if err != nil {
		t.Fatal(err)
	}
	confirmBytes := encodeMsg(t, confirm)
	confirmAgain, _, err := offerer.Handle(encodeMsg(t, first))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encodeMsg(t, confirmAgain), confirmBytes) {
		t.Fatal("duplicate challenge must be re-answered with the identical confirm")
	}

	ready, _, err := joiner.Handle(confirmBytes)
	if err != nil {
		t.Fatal(err)
	}
	readyAgain, _, err := joiner.Handle(confirmBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encodeMsg(t, readyAgain), encodeMsg(t, ready)) {
		t.Fatal("duplicate confirm must be re-answered with the identical ready")
	}

	// Conflicting duplicates fail closed.
	otherOfferer, err := NewResumeAuthSession(resumeTestContext(RoleOfferer,
		func(ctx *ResumeAuthContext) { ctx.NonceSource = fixedNonce(bytesRange(0x70, 0x90)) }))
	if err != nil {
		t.Fatal(err)
	}
	otherInit, err := otherOfferer.Start()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := joiner.Handle(encodeMsg(t, otherInit)); err == nil {
		t.Fatal("conflicting duplicate init must fail closed")
	}
}

func TestResumeHandshakeReplayAndReflection(t *testing.T) {
	// A recorded message cannot replay into a fresh attempt: fresh nonces change the
	// transcript, so the recorded proofs fail.
	freshOfferer, err := NewResumeAuthSession(resumeTestContext(RoleOfferer,
		func(ctx *ResumeAuthContext) { ctx.NonceSource = fixedNonce(bytesRange(0x60, 0x80)) }))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := freshOfferer.Start(); err != nil {
		t.Fatal(err)
	}
	recordedChallenge := &ResumeMessage{
		Type: ResumeMsgChallenge, Version: 1, Role: RoleJoiner,
		Nonce: b64enc(resumeVectorJoiner), Proof: b64enc(bytesRange(0x10, 0x30)), // recorded proof, wrong transcript
	}
	if _, _, err := freshOfferer.Handle(encodeMsg(t, recordedChallenge)); err == nil ||
		!strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("recorded challenge into a fresh offerer must fail, got %v", err)
	}

	// Reflection: the offerer proof (over the SAME transcript) fed back as the joiner
	// proof fails, and the ready proof is not interchangeable with the joiner proof.
	transcript, err := ResumeTranscript(ResumeAuthVersion, resumeVectorTransfer, resumeVectorFinger,
		resumeVectorOfferer, resumeVectorJoiner)
	if err != nil {
		t.Fatal(err)
	}
	offererProof, err := ResumeOffererProof(resumeTestSecret, transcript)
	if err != nil {
		t.Fatal(err)
	}
	joinerProof, err := ResumeJoinerProof(resumeTestSecret, transcript)
	if err != nil {
		t.Fatal(err)
	}
	readyProof, err := ResumeReadyProof(resumeTestSecret, transcript)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(offererProof, joinerProof) || bytes.Equal(offererProof, readyProof) ||
		bytes.Equal(joinerProof, readyProof) {
		t.Fatal("the three proofs must be pairwise distinct")
	}
	if verifyResumeProof(offererProof, resumeTestSecret, transcript, resumeProofTagJoiner, infoResumeProofJoiner) {
		t.Fatal("offerer proof must not verify as a joiner proof (role reflection)")
	}
	if verifyResumeProof(readyProof, resumeTestSecret, transcript, resumeProofTagJoiner, infoResumeProofJoiner) {
		t.Fatal("ready proof must not verify as the challenge joiner proof")
	}

	// Swapped original roles: a peer constructed for the joiner role cannot initiate.
	joinerSession, err := NewResumeAuthSession(resumeTestContext(RoleJoiner, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := joinerSession.Start(); err == nil {
		t.Fatal("joiner cannot start the handshake")
	}
}

func TestResumeHandshakeServerForgery(t *testing.T) {
	transcript, err := ResumeTranscript(ResumeAuthVersion, resumeVectorTransfer, resumeVectorFinger,
		resumeVectorOfferer, resumeVectorJoiner)
	if err != nil {
		t.Fatal(err)
	}
	recordedJoinerProof, err := ResumeJoinerProof(resumeTestSecret, transcript)
	if err != nil {
		t.Fatal(err)
	}
	recordedOffererProof, err := ResumeOffererProof(resumeTestSecret, transcript)
	if err != nil {
		t.Fatal(err)
	}

	// (a) Replay the recorded challenge into a fresh offerer: fails (transcript differs).
	freshOfferer, err := NewResumeAuthSession(resumeTestContext(RoleOfferer,
		func(ctx *ResumeAuthContext) { ctx.NonceSource = fixedNonce(bytesRange(0x60, 0x80)) }))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := freshOfferer.Start(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := freshOfferer.Handle(encodeMsg(t, &ResumeMessage{
		Type: ResumeMsgChallenge, Version: 1, Role: RoleJoiner,
		Nonce: b64enc(resumeVectorJoiner), Proof: b64enc(recordedJoinerProof),
	})); err == nil {
		t.Fatal("recorded challenge must fail on a fresh offerer")
	}

	// (b) Fake offerer without the secret: its init reaches a real joiner, but the server
	// mutates the real joiner's valid challenge and the real offerer refuses; the fake
	// offerer cannot even verify the real joiner's challenge.
	fakeOfferer, err := NewResumeAuthSession(resumeTestContext(RoleOfferer,
		func(ctx *ResumeAuthContext) {
			ctx.ResumeSecret = bytesRange(0x80, 0xa0)
			ctx.NonceSource = fixedNonce(bytesRange(0x70, 0x90))
		}))
	if err != nil {
		t.Fatal(err)
	}
	fakeInit, err := fakeOfferer.Start()
	if err != nil {
		t.Fatal(err)
	}
	realJoiner, err := NewResumeAuthSession(resumeTestContext(RoleJoiner, nil))
	if err != nil {
		t.Fatal(err)
	}
	realChallenge, _, err := realJoiner.Handle(encodeMsg(t, fakeInit))
	if err != nil {
		t.Fatal(err)
	}
	mutated := *realChallenge
	mutated.Proof = b64enc(bytesRange(0x10, 0x30))
	realOfferer, err := NewResumeAuthSession(resumeTestContext(RoleOfferer,
		func(ctx *ResumeAuthContext) { ctx.NonceSource = fixedNonce(bytesRange(0x70, 0x90)) }))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := realOfferer.Start(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := realOfferer.Handle(encodeMsg(t, &mutated)); err == nil {
		t.Fatal("mutated challenge must fail")
	}
	if _, _, err := fakeOfferer.Handle(encodeMsg(t, realChallenge)); err == nil {
		t.Fatal("a fake offerer without the secret must fail to authenticate")
	}

	// (c) Fake joiner side: the recorded offerer proof (over the old transcript) replayed
	// as a confirm for a real joiner whose transcript differs — fails.
	freshJoiner, err := NewResumeAuthSession(resumeTestContext(RoleJoiner,
		func(ctx *ResumeAuthContext) { ctx.NonceSource = fixedNonce(bytesRange(0xb0, 0xd0)) }))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := freshJoiner.Handle(encodeMsg(t, &ResumeMessage{
		Type: ResumeMsgInit, Version: 1, Role: RoleOfferer, Nonce: b64enc(bytesRange(0xa0, 0xc0)),
	})); err != nil {
		t.Fatal(err)
	}
	if _, _, err := freshJoiner.Handle(encodeMsg(t, &ResumeMessage{
		Type: ResumeMsgConfirm, Version: 1, Role: RoleOfferer, Proof: b64enc(recordedOffererProof),
	})); err == nil {
		t.Fatal("recorded offerer proof must fail on a fresh joiner")
	}

	// (d) Reordering fails closed: a confirm before any init is impossible.
	reorderOfferer, err := NewResumeAuthSession(resumeTestContext(RoleOfferer, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := reorderOfferer.Handle(encodeMsg(t, &ResumeMessage{
		Type: ResumeMsgConfirm, Version: 1, Role: RoleOfferer, Proof: b64enc(recordedOffererProof),
	})); err == nil {
		t.Fatal("confirm before init must fail")
	}
}

func TestResumeHandshakeKeyExposureTiming(t *testing.T) {
	// A failed attempt never exposes keys: the wrong-secret path settles failed and the
	// session returns no result on any subsequent handle.
	offerer, err := NewResumeAuthSession(resumeTestContext(RoleOfferer, nil))
	if err != nil {
		t.Fatal(err)
	}
	joiner, err := NewResumeAuthSession(resumeTestContext(RoleJoiner,
		func(ctx *ResumeAuthContext) { ctx.ResumeSecret = bytesRange(0x80, 0xa0) }))
	if err != nil {
		t.Fatal(err)
	}
	init, err := offerer.Start()
	if err != nil {
		t.Fatal(err)
	}
	challenge, _, err := joiner.Handle(encodeMsg(t, init))
	if err != nil {
		t.Fatal(err)
	}
	if _, result, err := offerer.Handle(encodeMsg(t, challenge)); err == nil || result != nil {
		t.Fatalf("failed offerer must return no result (result=%v err=%v)", result, err)
	}
	// A settled-failed session rejects further input.
	if _, _, err := offerer.Handle(encodeMsg(t, challenge)); err == nil {
		t.Fatal("settled-failed session must reject further messages")
	}
}

func TestResumeAuthNegotiation(t *testing.T) {
	if !NegotiateResumeAuth([]string{ResumeAuthCapability}, []string{ResumeAuthCapability}) {
		t.Fatal("both peers advertising the capability must negotiate")
	}
	if NegotiateResumeAuth([]string{ResumeAuthCapability}, []string{"folders"}) {
		t.Fatal("a peer without the capability must not negotiate")
	}
	if NegotiateResumeAuth([]string{"folders"}, []string{ResumeAuthCapability}) {
		t.Fatal("a peer without the capability must not negotiate")
	}
	if NegotiateResumeAuth(nil, nil) {
		t.Fatal("no capabilities must not negotiate")
	}
}
