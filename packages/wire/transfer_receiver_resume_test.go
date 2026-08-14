package wire

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// resumeManifest builds the manifest the senderFrames will stream, with the canonical
// fingerprint the seed must bind to (V13-PR06).
func resumeManifest(t *testing.T, id string, data []byte, blockSize int) (Manifest, string) {
	t.Helper()
	sum := sha256.Sum256(data)
	blocks := 0
	if len(data) > 0 {
		blocks = (len(data)-1)/blockSize + 1
	}
	raw := NewManifest([]FileEntry{{
		Idx: 0, Name: "f", Size: int64(len(data)), Mime: "application/octet-stream",
		LastModified: 1, BlockSize: blockSize, Blocks: blocks, FileDigest: hex.EncodeToString(sum[:]),
	}}, int64(len(data)))
	raw.TransferID = id
	validated, err := ValidateManifest(*raw)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := ManifestFingerprint(validated)
	if err != nil {
		t.Fatal(err)
	}
	return validated, fp
}

// mustDigest feeds the given prefix into a fresh digest, mirroring a persisted high-water mark.
func mustDigest(t *testing.T, prefix []byte) Digest {
	t.Helper()
	d := NewSHA256Digest()
	d.Update(prefix)
	return d
}

// runReceiverWithSeed drives a receiver whose seed is the given claim and returns the Wait
// outcome plus the decoded back-channel frames.
func runReceiverWithSeed(t *testing.T, manifest Manifest, seed *ReceiverResume) (ReceiveResult, error, []ControlMsg) {
	t.Helper()
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	sf := newSenderFrames(t, keys)
	sf.ctrl(&manifest)
	if manifest.Files[0].Blocks > 0 {
		// Stream the whole file so a fresh receive completes; a resumed one ignores the held prefix.
		data := make([]byte, manifest.Files[0].Size)
		sf.blockData(data, manifest.Files[0].BlockSize, manifest.Files[0].BlockSize)
		sf.ctrl(NewComplete(CompletionDigest(manifest.Files)))
	}
	sink := &MemorySink{}
	var back outbox
	opts := ReceiverOptions{
		Send: back.push, SendDir: keys.J2O, RecvDir: keys.O2J, Sink: sink,
	}
	if seed != nil {
		opts.Resume = seed
	}
	r := NewReceiver(opts)
	for _, f := range sf.frames {
		r.Handle(f)
	}
	res, waitErr := r.Wait(context.Background())

	var msgs []ControlMsg
	for i, f := range back.snapshot() {
		o, err := Open(keys.J2O, uint64(i), f)
		if err != nil {
			t.Fatalf("open back frame %d: %v", i, err)
		}
		m, err := DecodeControl(o.Plaintext)
		if err != nil {
			t.Fatalf("decode back frame %d: %v", i, err)
		}
		msgs = append(msgs, m)
	}
	return res, waitErr, msgs
}

// TestReceiverRejectsBadResumeSeeds: a host-provided seed is a claim, not a trust anchor.
// Every impossible claim fails the receive closed before any of it is advertised.
func TestReceiverRejectsBadResumeSeeds(t *testing.T) {
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	_ = keys
	data := make([]byte, 20)
	manifest, fp := resumeManifest(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", data, 8)

	seed := func(mutate func(*ReceiverResume)) *ReceiverResume {
		s := &ReceiverResume{
			TransferID:          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			ManifestFingerprint: fp,
			Files:               map[int]ResumeFileProgress{0: {HaveBlocks: 0}},
		}
		mutate(s)
		return s
	}

	cases := []struct {
		name string
		rs   *ReceiverResume
		want string
	}{
		{"uppercase fingerprint", seed(func(s *ReceiverResume) { s.ManifestFingerprint = strings.ToUpper(s.ManifestFingerprint) }), "resume seed manifestFingerprint must be 64 lowercase hex characters"},
		{"short fingerprint", seed(func(s *ReceiverResume) { s.ManifestFingerprint = fp[:10] }), "resume seed manifestFingerprint must be 64 lowercase hex characters"},
		{"wrong manifest fingerprint", seed(func(s *ReceiverResume) { s.ManifestFingerprint = strings.Repeat("0", 64) }), "resume seed manifest fingerprint does not match the authenticated manifest"},
		{"empty file set", seed(func(s *ReceiverResume) { s.Files = map[int]ResumeFileProgress{} }), "resume seed covers 0 files, manifest has 1"},
		{"missing file entry", seed(func(s *ReceiverResume) { s.Files = map[int]ResumeFileProgress{} }), "resume seed covers 0 files, manifest has 1"},
		{"haveBlocks above blocks", seed(func(s *ReceiverResume) { s.Files = map[int]ResumeFileProgress{0: {HaveBlocks: 4}} }), "resume seed haveBlocks 4 out of range for file 0 (blocks 3)"},
		{"haveBlocks negative", seed(func(s *ReceiverResume) { s.Files = map[int]ResumeFileProgress{0: {HaveBlocks: -1}} }), "resume seed haveBlocks -1 out of range for file 0 (blocks 3)"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			_, err, msgs := runReceiverWithSeed(t, manifest, c.rs)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Wait error = %v, want one mentioning %q", err, c.want)
			}
			// The failure must be a sink_error fail frame; no resume_state may ever be advertised.
			if len(msgs) != 1 || msgs[0].FrameType() != FrameFail {
				t.Fatalf("back-channel = %#v, want a single fail frame", msgs)
			}
		})
	}
}

// TestReceiverAdvertisesFingerprintBoundResumeState: a valid seed is advertised only bound to
// the authenticated manifest's canonical fingerprint, and only the missing suffix is streamed.
func TestReceiverAdvertisesFingerprintBoundResumeState(t *testing.T) {
	data := make([]byte, 20)
	manifest, fp := resumeManifest(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", data, 8)

	prefix := 2 * 8
	seedDigest := NewSHA256Digest()
	seedDigest.Update(data[:prefix])
	seed := &ReceiverResume{
		TransferID:          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ManifestFingerprint: fp,
		Files:               map[int]ResumeFileProgress{0: {HaveBlocks: 2, SeedDigest: seedDigest}},
	}
	_, err, msgs := runReceiverWithSeed(t, manifest, seed)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	// resume_state, then an ack for every block the test streamed (the held 0-1 are acked
	// from the resumed high-water mark; block 2 is verified normally), then done.
	if len(msgs) != 5 {
		t.Fatalf("back-channel has %d frames, want 5 (resume_state, ack ×3, done)", len(msgs))
	}
	rs, ok := msgs[0].(*ResumeState)
	if !ok {
		t.Fatalf("first back frame = %T, want resume_state", msgs[0])
	}
	if rs.ManifestFingerprint != fp {
		t.Fatalf("advertised fingerprint = %q, want %q", rs.ManifestFingerprint, fp)
	}
	if len(rs.Files) != 1 || rs.Files[0].HaveBlocks != 2 {
		t.Fatalf("advertised resume_state = %#v, want haveBlocks 2", rs)
	}
	for i := 1; i <= 3; i++ {
		ack, ok := msgs[i].(*Ack)
		if !ok || ack.BlockIdx != i-1 {
			t.Fatalf("back frame %d = %#v, want ack for block %d", i, msgs[i], i-1)
		}
	}
	if msgs[4].FrameType() != FrameDone {
		t.Fatalf("last back frame = %T, want done", msgs[4])
	}
}

// TestReceiverIgnoresSeedForDifferentTransfer: a seed bound to another transfer is a different
// receive; the receiver starts fresh and advertises an all-zero resume_state for this one.
func TestReceiverIgnoresSeedForDifferentTransfer(t *testing.T) {
	data := make([]byte, 20)
	manifest, _ := resumeManifest(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", data, 8)
	staleSeed := NewSHA256Digest()
	staleSeed.Update(make([]byte, 8))
	seed := &ReceiverResume{
		TransferID:          "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ManifestFingerprint: strings.Repeat("0", 64),
		Files:               map[int]ResumeFileProgress{0: {HaveBlocks: 2, SeedDigest: staleSeed}},
	}
	_, err, msgs := runReceiverWithSeed(t, manifest, seed)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	rs, ok := msgs[0].(*ResumeState)
	if !ok {
		t.Fatalf("first back frame = %T, want resume_state", msgs[0])
	}
	if len(rs.Files) != 1 || rs.Files[0].HaveBlocks != 0 {
		t.Fatalf("advertised resume_state = %#v, want an all-zero high-water mark", rs)
	}
}

// TestReceiverReanswersIdenticalResumeStateOnDuplicateManifest: a cutover can deliver the
// manifest twice; the identical duplicate is re-answered with the exact same resume_state
// (never a re-validated one), while a different manifest is a protocol violation.
func TestReceiverReanswersIdenticalResumeStateOnDuplicateManifest(t *testing.T) {
	data := make([]byte, 20)
	manifest, fp := resumeManifest(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", data, 8)
	seed := &ReceiverResume{
		TransferID:          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ManifestFingerprint: fp,
		Files: map[int]ResumeFileProgress{
			0: {HaveBlocks: 1, SeedDigest: mustDigest(t, data[:8])},
		},
	}
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	sf := newSenderFrames(t, keys)
	sf.ctrl(&manifest)
	sf.ctrl(&manifest)
	sf.blockData(data, 8, 8)
	sf.ctrl(NewComplete(CompletionDigest(manifest.Files)))

	sink := &MemorySink{}
	var back outbox
	r := NewReceiver(ReceiverOptions{
		Send: back.push, SendDir: keys.J2O, RecvDir: keys.O2J, Sink: sink, Resume: seed,
	})
	for _, f := range sf.frames {
		r.Handle(f)
	}
	if _, err := r.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	var msgs []ControlMsg
	for i, f := range back.snapshot() {
		o, err := Open(keys.J2O, uint64(i), f)
		if err != nil {
			t.Fatalf("open back frame %d: %v", i, err)
		}
		m, err := DecodeControl(o.Plaintext)
		if err != nil {
			t.Fatalf("decode back frame %d: %v", i, err)
		}
		msgs = append(msgs, m)
	}
	if len(msgs) != 6 {
		t.Fatalf("back-channel has %d frames, want 6 (resume_state ×2, ack ×3, done)", len(msgs))
	}
	first, ok1 := msgs[0].(*ResumeState)
	second, ok2 := msgs[1].(*ResumeState)
	if !ok1 || !ok2 || !resumeStatesEqual(first, second) {
		t.Fatalf("duplicate manifest answers = %#v / %#v, want identical resume_state messages", msgs[0], msgs[1])
	}
	if msgs[5].FrameType() != FrameDone {
		t.Fatalf("last back frame = %T, want done", msgs[5])
	}

	// A *different* manifest arriving after the first was applied is a violation: the seed
	// already validated against the first manifest, and the second is not that transfer.
	other, _ := resumeManifest(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", make([]byte, 40), 8)
	sf2 := newSenderFrames(t, keys)
	sf2.ctrl(&manifest)
	sf2.ctrl(&other)
	sink2 := &MemorySink{}
	var back2 outbox
	r2 := NewReceiver(ReceiverOptions{
		Send: back2.push, SendDir: keys.J2O, RecvDir: keys.O2J, Sink: sink2, Resume: seed,
	})
	for _, f := range sf2.frames {
		r2.Handle(f)
	}
	_, err = r2.Wait(context.Background())
	if err == nil || !strings.Contains(err.Error(), "duplicate manifest") {
		t.Fatalf("Wait error = %v, want duplicate manifest", err)
	}
}

// TestReceiverAllCompleteSeedSettles: a seed whose high-water mark already covers the whole
// file needs no data; the receiver advertises it and settles on the terminal Complete.
func TestReceiverAllCompleteSeedSettles(t *testing.T) {
	data := make([]byte, 20)
	manifest, fp := resumeManifest(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", data, 8)
	seedDigest := NewSHA256Digest()
	seedDigest.Update(data)
	seed := &ReceiverResume{
		TransferID:          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ManifestFingerprint: fp,
		Files:               map[int]ResumeFileProgress{0: {HaveBlocks: 3, SeedDigest: seedDigest}},
	}
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	sf := newSenderFrames(t, keys)
	sf.ctrl(&manifest)
	sf.ctrl(NewComplete(CompletionDigest(manifest.Files)))

	sink := &MemorySink{}
	var back outbox
	r := NewReceiver(ReceiverOptions{
		Send: back.push, SendDir: keys.J2O, RecvDir: keys.O2J, Sink: sink, Resume: seed,
	})
	for _, f := range sf.frames {
		r.Handle(f)
	}
	res, err := r.Wait(context.Background())
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if res.Digest != hexSHA256(data) {
		t.Fatalf("digest = %s, want %s", res.Digest, hexSHA256(data))
	}
	if !sink.IsClosed() {
		t.Fatal("sink not closed on done")
	}
	var msgs []ControlMsg
	for i, f := range back.snapshot() {
		o, err := Open(keys.J2O, uint64(i), f)
		if err != nil {
			t.Fatalf("open back frame %d: %v", i, err)
		}
		m, err := DecodeControl(o.Plaintext)
		if err != nil {
			t.Fatalf("decode back frame %d: %v", i, err)
		}
		msgs = append(msgs, m)
	}
	if len(msgs) != 2 {
		t.Fatalf("back-channel has %d frames, want 2 (resume_state, done)", len(msgs))
	}
	rs, ok := msgs[0].(*ResumeState)
	if !ok || rs.Files[0].HaveBlocks != 3 {
		t.Fatalf("first back frame = %#v, want resume_state with haveBlocks 3", msgs[0])
	}
	if msgs[1].FrameType() != FrameDone {
		t.Fatalf("second back frame = %T, want done", msgs[1])
	}
}
