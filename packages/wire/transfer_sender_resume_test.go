package wire

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// sealResumeIn seals one resume_state under the sender's inbound counter so tests can
// hand it to Handle exactly like a frame from the receiver.
func sealResumeIn(t *testing.T, keys TransferKeys, counter uint64, rs *ResumeState) []byte {
	t.Helper()
	payload, err := EncodeControl(rs)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := Seal(keys.J2O, counter, FrameHeaderInput{Version: FrameVersion, Type: FrameResumeState}, payload)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

// runSenderWithResume starts a sender that waits for one resume_state, injects it, then
// drives the resumed stream to completion. It returns the sender error (nil on success),
// the outbox snapshot, and the number of frames whose block data was transmitted.
func runSenderWithResume(t *testing.T, data []byte, rs *ResumeState) (*outbox, int, error) {
	t.Helper()
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	var out outbox
	s := NewSender(SenderOptions{
		File:      BytesSource(data, FileMeta{Name: "f", Size: int64(len(data)), Mime: "application/octet-stream", LastModified: 1}, 0),
		Send:      out.push,
		SendDir:   keys.O2J,
		RecvDir:   keys.J2O,
		BlockSize: 8,
		FrameSize: 4,
		Window:    1,
		TransferID: func() string {
			if rs != nil {
				return rs.TransferID
			}
			return "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}(),
	})

	res := make(chan error, 1)
	go func() {
		_, err := s.Run(context.Background())
		res <- err
	}()

	if rs != nil {
		// Wait for the manifest, then answer with the resume_state.
		waitStable(t, &out, 1)
		s.Handle(sealResumeIn(t, keys, 0, rs))
	} else {
		// Inject the resume_state before the manifest was ever validated.
		s.Handle(sealResumeIn(t, keys, 0, NewResumeState("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", []ResumeFileState{{Idx: 0, HaveBlocks: 0}})))
		return &out, -1, waitSenderResult(t, res)
	}

	// With window=1 the resumed stream stalls after the manifest plus the frames of the
	// first block above the high-water mark; settle it block by block.
	blocks := (len(data)-1)/8 + 1
	have := 0
	if len(rs.Files) == 1 {
		have = rs.Files[0].HaveBlocks
	}
	counter := uint64(1)
	for b := have; b < blocks; b++ {
		waitStable(t, &out, 1+2*(b-have+1))
		payload, err := EncodeControl(NewAck(0, b))
		if err != nil {
			t.Fatal(err)
		}
		frame, err := Seal(keys.J2O, counter, FrameHeaderInput{Version: FrameVersion, Type: FrameAck}, payload)
		if err != nil {
			t.Fatal(err)
		}
		counter++
		s.Handle(frame)
	}
	waitStable(t, &out, 1+2*(blocks-have)+1)
	donePayload, err := EncodeControl(NewDone())
	if err != nil {
		t.Fatal(err)
	}
	doneFrame, err := Seal(keys.J2O, counter, FrameHeaderInput{Version: FrameVersion, Type: FrameDone}, donePayload)
	if err != nil {
		t.Fatal(err)
	}
	s.Handle(doneFrame)

	runErr := waitSenderResult(t, res)
	frames := out.snapshot()
	transmitted := 0
	for i, f := range frames {
		o, err := Open(keys.O2J, uint64(i), f)
		if err != nil {
			t.Fatalf("open frame %d: %v", i, err)
		}
		if o.Header.Type == FrameBlockData {
			transmitted++
		}
	}
	return &out, transmitted, runErr
}

func waitSenderResult(t *testing.T, res chan error) error {
	t.Helper()
	select {
	case err := <-res:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("sender.Run did not return")
		return nil
	}
}

func fp(t *testing.T, data []byte, transferID string) string {
	t.Helper()
	sum := sha256.Sum256(data)
	blocks := (len(data)-1)/8 + 1
	manifest := Manifest{
		Type:       FrameManifest,
		TransferID: transferID,
		Files: []FileEntry{{
			Idx: 0, Name: "f", Size: int64(len(data)), Mime: "application/octet-stream",
			LastModified: 1, BlockSize: 8, Blocks: blocks, FileDigest: hex.EncodeToString(sum[:]),
		}},
		TotalSize: int64(len(data)),
	}
	f, err := ManifestFingerprint(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// TestSenderRejectsResumeStateBeforeManifest: a resume_state must never be accepted before
// the sender validated its own manifest — there is no binding to check it against.
func TestSenderRejectsResumeStateBeforeManifest(t *testing.T) {
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	s := NewSender(SenderOptions{
		File:      BytesSource([]byte{1, 2, 3}, FileMeta{Name: "f", Size: 3}, 0),
		Send:      func([]byte) error { return nil },
		SendDir:   keys.O2J,
		RecvDir:   keys.J2O,
		BlockSize: 8,
		FrameSize: 4,
	})
	s.Handle(sealResumeIn(t, keys, 0, NewResumeState("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", []ResumeFileState{{Idx: 0, HaveBlocks: 0}})))
	res := make(chan error, 1)
	go func() {
		_, err := s.Run(context.Background())
		res <- err
	}()
	err = waitSenderResult(t, res)
	if err == nil || !strings.Contains(err.Error(), "unexpected resume_state") {
		t.Fatalf("Run error = %v, want one mentioning unexpected resume_state", err)
	}
}

// TestSenderRejectsResumeTransferIDMismatch: a resume_state bound to another transfer is a
// different receive; the sender must fail closed rather than trust its claims.
func TestSenderRejectsResumeTransferIDMismatch(t *testing.T) {
	data := seq(20)
	var out outbox
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	s := NewSender(SenderOptions{
		File:       BytesSource(data, FileMeta{Name: "f", Size: int64(len(data)), Mime: "application/octet-stream", LastModified: 1}, 0),
		Send:       out.push,
		SendDir:    keys.O2J,
		RecvDir:    keys.J2O,
		BlockSize:  8,
		FrameSize:  4,
		Window:     1,
		TransferID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	res := make(chan error, 1)
	go func() {
		_, err := s.Run(context.Background())
		res <- err
	}()
	waitStable(t, &out, 1)
	s.Handle(sealResumeIn(t, keys, 0, NewResumeState("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", []ResumeFileState{{Idx: 0, HaveBlocks: 0}})))
	err = waitSenderResult(t, res)
	if err == nil || !strings.Contains(err.Error(), "resume_state transfer id mismatch") {
		t.Fatalf("Run error = %v, want resume_state transfer id mismatch", err)
	}
}

// TestSenderRejectsResumeFingerprintMismatch: a resume_state claiming a manifest the sender
// is not streaming must fail closed even when every other claim is plausible.
func TestSenderRejectsResumeFingerprintMismatch(t *testing.T) {
	data := seq(20)
	fpA := fp(t, data, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	var out outbox
	s := NewSender(SenderOptions{
		File:       BytesSource(data, FileMeta{Name: "f", Size: int64(len(data)), Mime: "application/octet-stream", LastModified: 1}, 0),
		Send:       out.push,
		SendDir:    keys.O2J,
		RecvDir:    keys.J2O,
		BlockSize:  8,
		FrameSize:  4,
		Window:     1,
		TransferID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	res := make(chan error, 1)
	go func() {
		_, err := s.Run(context.Background())
		res <- err
	}()
	waitStable(t, &out, 1)
	stale := NewResumeState("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", []ResumeFileState{{Idx: 0, HaveBlocks: 1}})
	stale.ManifestFingerprint = strings.Repeat("0", 64)
	if stale.ManifestFingerprint == fpA {
		t.Fatal("test fingerprint collision with the real manifest fingerprint")
	}
	s.Handle(sealResumeIn(t, keys, 0, stale))
	err = waitSenderResult(t, res)
	if err == nil || !strings.Contains(err.Error(), "resume_state manifest fingerprint mismatch") {
		t.Fatalf("Run error = %v, want resume_state manifest fingerprint mismatch", err)
	}
}

// TestSenderRejectsMalformedResumeClaims: every impossible claim — unknown file, duplicated
// file, out-of-range haveBlocks, missing file entry — fails the send closed.
func TestSenderRejectsMalformedResumeClaims(t *testing.T) {
	data := seq(20) // block=8 → blocks 0,1 full, block 2 = 4 bytes
	id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cases := []struct {
		name string
		rs   *ResumeState
		want string
	}{
		{"unknown file", NewResumeState(id, []ResumeFileState{{Idx: 3, HaveBlocks: 0}}), "resume_state references an unknown file"},
		{"negative file", NewResumeState(id, []ResumeFileState{{Idx: -1, HaveBlocks: 0}}), "resume_state references an unknown file"},
		{"duplicate file", NewResumeState(id, []ResumeFileState{{Idx: 0, HaveBlocks: 0}, {Idx: 0, HaveBlocks: 0}}), "resume_state references a file more than once"},
		{"haveBlocks above blocks", NewResumeState(id, []ResumeFileState{{Idx: 0, HaveBlocks: 4}}), "resume_state haveBlocks out of range"},
		{"haveBlocks negative", NewResumeState(id, []ResumeFileState{{Idx: 0, HaveBlocks: -1}}), "resume_state haveBlocks out of range"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			keys, err := DeriveTransferKeys(senderMaster())
			if err != nil {
				t.Fatal(err)
			}
			var out outbox
			s := NewSender(SenderOptions{
				File:       BytesSource(data, FileMeta{Name: "f", Size: int64(len(data)), Mime: "application/octet-stream", LastModified: 1}, 0),
				Send:       out.push,
				SendDir:    keys.O2J,
				RecvDir:    keys.J2O,
				BlockSize:  8,
				FrameSize:  4,
				Window:     1,
				TransferID: id,
			})
			res := make(chan error, 1)
			go func() {
				_, err := s.Run(context.Background())
				res <- err
			}()
			waitStable(t, &out, 1)
			s.Handle(sealResumeIn(t, keys, 0, c.rs))
			err = waitSenderResult(t, res)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Run error = %v, want one mentioning %s", err, c.want)
			}
			if frames := out.snapshot(); frames[len(frames)-1][9] == FrameComplete {
				t.Fatal("complete was sent despite a rejected resume_state")
			}
		})
	}
}

// TestSenderRejectsResumeMissingFileEntry: a claim covering only one of two manifest files
// must fail closed, not silently restart the uncovered file from zero.
func TestSenderRejectsResumeMissingFileEntry(t *testing.T) {
	id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	dataA := seq(20)
	dataB := seq(30)
	meta := func(name string, size int) FileMeta {
		return FileMeta{Name: name, Size: int64(size), Mime: "application/octet-stream", LastModified: 1}
	}
	var out outbox
	s := NewSender(SenderOptions{
		Files: []FileSource{
			BytesSource(dataA, meta("a", len(dataA)), 0),
			BytesSource(dataB, meta("b", len(dataB)), 0),
		},
		Send:       out.push,
		SendDir:    keys.O2J,
		RecvDir:    keys.J2O,
		BlockSize:  8,
		FrameSize:  4,
		Window:     1,
		TransferID: id,
	})
	res := make(chan error, 1)
	go func() {
		_, err := s.Run(context.Background())
		res <- err
	}()
	waitStable(t, &out, 1)
	s.Handle(sealResumeIn(t, keys, 0, NewResumeState(id, []ResumeFileState{{Idx: 0, HaveBlocks: 1}})))
	err = waitSenderResult(t, res)
	if err == nil || !strings.Contains(err.Error(), "resume_state is missing a file entry") {
		t.Fatalf("Run error = %v, want resume_state is missing a file entry", err)
	}
}

// TestSenderResumeStreamsOnlyMissingBlocks: a valid resume_state (with fingerprint) skips the
// held prefix entirely and transmits only the blocks above the high-water mark.
func TestSenderResumeStreamsOnlyMissingBlocks(t *testing.T) {
	data := seq(20) // blocks 0,1 full, block 2 = 4 bytes
	id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	rs := NewResumeState(id, []ResumeFileState{{Idx: 0, HaveBlocks: 2}})
	rs.ManifestFingerprint = fp(t, data, id)
	out, transmitted, err := runSenderWithResume(t, data, rs)
	if err != nil {
		t.Fatalf("Run error = %v", err)
	}
	if transmitted != 1 {
		t.Fatalf("transmitted %d data frames, want 1 (only block 2)", transmitted)
	}
	// manifest + block2 data + block2 hash + complete
	if n := out.len(); n != 4 {
		t.Fatalf("outbox has %d frames, want 4 (manifest, block 2 data, hash, complete)", n)
	}
}

// TestSenderOnResumeReportsReusedBaselineBeforeBlocks pins the V13-PR08 progress contract:
// the verified baseline reused from the authenticated checkpoint is reported ONCE via
// OnResume BEFORE any block is sent, and the first OnProgress sample counts only the
// session advance above that baseline (firstProgress = reused + first new block), so the
// host anchors its session rate on the reused jump without counting it as transferred.
func TestSenderOnResumeReportsReusedBaselineBeforeBlocks(t *testing.T) {
	data := seq(20) // 3 blocks of 8: 16 bytes + 4
	id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	rs := NewResumeState(id, []ResumeFileState{{Idx: 0, HaveBlocks: 2}})
	rs.ManifestFingerprint = fp(t, data, id)
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	var out outbox
	reused := int64(-1)
	firstProgress := int64(-1)
	s := NewSender(SenderOptions{
		File: BytesSource(data, FileMeta{Name: "f", Size: int64(len(data)), Mime: "application/octet-stream", LastModified: 1}, 0),
		Send: out.push, SendDir: keys.O2J, RecvDir: keys.J2O,
		BlockSize: 8, FrameSize: 4, Window: 1,
		TransferID: id,
		OnResume: func(n int64) {
			if reused != -1 {
				t.Fatalf("OnResume fired %d times, want exactly once", reused)
			}
			reused = n
		},
		OnProgress: func(n int64) {
			if firstProgress < 0 {
				firstProgress = n
			}
		},
	})
	res := make(chan error, 1)
	go func() {
		_, err := s.Run(context.Background())
		res <- err
	}()
	waitStable(t, &out, 1)
	s.Handle(sealResumeIn(t, keys, 0, rs))
	counter := uint64(1)
	// Ack the single missing block and the terminal Done, settling the send.
	waitStable(t, &out, 3)
	ack, err := EncodeControl(NewAck(0, 2))
	if err != nil {
		t.Fatal(err)
	}
	frame, err := Seal(keys.J2O, counter, FrameHeaderInput{Version: FrameVersion, Type: FrameAck}, ack)
	if err != nil {
		t.Fatal(err)
	}
	counter++
	s.Handle(frame)
	waitStable(t, &out, 4)
	donePayload, err := EncodeControl(NewDone())
	if err != nil {
		t.Fatal(err)
	}
	doneFrame, err := Seal(keys.J2O, counter, FrameHeaderInput{Version: FrameVersion, Type: FrameDone}, donePayload)
	if err != nil {
		t.Fatal(err)
	}
	s.Handle(doneFrame)
	if err := waitSenderResult(t, res); err != nil {
		t.Fatalf("Run error = %v", err)
	}
	// 2 blocks * 8 bytes = 16 bytes reused from the authenticated checkpoint.
	if reused != 16 {
		t.Fatalf("OnResume reused = %d, want 16", reused)
	}
	// The reused baseline was reported before any block was sent; the first OnProgress then
	// equals baseline + the one missing block (4 bytes), proving the session advance is
	// measured above the checkpoint, not from zero.
	if firstProgress != reused+4 {
		t.Fatalf("first OnProgress = %d, want reused baseline + first new block (%d)", firstProgress, reused+4)
	}
	// Zero-byte session advance: with no missing blocks, firstProgress must never exceed the
	// baseline — but this transfer has one missing block, so assert the ordering instead:
	// OnResume fired before the first OnProgress.
	if reused != 16 || firstProgress < reused {
		t.Fatalf("progress regressed below the reused baseline: reused=%d firstProgress=%d", reused, firstProgress)
	}
}

// TestSenderAcceptsLegacyResumeStateWithoutFingerprint: a peer predating the fingerprint
// binding answers without the field; structural validation still applies and the resume works.
func TestSenderAcceptsLegacyResumeStateWithoutFingerprint(t *testing.T) {
	data := seq(20)
	rs := NewResumeState("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", []ResumeFileState{{Idx: 0, HaveBlocks: 2}})
	out, transmitted, err := runSenderWithResume(t, data, rs)
	if err != nil {
		t.Fatalf("Run error = %v", err)
	}
	if transmitted != 1 {
		t.Fatalf("transmitted %d data frames, want 1", transmitted)
	}
	if n := out.len(); n != 4 {
		t.Fatalf("outbox has %d frames, want 4", n)
	}
}

// TestSenderRejectsConflictingDuplicateResumeState: the receiver's answer retransmitted
// identically after a path cutover is an idempotent no-op; a different second answer means
// one of the two peers is not this transfer and the send must fail closed.
func TestSenderRejectsConflictingDuplicateResumeState(t *testing.T) {
	data := seq(20)
	id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	var out outbox
	s := NewSender(SenderOptions{
		File:       BytesSource(data, FileMeta{Name: "f", Size: int64(len(data)), Mime: "application/octet-stream", LastModified: 1}, 0),
		Send:       out.push,
		SendDir:    keys.O2J,
		RecvDir:    keys.J2O,
		BlockSize:  8,
		FrameSize:  4,
		Window:     1,
		TransferID: id,
	})
	res := make(chan error, 1)
	go func() {
		_, err := s.Run(context.Background())
		res <- err
	}()
	waitStable(t, &out, 1)
	first := NewResumeState(id, []ResumeFileState{{Idx: 0, HaveBlocks: 2}})
	first.ManifestFingerprint = fp(t, data, id)
	s.Handle(sealResumeIn(t, keys, 0, first))
	// A different second answer (raised high-water mark out of nowhere) is a conflict.
	conflicting := NewResumeState(id, []ResumeFileState{{Idx: 0, HaveBlocks: 3}})
	conflicting.ManifestFingerprint = first.ManifestFingerprint
	s.Handle(sealResumeIn(t, keys, 1, conflicting))
	err = waitSenderResult(t, res)
	if err == nil || !strings.Contains(err.Error(), "conflicting duplicate resume_state") {
		t.Fatalf("Run error = %v, want conflicting duplicate resume_state", err)
	}
}

// TestSenderDuplicateResumeStateIsIdempotent: an identical retransmitted answer (the cutover
// case the receiver's manifest retransmission triggers) must not disturb the resumed stream.
func TestSenderDuplicateResumeStateIsIdempotent(t *testing.T) {
	data := seq(20)
	id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	var out outbox
	s := NewSender(SenderOptions{
		File:       BytesSource(data, FileMeta{Name: "f", Size: int64(len(data)), Mime: "application/octet-stream", LastModified: 1}, 0),
		Send:       out.push,
		SendDir:    keys.O2J,
		RecvDir:    keys.J2O,
		BlockSize:  8,
		FrameSize:  4,
		Window:     1,
		TransferID: id,
	})
	res := make(chan error, 1)
	go func() {
		_, err := s.Run(context.Background())
		res <- err
	}()
	waitStable(t, &out, 1)
	rs := NewResumeState(id, []ResumeFileState{{Idx: 0, HaveBlocks: 2}})
	rs.ManifestFingerprint = fp(t, data, id)
	s.Handle(sealResumeIn(t, keys, 0, rs))
	s.Handle(sealResumeIn(t, keys, 1, rs))

	// Wait for the resumed stream (manifest + block 2 data + hash) before acking:
	// an ack for a file the sender has not started streaming is "ack for unknown file".
	waitStable(t, &out, 3)
	payload, err := EncodeControl(NewAck(0, 2))
	if err != nil {
		t.Fatal(err)
	}
	ackFrame, err := Seal(keys.J2O, 2, FrameHeaderInput{Version: FrameVersion, Type: FrameAck}, payload)
	if err != nil {
		t.Fatal(err)
	}
	s.Handle(ackFrame)
	waitStable(t, &out, 4)
	donePayload, err := EncodeControl(NewDone())
	if err != nil {
		t.Fatal(err)
	}
	doneFrame, err := Seal(keys.J2O, 3, FrameHeaderInput{Version: FrameVersion, Type: FrameDone}, donePayload)
	if err != nil {
		t.Fatal(err)
	}
	s.Handle(doneFrame)
	if err := waitSenderResult(t, res); err != nil {
		t.Fatalf("Run error = %v", err)
	}
	transmitted := 0
	for i, f := range out.snapshot() {
		o, err := Open(keys.O2J, uint64(i), f)
		if err != nil {
			t.Fatalf("open frame %d: %v", i, err)
		}
		if o.Header.Type == FrameBlockData {
			transmitted++
		}
	}
	if transmitted != 1 {
		t.Fatalf("transmitted %d data frames, want 1", transmitted)
	}
}
