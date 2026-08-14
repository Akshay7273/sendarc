package wire

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// senderMaster is the fixed 32-byte master key both sender tests derive their keys from.
func senderMaster() []byte {
	m := make([]byte, 32)
	for i := range m {
		m[i] = 9
	}
	return m
}

// outbox is a concurrency-safe capture of the frames a Sender emits from its Run goroutine.
type outbox struct {
	mu     sync.Mutex
	frames [][]byte
}

func (o *outbox) push(f []byte) error {
	o.mu.Lock()
	o.frames = append(o.frames, append([]byte(nil), f...))
	o.mu.Unlock()
	return nil
}

func (o *outbox) len() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.frames)
}

func (o *outbox) snapshot() [][]byte {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([][]byte(nil), o.frames...)
}

// waitStable blocks until the outbox has held want frames unchanged across a few polls,
// i.e. the sender has stalled on its window gate rather than merely being between sends.
func waitStable(t *testing.T, o *outbox, want int) {
	t.Helper()
	stable := 0
	for i := 0; i < 2000; i++ {
		if o.len() == want {
			if stable++; stable >= 5 {
				return
			}
		} else {
			stable = 0
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("outbox never stabilized at %d frames (saw %d)", want, o.len())
}

func TestSenderEmitsGrammarGatedByAck(t *testing.T) {
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	data := seq(20) // block=8 → blocks 0,1 full, block 2 = 4 bytes
	var out outbox

	s := NewSender(SenderOptions{
		File:      BytesSource(data, FileMeta{Name: "f", Size: 20}, 0),
		Send:      out.push,
		SendDir:   keys.O2J,
		RecvDir:   keys.J2O,
		BlockSize: 8,
		FrameSize: 4,
		Window:    1, // force gating after block 0
	})

	type result struct {
		digest string
		err    error
	}
	res := make(chan result, 1)
	go func() {
		d, err := s.Run(context.Background())
		res <- result{d, err}
	}()

	// manifest + block 0's two frames + block 0 hash = 4 frames, then it stalls on window=1.
	waitStable(t, &out, 4)
	peek := 0
	for _, f := range out.snapshot() {
		o, err := Open(keys.O2J, uint64(peek), f)
		if err != nil {
			t.Fatalf("open frame %d: %v", peek, err)
		}
		if peek == 0 && o.Header.Type != FrameManifest {
			t.Fatalf("frame 0 type = %d, want manifest", o.Header.Type)
		}
		if o.Header.Type == FrameComplete {
			t.Fatalf("complete sent before receiver acked the window")
		}
		peek++
	}

	// Ack every verified block so the window drains, then send done.
	ackCtr := uint64(0)
	ack := func(blockIdx int) {
		payload, err := EncodeControl(NewAck(0, blockIdx))
		if err != nil {
			t.Fatal(err)
		}
		frame, err := Seal(keys.J2O, ackCtr, FrameHeaderInput{Version: FrameVersion, Type: FrameAck}, payload)
		if err != nil {
			t.Fatal(err)
		}
		ackCtr++
		s.Handle(frame)
	}
	ack(0)
	waitStable(t, &out, 7)
	ack(1)
	waitStable(t, &out, 9)
	ack(2)

	// Every block, including the short final block, carries a hash. The sender emits complete
	// only after all three verified acknowledgements arrive.
	waitStable(t, &out, 10)

	donePayload, err := EncodeControl(NewDone())
	if err != nil {
		t.Fatal(err)
	}
	doneFrame, err := Seal(keys.J2O, ackCtr, FrameHeaderInput{Version: FrameVersion, Type: FrameDone}, donePayload)
	if err != nil {
		t.Fatal(err)
	}
	s.Handle(doneFrame)

	got := <-res
	if got.err != nil {
		t.Fatalf("Run: %v", got.err)
	}
	sum := sha256.Sum256(data)
	wantDigest := hex.EncodeToString(sum[:])
	if got.digest != wantDigest {
		t.Errorf("digest = %s, want %s", got.digest, wantDigest)
	}

	// Decode the full outbound sequence: last frame must be complete with the file digest, and
	// the block_data payloads must reassemble to the original bytes in order.
	var body []byte
	var lastType uint8
	var lastPayload []byte
	c := 0
	for _, f := range out.snapshot() {
		o, err := Open(keys.O2J, uint64(c), f)
		if err != nil {
			t.Fatalf("open frame %d: %v", c, err)
		}
		if o.Header.Type == FrameBlockData {
			body = append(body, o.Plaintext...)
		}
		lastType, lastPayload = o.Header.Type, o.Plaintext
		c++
	}
	if lastType != FrameComplete {
		t.Fatalf("last frame type = %d, want complete", lastType)
	}
	msg, err := DecodeControl(lastPayload)
	if err != nil {
		t.Fatal(err)
	}
	complete, ok := msg.(*Complete)
	if !ok || complete.FileDigest != wantDigest {
		t.Fatalf("complete = %#v, want digest %s", msg, wantDigest)
	}
	if string(body) != string(data) {
		t.Errorf("reassembled body = %v, want %v", body, data)
	}
}

func TestSenderRejectsOnReceiverFail(t *testing.T) {
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	s := NewSender(SenderOptions{
		File:      BytesSource(make([]byte, 4), FileMeta{Name: "f", Size: 4}, 0),
		Send:      func([]byte) error { return nil },
		SendDir:   keys.O2J,
		RecvDir:   keys.J2O,
		BlockSize: 8,
		FrameSize: 4,
	})

	res := make(chan error, 1)
	go func() {
		_, err := s.Run(context.Background())
		res <- err
	}()

	payload, err := EncodeControl(NewFail(FailIntegrity))
	if err != nil {
		t.Fatal(err)
	}
	failFrame, err := Seal(keys.J2O, 0, FrameHeaderInput{Version: FrameVersion, Type: FrameFail}, payload)
	if err != nil {
		t.Fatal(err)
	}
	s.Handle(failFrame)

	select {
	case err := <-res:
		if err == nil || !strings.Contains(err.Error(), "integrity") {
			t.Fatalf("Run error = %v, want one mentioning integrity", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after receiver fail")
	}
}

func TestSenderRetransmitsNackWithFreshCounterAndAckedProgress(t *testing.T) {
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	data := []byte{1, 2, 3, 4}
	var out outbox
	var progress []int64
	s := NewSender(SenderOptions{
		File:       BytesSource(data, FileMeta{Name: "f", Size: int64(len(data))}, 0),
		Send:       out.push,
		SendDir:    keys.O2J,
		RecvDir:    keys.J2O,
		BlockSize:  8,
		FrameSize:  4,
		Window:     1,
		AckTimeout: time.Second,
		OnProgress: func(n int64) { progress = append(progress, n) },
	})

	res := make(chan error, 1)
	go func() { _, runErr := s.Run(context.Background()); res <- runErr }()
	waitStable(t, &out, 3)
	if len(progress) != 0 {
		t.Fatalf("progress before ack = %v", progress)
	}

	peerCounter := uint64(0)
	feed := func(msg ControlMsg) {
		payload, encodeErr := EncodeControl(msg)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		frame, sealErr := Seal(keys.J2O, peerCounter,
			FrameHeaderInput{Version: FrameVersion, Type: msg.FrameType()}, payload)
		if sealErr != nil {
			t.Fatal(sealErr)
		}
		peerCounter++
		s.Handle(frame)
	}
	feed(NewNack(0, 0, NackMissing))
	waitStable(t, &out, 5)
	feed(NewAck(0, 0))
	waitStable(t, &out, 6)
	feed(NewDone())
	if runErr := <-res; runErr != nil {
		t.Fatalf("Run: %v", runErr)
	}
	if len(progress) != 1 || progress[0] != int64(len(data)) {
		t.Fatalf("progress = %v, want [%d]", progress, len(data))
	}

	frames := out.snapshot()
	wantTypes := []uint8{FrameManifest, FrameBlockData, FrameBlockHash,
		FrameBlockData, FrameBlockHash, FrameComplete}
	for i, frame := range frames {
		opened, openErr := Open(keys.O2J, uint64(i), frame)
		if openErr != nil {
			t.Fatalf("open frame %d: %v", i, openErr)
		}
		if opened.Header.Type != wantTypes[i] {
			t.Errorf("frame %d type = %d, want %d", i, opened.Header.Type, wantTypes[i])
		}
	}
	if string(frames[1]) == string(frames[3]) {
		t.Error("retransmitted ciphertext reused the original nonce")
	}
}

func TestSenderPauseResumeStopsNewData(t *testing.T) {
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	var out outbox
	var states []TransferState
	s := NewSender(SenderOptions{
		File:          BytesSource([]byte{1, 2, 3, 4}, FileMeta{Name: "f", Size: 4}, 0),
		Send:          out.push,
		SendDir:       keys.O2J,
		RecvDir:       keys.J2O,
		BlockSize:     8,
		FrameSize:     4,
		OnStateChange: func(state TransferState) { states = append(states, state) },
	})
	if err := s.Pause(); err != nil {
		t.Fatal(err)
	}
	res := make(chan error, 1)
	go func() { _, runErr := s.Run(context.Background()); res <- runErr }()
	waitStable(t, &out, 2) // pause control + manifest
	if err := s.Resume(); err != nil {
		t.Fatal(err)
	}
	waitStable(t, &out, 5) // resume control + data + hash

	peerCounter := uint64(0)
	for _, msg := range []ControlMsg{NewAck(0, 0), NewDone()} {
		if _, ok := msg.(*Done); ok {
			waitStable(t, &out, 6) // complete precedes done
		}
		payload, encodeErr := EncodeControl(msg)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		frame, sealErr := Seal(keys.J2O, peerCounter,
			FrameHeaderInput{Version: FrameVersion, Type: msg.FrameType()}, payload)
		if sealErr != nil {
			t.Fatal(sealErr)
		}
		peerCounter++
		s.Handle(frame)
	}
	if runErr := <-res; runErr != nil {
		t.Fatalf("Run: %v", runErr)
	}
	if len(states) != 2 || states[0] != TransferPaused || states[1] != TransferRunning {
		t.Fatalf("states = %v, want [paused running]", states)
	}
}

func TestSenderBoundsTimeoutRetries(t *testing.T) {
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	var out outbox
	s := NewSender(SenderOptions{
		File:       BytesSource([]byte{1, 2, 3, 4}, FileMeta{Name: "f", Size: 4}, 0),
		Send:       out.push,
		SendDir:    keys.O2J,
		RecvDir:    keys.J2O,
		BlockSize:  8,
		FrameSize:  4,
		AckTimeout: 5 * time.Millisecond,
		MaxRetries: 1,
	})
	res := make(chan error, 1)
	go func() { _, runErr := s.Run(context.Background()); res <- runErr }()
	select {
	case runErr := <-res:
		if runErr == nil || !strings.Contains(runErr.Error(), string(FailRetryExhausted)) {
			t.Fatalf("Run error = %v, want retry_exhausted", runErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after bounded retries")
	}
	if out.len() != 6 { // manifest + initial data/hash + one retry data/hash + fail
		t.Fatalf("outbox has %d frames, want 6", out.len())
	}
}

func TestSenderContextCancellationNotifiesPeer(t *testing.T) {
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	var out outbox
	s := NewSender(SenderOptions{
		File: BytesSource([]byte{1, 2, 3, 4}, FileMeta{Name: "f", Size: 4}, 0),
		Send: out.push, SendDir: keys.O2J, RecvDir: keys.J2O,
		BlockSize: 8, FrameSize: 4, AckTimeout: time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	res := make(chan error, 1)
	go func() { _, runErr := s.Run(ctx); res <- runErr }()
	waitStable(t, &out, 3)
	cancel()
	select {
	case runErr := <-res:
		if runErr == nil || !strings.Contains(runErr.Error(), string(FailCanceled)) {
			t.Fatalf("Run error = %v, want canceled", runErr)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not stop after context cancellation")
	}
	frames := out.snapshot()
	opened, openErr := Open(keys.O2J, uint64(len(frames)-1), frames[len(frames)-1])
	if openErr != nil {
		t.Fatal(openErr)
	}
	msg, decodeErr := DecodeControl(opened.Plaintext)
	control, ok := msg.(*Control)
	if decodeErr != nil || !ok || control.Op != ControlCancel {
		t.Fatalf("last cancellation frame = %#v, err=%v", msg, decodeErr)
	}
}

// TestSenderFailsOnDoneBeforeComplete pins the fail-closed half of the Done path: a
// receiver may only send Done in response to Complete (after verifying the whole-file
// digest), so Done before Complete is a protocol violation and must fail the transfer.
func TestSenderFailsOnDoneBeforeComplete(t *testing.T) {
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	var out outbox
	s := NewSender(SenderOptions{
		File:      BytesSource([]byte{1, 2, 3, 4}, FileMeta{Name: "f", Size: 4}, 0),
		Send:      out.push,
		SendDir:   keys.O2J,
		RecvDir:   keys.J2O,
		BlockSize: 8,
		FrameSize: 4,
	})
	res := make(chan error, 1)
	go func() { _, runErr := s.Run(context.Background()); res <- runErr }()
	waitStable(t, &out, 3) // manifest + data + hash

	done, err := EncodeControl(NewDone())
	if err != nil {
		t.Fatal(err)
	}
	frame, err := Seal(keys.J2O, 0, FrameHeaderInput{Version: FrameVersion, Type: NewDone().FrameType()}, done)
	if err != nil {
		t.Fatal(err)
	}
	s.Handle(frame)
	if runErr := <-res; runErr == nil {
		t.Fatal("Run succeeded on Done before Complete was sent")
	}
}

func TestSenderOnManifestRunsBeforeFirstFrame(t *testing.T) {
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	data := seq(20) // block=8 → blocks 0,1 full, block 2 = 4 bytes
	var out outbox
	hookDone := make(chan *Manifest, 1)
	var hookRan atomic.Bool
	firstFrameHookRan := false
	seenFirst := false
	s := NewSender(SenderOptions{
		File:       BytesSource(data, FileMeta{Name: "f", Size: 20}, 0),
		Send:       out.push,
		SendDir:    keys.O2J,
		RecvDir:    keys.J2O,
		BlockSize:  8,
		FrameSize:  4,
		Window:     1,
		TransferID: "0123456789abcdef0123456789abcdef",
		OnManifest: func(m Manifest) error {
			hookRan.Store(true)
			hookDone <- &m
			return nil
		},
	})
	// The hook must have completed before the very first frame (the manifest) is emitted:
	// the sender's own goroutine runs the hook, then Send; capturing order proves the
	// record would be durable before the id is advertised.
	origSend := out.push
	s.o.Send = func(f []byte) error {
		if !seenFirst {
			seenFirst = true
			firstFrameHookRan = hookRan.Load()
		}
		return origSend(f)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res := make(chan error, 1)
	go func() { _, runErr := s.Run(ctx); res <- runErr }()

	select {
	case m := <-hookDone:
		if m.TransferID != "0123456789abcdef0123456789abcdef" {
			t.Fatalf("hook manifest transferId = %q", m.TransferID)
		}
		if len(m.Files) != 1 || m.Files[0].Name != "f" || m.Files[0].Size != 20 {
			t.Fatalf("hook manifest files = %#v", m.Files)
		}
		sum := sha256.Sum256(data)
		if m.Files[0].FileDigest != hex.EncodeToString(sum[:]) {
			t.Fatalf("hook manifest digest = %s", m.Files[0].FileDigest)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnManifest never called")
	}
	// The manifest frame must be on the wire before canceling: the cancellation sends its
	// own control frame, and racing it against the manifest send makes the "first frame is
	// the manifest" assertion below nondeterministic.
	waitStable(t, &out, 1)

	cancel()
	if err := <-res; err == nil {
		t.Fatalf("Run unexpectedly succeeded after cancellation")
	}
	if !seenFirst {
		t.Fatal("no frame was ever sent")
	}
	if !firstFrameHookRan {
		t.Fatal("the manifest frame was emitted before OnManifest completed")
	}
	if out.len() == 0 {
		t.Fatal("manifest frame missing after hook")
	}
	opened, err := Open(keys.O2J, 0, out.snapshot()[0])
	if err != nil {
		t.Fatalf("open first frame: %v", err)
	}
	if opened.Header.Type != FrameManifest {
		t.Fatalf("first frame type = %d, want manifest", opened.Header.Type)
	}
	msg, err := DecodeControl(opened.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := msg.(*Manifest)
	if !ok || m.TransferID != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("first frame manifest = %#v", msg)
	}
}

func TestSenderOnManifestErrorAbortsBeforeManifestSent(t *testing.T) {
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	var out outbox
	s := NewSender(SenderOptions{
		File:       BytesSource(seq(20), FileMeta{Name: "f", Size: 20}, 0),
		Send:       out.push,
		SendDir:    keys.O2J,
		RecvDir:    keys.J2O,
		BlockSize:  8,
		FrameSize:  4,
		TransferID: "0123456789abcdef0123456789abcdef",
		OnManifest: func(Manifest) error {
			return errors.New("sender-state write failed")
		},
	})
	res := make(chan error, 1)
	go func() { _, runErr := s.Run(context.Background()); res <- runErr }()
	select {
	case runErr := <-res:
		if runErr == nil || !strings.Contains(runErr.Error(), "sender-state write failed") {
			t.Fatalf("Run error = %v, want the hook failure", runErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after hook failure")
	}
	if out.len() != 0 {
		t.Fatalf("hook failure still emitted %d frames; the manifest must never reach the wire", out.len())
	}
}
