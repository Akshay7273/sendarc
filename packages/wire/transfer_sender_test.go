package wire

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
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

func TestSenderEmitsGrammarGatedByBlockRecv(t *testing.T) {
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

	// Ack every block so the window drains, then send done.
	ackCtr := uint64(0)
	ack := func(blockIdx int) {
		payload, err := EncodeControl(NewBlockRecv(0, blockIdx))
		if err != nil {
			t.Fatal(err)
		}
		frame, err := Seal(keys.J2O, ackCtr, FrameHeaderInput{Version: FrameVersion, Type: FrameBlockRecv}, payload)
		if err != nil {
			t.Fatal(err)
		}
		ackCtr++
		s.Handle(frame)
	}
	ack(0)
	ack(1)
	ack(2)

	// Let pass 2 drain all blocks and send complete before we confirm done — otherwise done
	// would settle the sender mid-stream and complete would never be sent. The final 4-byte
	// block lands on a frame boundary, so like the TS reference it carries no block_hash:
	// manifest + (block0: 2 data + hash) + (block1: 2 data + hash) + (block2: 1 data) +
	// complete = 9 frames.
	waitStable(t, &out, 9)

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
