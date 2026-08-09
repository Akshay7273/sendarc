package wire

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

// loopbackMaster is the fixed master key the loopback derives both directions from.
func loopbackMaster() []byte {
	m := make([]byte, 32)
	for i := range m {
		m[i] = 3
	}
	return m
}

type loopbackResult struct {
	runErr  error
	recvRes ReceiveResult
	recvErr error
	sink    *MemorySink
}

// runLoopback wires a Sender (offerer, o2j) to a Receiver (joiner) over two buffered channels,
// each drained by its own goroutine so delivery is ordered and genuinely concurrent — the same
// shape as a real reliable, ordered DataChannel. When corrupt is set, one byte of the second
// frame the sender emits is flipped in flight, forcing an integrity abort.
func runLoopback(t *testing.T, data []byte, blockSize, frameSize, window int, corrupt bool) loopbackResult {
	t.Helper()
	keys, err := DeriveTransferKeys(loopbackMaster())
	if err != nil {
		t.Fatal(err)
	}
	sink := &MemorySink{}

	// Buffers comfortably exceed the window's in-flight frames so no send blocks; the window
	// gate, not the buffer, is what bounds the sender.
	s2r := make(chan []byte, 4096)
	r2s := make(chan []byte, 4096)
	cp := func(f []byte) []byte { return append([]byte(nil), f...) }

	var sentCount int64
	senderSend := func(f []byte) error {
		if corrupt && atomic.AddInt64(&sentCount, 1) == 2 {
			f = cp(f)
			f[len(f)-1] ^= 0x01
		}
		s2r <- cp(f)
		return nil
	}

	sender := NewSender(SenderOptions{
		File:      BytesSource(data, FileMeta{Name: "f", Size: int64(len(data)), Mime: "application/octet-stream", LastModified: 1}, 0),
		Send:      senderSend,
		SendDir:   keys.O2J,
		RecvDir:   keys.J2O,
		BlockSize: blockSize,
		FrameSize: frameSize,
		Window:    window,
	})
	receiver := NewReceiver(ReceiverOptions{
		Send:    func(f []byte) error { r2s <- cp(f); return nil },
		SendDir: keys.J2O,
		RecvDir: keys.O2J,
		Sink:    sink,
	})

	go func() {
		for f := range s2r {
			receiver.Handle(f)
		}
	}()
	go func() {
		for f := range r2s {
			sender.Handle(f)
		}
	}()

	runErrCh := make(chan error, 1)
	go func() { _, e := sender.Run(context.Background()); runErrCh <- e }()

	recvRes, recvErr := receiver.Wait(context.Background())
	var runErr error
	select {
	case runErr = <-runErrCh:
	case <-time.After(5 * time.Second):
		t.Fatal("sender.Run did not return after the receiver settled")
	}
	close(s2r)
	close(r2s)
	return loopbackResult{runErr: runErr, recvRes: recvRes, recvErr: recvErr, sink: sink}
}

func TestLoopbackStreamsVariousSizes(t *testing.T) {
	sizes := []int{0, 1, 7, 8, 20, 4096, 100_000}
	for _, size := range sizes {
		size := size
		t.Run(fmt.Sprintf("%d_bytes", size), func(t *testing.T) {
			data := make([]byte, size)
			for i := range data {
				data[i] = byte((i*131 + 7) & 0xff)
			}
			res := runLoopback(t, data, 1024, 256, 4, false)
			if res.runErr != nil {
				t.Fatalf("sender: %v", res.runErr)
			}
			if res.recvErr != nil {
				t.Fatalf("receiver: %v", res.recvErr)
			}
			if string(res.sink.Bytes()) != string(data) {
				t.Fatalf("received bytes differ from source (%d bytes)", size)
			}
			want := sha256.Sum256(data)
			if res.recvRes.Digest != hex.EncodeToString(want[:]) {
				t.Errorf("digest = %s, want %s", res.recvRes.Digest, hex.EncodeToString(want[:]))
			}
		})
	}
}

func TestLoopbackAbortsOnCorruptedFrame(t *testing.T) {
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i & 0xff)
	}
	res := runLoopback(t, data, 1024, 256, 4, true)
	if res.runErr == nil && res.recvErr == nil {
		t.Fatal("corrupted transfer settled cleanly; expected an abort on at least one side")
	}
	if res.sink.IsClosed() {
		t.Error("sink was closed despite a corrupted frame; it must not commit")
	}
}
