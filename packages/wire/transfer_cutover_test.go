package wire

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This file pins the direct→relay path-migration correctness contract asserted by V12-PR05: a
// cutover to a new ordered byte path must (1) keep already-committed blocks authoritative,
// (2) discard only the uncommitted partial block being assembled on the old path, (3) retransmit
// the unacknowledged inflight window with fresh AEAD counters so the receiver can resync, and
// (4) reject old-path frames that arrive late as replays rather than treating them as an
// integrity violation. A path cutover mid-transfer never restarts progress at byte zero.

// cutoverLink models two ordered byte paths (e.g. direct then relay). Engines write via route(),
// which copies frames to the currently selected path; the active-path channels are drained so no
// send blocks. At a cutover the test disarms the old path (its queued tail is dropped, as a
// torn-down transport would) and swaps the active path so writes land on the new one.
type cutoverLink struct {
	oldS2R, oldR2S chan []byte
	newS2R, newR2S chan []byte

	path atomic.Int32
}

func newCutoverLink() *cutoverLink {
	return &cutoverLink{
		oldS2R: make(chan []byte, 8192), oldR2S: make(chan []byte, 8192),
		newS2R: make(chan []byte, 8192), newR2S: make(chan []byte, 8192),
	}
}

func (l *cutoverLink) route(dir int, frame []byte) error {
	if l.path.Load() == cutPathNew {
		return l.deliver(dir == dirS2R, l.newS2R, l.newR2S, frame)
	}
	return l.deliver(dir == dirS2R, l.oldS2R, l.oldR2S, frame)
}

func (l *cutoverLink) deliver(s2r bool, s2rCh, r2sCh chan []byte, frame []byte) error {
	ch := r2sCh
	if s2r {
		ch = s2rCh
	}
	ch <- append([]byte(nil), frame...)
	return nil
}

func (l *cutoverLink) switchPath() { l.path.Store(cutPathNew) }

const (
	cutPathOld = 0
	cutPathNew = 1
)

// TestSenderReceiverMidTransferCutover drives a sender→receiver transfer over the old path,
// cuts over to the new path mid-data once block 0 is committed while later blocks are still in
// flight / partially assembled, and asserts the transfer still completes byte-identically:
// committed blocks stay written, the uncommitted window is retransmitted with fresh counters, an
// old-path frame replayed after the switch is ignored (not fatal), and Complete/Done settle.
func TestSenderReceiverMidTransferCutover(t *testing.T) {
	keys, err := DeriveTransferKeys(loopbackMaster())
	if err != nil {
		t.Fatal(err)
	}
	data := testData(128_000, 7)
	const blockSize = 2048
	const cutAfterBytes = blockSize // trigger after block 0 is committed
	sink := &MemorySink{}
	link := newCutoverLink()

	var receiver *Receiver
	sender := NewSender(SenderOptions{
		File:        BytesSource(data, FileMeta{Name: "f", Size: int64(len(data)), Mime: "application/octet-stream", LastModified: 1}, 0),
		Send:        func(f []byte) error { return link.route(dirS2R, f) },
		SendDir:     keys.O2J,
		RecvDir:     keys.J2O,
		BlockSize:   blockSize,
		FrameSize:   512,
		Window:      4,
		AckTimeout:  5 * time.Second,
		MaxRetries:  10,
		DoneTimeout: 5 * time.Second,
	})
	// The cutover must not run inside the receiver's Handle (OnProgress holds handleMu, and
	// TransportChanged re-enters it), so OnProgress only signals a dedicated switch goroutine.
	cutRequested := make(chan struct{}, 1)
	cutDone := make(chan struct{})
	var cutOnce sync.Once
	doCut := func() {
		cutOnce.Do(func() {
			link.switchPath()
			receiver.TransportChanged()
			sender.TransportChanged()
			close(cutDone)
		})
	}
	receiver = NewReceiver(ReceiverOptions{
		Send:    func(f []byte) error { return link.route(dirR2S, f) },
		SendDir: keys.J2O,
		RecvDir: keys.O2J,
		Sink:    sink,
		OnProgress: func(acked int64) {
			if acked >= cutAfterBytes {
				select {
				case cutRequested <- struct{}{}:
				default:
				}
			}
		},
	})
	go func() {
		for {
			select {
			case <-cutRequested:
				doCut()
				select {
				case <-cutDone:
					return
				default:
				}
			case <-cutDone:
				return
			}
		}
	}()

	// Capture a signed old-path data frame for the post-cutover replay probe.
	var replayProbe atomic.Pointer[[]byte]
	var stop int32
	drain := func(ch <-chan []byte, fn func([]byte), captureReplay bool) {
		for {
			select {
			case f := <-ch:
				if captureReplay && replayProbe.Load() == nil && len(f) > 0 && f[9] == FrameBlockData {
					g := append([]byte(nil), f...)
					replayProbe.Store(&g)
				}
				fn(f)
			default:
				if atomic.LoadInt32(&stop) == 1 {
					return
				}
				time.Sleep(time.Millisecond)
			}
		}
	}

	// Old-path side only delivers until the cut; afterwards the stale tail is dropped, exactly
	// what a torn-down direct transport does. New-path drains run for the whole transfer.
	go drain(link.oldS2R, func(f []byte) {
		select {
		case <-cutDone:
			return
		default:
		}
		receiver.Handle(f)
	}, true)
	go drain(link.oldR2S, sender.Handle, false)
	go drain(link.newS2R, receiver.Handle, false)
	go drain(link.newR2S, sender.Handle, false)

	runCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	runErrCh := make(chan error, 1)
	go func() { _, e := sender.Run(runCtx); runErrCh <- e }()
	recvResCh := make(chan ReceiveResult, 1)
	recvErrCh := make(chan error, 1)
	go func() { r, e := receiver.Wait(runCtx); recvResCh <- r; recvErrCh <- e }()

	// After the cutover, inject one old-path frame as a replay probe: the receiver must drop it
	// (an already-consumed counter) rather than aborting the transfer as an integrity violation.
	go func() {
		<-cutDone
		time.Sleep(10 * time.Millisecond)
		if p := replayProbe.Load(); p != nil {
			receiver.Handle(append([]byte(nil), (*p)...))
		}
	}()

	var runErr error
	select {
	case runErr = <-runErrCh:
	case <-time.After(15 * time.Second):
		t.Fatal("sender.Run did not return within deadline")
	}
	recvRes := <-recvResCh
	recvErr := <-recvErrCh
	atomic.StoreInt32(&stop, 1)

	if runErr != nil {
		t.Fatalf("sender after mid-transfer cutover: %v", runErr)
	}
	if recvErr != nil {
		t.Fatalf("receiver after mid-transfer cutover: %v", recvErr)
	}
	if !bytes.Equal(sink.Bytes(), data) {
		t.Fatal("received bytes differ from source after mid-transfer cutover")
	}
	if len(recvRes.Digests) == 0 || recvRes.Digests[0] == "" {
		t.Fatal("receiver produced no digest after cutover")
	}
}
