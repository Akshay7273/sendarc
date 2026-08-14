package wire

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
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
//
// Harness contract (mirrors the production supervisor/adaptive boundary): the cutover is atomic
// from the transfer engine's perspective. The receiver learns the path changed — Receiver.
// TransportChanged — before the first frame from the new generation is delivered to
// Receiver.Handle. Production enforces this at the supervisor/path-generation boundary, not
// inside the transports: when a new path activates, the old underlying path is closed, and stale
// old-generation delivery is suppressed because the old entry is no longer eligible for delivery
// (Supervisor.promoteOnData refuses frames from non-active entries), while the switch callback
// (onSwitch → TransportChanged) runs synchronously to completion before the first new-generation
// frame reaches Handle. Closing DataConn alone is not the rejection mechanism: pump selects
// between its inbox and the done channel, so an already-buffered frame can still surface after
// shutdown. A cutover that instead lets old-path tail frames re-enter the engine after the switch
// (or delivers new-path frames before TransportChanged) produces the integrity failure
// "new block before block_hash": a stale old-path block start grabs blockBuf, then the first
// legitimate new-path retransmission hits the "new block before block_hash" guard. That
// interleaving cannot occur in production and must not occur in the harness.

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
//
// The cutover itself is serialized against receiver-bound delivery with recvMu, so the switch,
// Receiver.TransportChanged, and Sender.TransportChanged are atomic with respect to every
// receiver.Handle call. The old-path drain drops everything queued after the cut, modeling what
// the transfer engine observes after production's supervisor filtering: once the switch happens,
// stale old-generation frames are never delivered to the engine. Without this, the harness races
// the switch goroutine against the delivery drains and intermittently delivers an old-path tail
// frame after TransportChanged (or a new-path frame before it), which aborts the receiver with
// "new block before block_hash" — an impossible ordering in production (reproduced under -race
// on pristine main; see TestSenderReceiverMidTransferCutoverDeterministic for the deterministic
// regression).
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
	// recvMu serializes every receiver-bound delivery with the cutover, mirroring the production
	// supervisor: the receiver learns the path changed before any new-generation frame is
	// delivered, and the old path's queued tail is dropped at the switch.
	var recvMu sync.Mutex
	// The cutover must not run inside the receiver's Handle (OnProgress holds handleMu, and
	// TransportChanged re-enters it), so OnProgress only signals a dedicated switch goroutine.
	cutRequested := make(chan struct{}, 1)
	cutDone := make(chan struct{})
	var cutOnce sync.Once
	doCut := func() {
		cutOnce.Do(func() {
			recvMu.Lock()
			defer recvMu.Unlock()
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
	drain := func(ch <-chan []byte, fn func([]byte)) {
		for {
			select {
			case f := <-ch:
				fn(f)
			default:
				if atomic.LoadInt32(&stop) == 1 {
					return
				}
				time.Sleep(time.Millisecond)
			}
		}
	}

	// Old-path side only delivers until the cut; afterwards its queued tail is dropped, modeling
	// the supervisor's filtering of stale old-generation frames (the old entry is closed and no
	// longer eligible for delivery). New-path drains run for the whole transfer.
	go drain(link.oldS2R, func(f []byte) {
		recvMu.Lock()
		defer recvMu.Unlock()
		select {
		case <-cutDone:
			return // stale old-generation tail: filtered out, never reaches the engine
		default:
		}
		if replayProbe.Load() == nil && len(f) > 0 && f[9] == FrameBlockData {
			g := append([]byte(nil), f...)
			replayProbe.Store(&g)
		}
		receiver.Handle(f)
	})
	go drain(link.oldR2S, sender.Handle)
	go drain(link.newS2R, func(f []byte) {
		recvMu.Lock()
		defer recvMu.Unlock()
		receiver.Handle(f)
	})
	go drain(link.newR2S, sender.Handle)

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
			recvMu.Lock()
			receiver.Handle(append([]byte(nil), (*p)...))
			recvMu.Unlock()
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

// TestSenderReceiverMidTransferCutoverDeterministic drives the exact mid-transfer cutover
// boundary by hand — no goroutine timing, sleeps, or OnProgress scheduling — as the deterministic
// regression for the flake reproduced on pristine main (receiver abort "new block before
// block_hash", ~15-20% under -race before this harness contract was enforced). Each step below is
// a barrier: the test goroutine feeds Receiver.Handle itself in the exact production order.
//
//  1. Old path: manifest + block 0 complete → acked.
//  2. Old path: block 1's first frame only — a partial block, no block_hash yet.
//  3. Cutover, atomically: switch path, Receiver.TransportChanged, Sender.TransportChanged.
//  4. The old-path tail (block 1 remainder + blocks 2-4, all still queued) is dropped, modeling
//     the supervisor's filtering of stale old-generation frames after the switch.
//  5. The first legitimate new-path retransmission (fresh AEAD counter) MUST be accepted — the
//     receiver discards the old partial block and starts fresh, instead of aborting with
//     "new block before block_hash".
//  6. A stale old-path frame injected mid-flight is replay-rejected below the consumed counter
//     and cannot corrupt the new state.
//  7. The transfer converges byte-identically; no counter reuse; ACK progress never moves
//     backwards; no block is written twice.
func TestSenderReceiverMidTransferCutoverDeterministic(t *testing.T) {
	keys, err := DeriveTransferKeys(loopbackMaster())
	if err != nil {
		t.Fatal(err)
	}
	data := testData(128_000, 7)
	const blockSize, frameSize = 2048, 512
	sink := &MemorySink{}

	var path atomic.Int32 // cutPathOld until the cutover, then cutPathNew
	var maxOldCtr, maxNewCtr uint64
	type outbound struct {
		frame   []byte
		newPath bool
	}
	outCh := make(chan outbound, 4096)
	ackCh := make(chan []byte, 4096)

	sendS2R := func(f []byte) error {
		frame := append([]byte(nil), f...)
		newPath := path.Load() == cutPathNew
		ctr := binary.BigEndian.Uint64(frame[:8])
		if newPath {
			if ctr > maxNewCtr {
				maxNewCtr = ctr
			}
		} else if ctr > maxOldCtr {
			maxOldCtr = ctr
		}
		outCh <- outbound{frame: frame, newPath: newPath}
		return nil
	}
	sendR2S := func(f []byte) error { ackCh <- append([]byte(nil), f...); return nil }

	var progressMu sync.Mutex
	var progress []int64
	onProgress := func(acked int64) {
		progressMu.Lock()
		progress = append(progress, acked)
		progressMu.Unlock()
	}

	sender := NewSender(SenderOptions{
		File:        BytesSource(data, FileMeta{Name: "f", Size: int64(len(data)), Mime: "application/octet-stream", LastModified: 1}, 0),
		Send:        sendS2R,
		SendDir:     keys.O2J,
		RecvDir:     keys.J2O,
		BlockSize:   blockSize,
		FrameSize:   frameSize,
		Window:      4,
		AckTimeout:  -1, // no timer-driven retries: the only retransmission is the cutover's
		MaxRetries:  10,
		DoneTimeout: 5 * time.Second,
	})
	receiver := NewReceiver(ReceiverOptions{
		Send:       sendR2S,
		SendDir:    keys.J2O,
		RecvDir:    keys.O2J,
		Sink:       sink,
		OnProgress: onProgress,
	})

	runCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sendErrCh := make(chan error, 1)
	go func() { _, e := sender.Run(runCtx); sendErrCh <- e }()
	recvErrCh := make(chan error, 1)
	go func() { _, e := receiver.Wait(runCtx); recvErrCh <- e }()

	// pull takes the next sender frame and asserts it was emitted on the expected path.
	pull := func(wantNew bool) outbound {
		select {
		case f := <-outCh:
			if f.newPath != wantNew {
				t.Fatalf("sender frame on new-path=%v, want %v", f.newPath, wantNew)
			}
			return f
		case e := <-sendErrCh:
			t.Fatalf("sender settled before the cutover: %v", e)
		case e := <-recvErrCh:
			t.Fatalf("receiver aborted before the cutover: %v", e)
		case <-time.After(15 * time.Second):
			t.Fatal("timed out waiting for a sender frame")
		}
		return outbound{}
	}
	feed := func(frame []byte) {
		receiver.Handle(frame)
		select {
		case e := <-recvErrCh:
			t.Fatalf("receiver aborted: %v", e)
		default:
		}
	}
	feedAcks := func() {
		for {
			select {
			case a := <-ackCh:
				sender.Handle(a)
			default:
				return
			}
		}
	}

	// 1. Manifest + block 0, fully assembled and committed on the old path.
	feed(pull(false).frame) // manifest
	for i := 0; i < 4; i++ {
		feed(pull(false).frame) // block 0 data frames
	}
	feed(pull(false).frame) // block 0 hash → commit → ack
	feedAcks()

	// 2. Begin block 1 on the old path: first frame only, no block_hash yet.
	first := pull(false)
	feed(first.frame)
	h, err := decodeFrameHeader(first.frame[8:24])
	if err != nil || h.BlockIdx != 1 || h.FrameOff != 0 {
		t.Fatalf("first block-1 frame = %+v, err %v; want block 1 at frame offset 0", h, err)
	}
	// Hold one old-path tail frame to inject later as a stale replay.
	stale := pull(false)
	if stale.newPath {
		t.Fatal("stale capture must come from the old path")
	}

	// 3. Cutover, atomically: the path switches and both engines learn it BEFORE the first
	//    new-generation frame is delivered — the production supervisor contract. The remaining
	//    old-path queue is the stale old-generation tail and is never fed.
	path.Store(cutPathNew)
	receiver.TransportChanged()
	sender.TransportChanged()

	// 4-7. Drain the sender: drop the old-path tail, deliver new-path frames, keep acks flowing,
	//      until both sides settle.
	droppedOld := 1 // the stale frame captured above
	firstNew := false
	var sendErr, recvErr error
	var sendDone, recvDone bool
	for !sendDone || !recvDone {
		select {
		case f := <-outCh:
			if !f.newPath {
				droppedOld++
				continue
			}
			if !firstNew {
				firstNew = true
				// The first legitimate new-path retransmission must start a fresh block:
				// TransportChanged already discarded the old partial block.
				feed(f.frame)
				// A stale old-path frame arriving after the switch sits below the consumed
				// counter and must be replay-rejected, never corrupting the new state.
				receiver.Handle(stale.frame)
				select {
				case e := <-recvErrCh:
					t.Fatalf("stale old-path frame corrupted the receiver: %v", e)
				default:
				}
				continue
			}
			feed(f.frame)
		case a := <-ackCh:
			sender.Handle(a)
		case e := <-sendErrCh:
			sendDone = true
			sendErr = e
		case e := <-recvErrCh:
			recvDone = true
			recvErr = e
		case <-time.After(30 * time.Second):
			t.Fatal("deterministic mid-transfer cutover stalled")
		}
	}

	if sendErr != nil {
		t.Fatalf("sender after deterministic mid-transfer cutover: %v", sendErr)
	}
	if recvErr != nil {
		t.Fatalf("receiver after deterministic mid-transfer cutover: %v", recvErr)
	}
	if !firstNew {
		t.Fatal("no new-path frame was ever delivered after the cutover")
	}
	if droppedOld == 0 {
		t.Fatal("expected the old-path tail to be present and dropped at the cutover")
	}
	if !bytes.Equal(sink.Bytes(), data) {
		t.Fatal("received bytes differ from source after deterministic mid-transfer cutover")
	}
	// Fresh AEAD counters: every new-path frame is sealed above every old-path frame, so no
	// counter is reused across the cutover and late old-path frames are replay-rejected.
	if maxNewCtr <= maxOldCtr {
		t.Fatalf("new-path retransmission counters (max %d) must exceed old-path counters (max %d)",
			maxNewCtr, maxOldCtr)
	}
	// ACK progress never moves backwards.
	progressMu.Lock()
	defer progressMu.Unlock()
	for i := 1; i < len(progress); i++ {
		if progress[i] < progress[i-1] {
			t.Fatalf("progress went backwards: %d after %d", progress[i], progress[i-1])
		}
	}
	// Every committed block is written exactly once (the receiver's high-water mark advances
	// monotonically; a duplicate commit would overlap the same sink offset).
	seen := make(map[int64]bool)
	for _, c := range sink.chunks {
		if seen[c.offset] {
			t.Fatalf("block written twice at offset %d", c.offset)
		}
		seen[c.offset] = true
	}
	if len(seen) != (len(data)+blockSize-1)/blockSize {
		t.Fatalf("sink wrote %d blocks, want %d", len(seen), (len(data)+blockSize-1)/blockSize)
	}
}

// TestReceiverSamePathNewBlockBeforeHashFails pins the integrity guard the cutover path must not
// weaken: on ONE unchanged ordered path, starting a second block before the first block's
// block_hash is a protocol violation, not a cutover, and must still fail closed.
func TestReceiverSamePathNewBlockBeforeHashFails(t *testing.T) {
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	data := seq(16)
	const blockSize, frameSize = 8, 4
	sf := newSenderFrames(t, keys)
	sf.ctrl(NewManifest([]FileEntry{{
		Idx: 0, Name: "f", Size: 16, BlockSize: blockSize, Blocks: 2, FileDigest: hexSHA256(data),
	}}, 16))
	// Block 0 begins but is not finished: only its first frame, no block_hash yet.
	sf.push(FrameHeaderInput{Version: FrameVersion, Type: FrameBlockData, BlockIdx: 0, FrameOff: 0}, data[0:4])
	// A second block start on the same ordered path before block 0's hash.
	sf.push(FrameHeaderInput{Version: FrameVersion, Type: FrameBlockData, Flags: FrameFlagLastInBlock, BlockIdx: 1, FrameOff: 0}, data[8:12])

	sink := &MemorySink{}
	var back outbox
	r := NewReceiver(ReceiverOptions{
		Send: back.push, SendDir: keys.J2O, RecvDir: keys.O2J, Sink: sink,
	})
	for _, f := range sf.frames {
		r.Handle(f)
	}
	_, err = r.Wait(context.Background())
	if err == nil || !strings.Contains(err.Error(), "new block before block_hash") {
		t.Fatalf("Wait error = %v, want integrity 'new block before block_hash'", err)
	}
	if sink.AbortReason() != "integrity" {
		t.Errorf("sink abort reason = %q, want integrity", sink.AbortReason())
	}
}
