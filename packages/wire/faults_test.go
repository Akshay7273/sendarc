package wire

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Deterministic fault-injection harness (plan §4.2, SB-1120..1128). A faultLink
// sits between each side's Send and the peer's Handle and mutates frames
// according to a per-direction, per-frame-type script keyed on occurrence, or —
// with a seeded RNG — at random. The wire engine treats its transport as
// reliable and ordered: any loss, reorder, or corruption of the sealed frame
// stream is a protocol violation and must fail closed (integrity abort), never
// corrupt or commit partial data. Every failure path must terminate both sides
// cleanly; the harness enforces a deadline so a stall surfaces as a test
// failure instead of a hang.

type faultAction uint8

const (
	fPass      faultAction = iota // deliver untouched
	fDrop                         // discard the frame
	fDuplicate                    // deliver twice
	fReorder                      // hold it, deliver after the next frame
	fLate                         // deliver after 300 ms (slow but alive peer)
	fTruncate                     // deliver the first half only (broken frame)
	fCorrupt                      // flip one payload byte
	fClose                        // drop this frame and kill both paths afterwards
)

// faultScript maps direction (0 = sender→receiver, 1 = receiver→sender) then
// frame type to the actions applied to successive occurrences; occurrences past
// the list pass through untouched.
type faultScript map[int]map[uint8][]faultAction

func (s faultScript) at(dir int, typ uint8, actions ...faultAction) faultScript {
	if s[dir] == nil {
		s[dir] = map[uint8][]faultAction{}
	}
	s[dir][typ] = actions
	return s
}

const (
	dirS2R = 0
	dirR2S = 1
)

// faultLink wraps one bidirectional frame path. A nil script and nil rng pass
// everything through untouched. Closing a path never closes the channels (a
// send on a closed channel would panic); it sets a flag the drainers poll, and
// frames sent after the flag are dropped — the same semantics as a dead peer.
type faultLink struct {
	s2r, r2s chan []byte
	script   faultScript
	rng      *rand.Rand

	counts     [2]map[uint8]int
	delayed    [2][]byte
	closed     atomic.Bool
	r2sSent    atomic.Uint64 // sealed receiver frames delivered (for NACK injection)
	benignOnly bool          // randomAction keeps only recoverable faults (drop/dup/late)
}

func newFaultLink(script faultScript, rng *rand.Rand) *faultLink {
	return &faultLink{
		s2r:    make(chan []byte, 4096),
		r2s:    make(chan []byte, 4096),
		script: script,
		rng:    rng,
		counts: [2]map[uint8]int{{}, {}},
	}
}

func (l *faultLink) send(dir int, frame []byte) error {
	// Sealed frames are counter(8) || header(16) || ciphertext || tag, so the
	// type byte lives at offset 9.
	typ := frame[9]
	occ := l.counts[dir][typ]
	l.counts[dir][typ] = occ + 1

	var act = fPass
	if l.rng != nil {
		act = l.randomAction(dir, typ)
	} else if acts := l.script[dir][typ]; occ < len(acts) {
		act = acts[occ]
	}
	switch act {
	case fDrop:
		return nil
	case fClose:
		l.close()
		return nil
	case fDuplicate:
		l.deliver(dir, frame)
		l.deliver(dir, frame)
		return nil
	case fReorder:
		// Hold it until the next write so it lands after that frame.
		if l.delayed[dir] == nil {
			l.delayed[dir] = append([]byte(nil), frame...)
			return nil
		}
		l.deliver(dir, frame)
		return nil
	case fLate:
		g := append([]byte(nil), frame...)
		time.AfterFunc(300*time.Millisecond, func() { l.deliver(dir, g) })
		return nil
	case fTruncate:
		l.deliver(dir, frame[:len(frame)/2])
		return nil
	case fCorrupt:
		g := append([]byte(nil), frame...)
		g[len(g)-1] ^= 0x40
		l.deliver(dir, g)
		return nil
	default:
		l.deliver(dir, frame)
		return nil
	}
}

func (l *faultLink) deliver(dir int, frame []byte) {
	if l.closed.Load() {
		return
	}
	l.sendToChannel(dir, frame)
	if l.delayed[dir] != nil {
		l.sendToChannel(dir, l.delayed[dir])
		l.delayed[dir] = nil
	}
}

func (l *faultLink) sendToChannel(dir int, frame []byte) {
	ch := l.s2r
	if dir == dirR2S {
		ch = l.r2s
	}
	if dir == dirR2S {
		l.r2sSent.Add(1)
	}
	ch <- append([]byte(nil), frame...)
}

// close kills both paths (a dead peer). Held frames are delivered first; the
// flag is set afterwards so the drainers finish those frames then stop.
func (l *faultLink) close() {
	for dir := 0; dir < 2; dir++ {
		if l.delayed[dir] != nil {
			l.sendToChannel(dir, l.delayed[dir])
			l.delayed[dir] = nil
		}
	}
	l.closed.Store(true)
}

func (l *faultLink) isClosed() bool { return l.closed.Load() }

// randomAction draws a fault from a fixed probability table so seeds stay
// comparable across runs.
func (l *faultLink) randomAction(_ int, typ uint8) faultAction {
	switch {
	case l.rng.Float64() < 0.02:
		return fDrop
	case l.rng.Float64() < 0.01:
		return fDuplicate
	case !l.benignOnly && l.rng.Float64() < 0.015:
		return fReorder
	case l.rng.Float64() < 0.01:
		return fLate
	case !l.benignOnly && l.rng.Float64() < 0.008 && typ == FrameBlockData:
		return fTruncate
	case !l.benignOnly && l.rng.Float64() < 0.008 && typ == FrameBlockData:
		return fCorrupt
	case !l.benignOnly && l.rng.Float64() < 0.004:
		return fClose
	default:
		return fPass
	}
}

// faultResult mirrors loopbackResult and records whether the receiver settled
// on its own (versus being cut off by the harness deadline).
type faultResult struct {
	runErr      error
	recvErr     error
	sink        *MemorySink
	recvSettled bool
	recvDigest  string
}

type faultRunOptions struct {
	ackTimeout  time.Duration
	doneTimeout time.Duration
	maxRetries  int
	deadline    time.Duration
	source      FileSource
	sink        Sink
	destination Destination
	benignOnly  bool
	// cutover fires on the sender once the manifest frame has been attempted on
	// the link (dropped or not), simulating a path change mid-transfer.
	cutover func(link *faultLink, sender *Sender)
}

// runFaultLoopback runs one transfer through the fault link and enforces a
// deadline so a stall fails the test instead of hanging it.
func runFaultLoopback(t *testing.T, data []byte, blockSize, frameSize, window int,
	script faultScript, rng *rand.Rand, opts faultRunOptions) faultResult {
	t.Helper()
	keys, err := DeriveTransferKeys(loopbackMaster())
	if err != nil {
		t.Fatal(err)
	}
	link := newFaultLink(script, rng)
	link.benignOnly = opts.benignOnly
	defaultSink := &MemorySink{}
	userSink := opts.sink
	if userSink == nil {
		userSink = defaultSink
	}
	dest := opts.destination
	if dest == nil {
		dest = SingleSinkDestination(userSink)
	}
	source := opts.source
	if source == nil {
		source = BytesSource(data, FileMeta{Name: "f", Size: int64(len(data)), Mime: "application/octet-stream", LastModified: 1}, 0)
	}

	ackTimeout := opts.ackTimeout
	if ackTimeout == 0 {
		ackTimeout = 250 * time.Millisecond
	}
	doneTimeout := opts.doneTimeout
	if doneTimeout == 0 {
		doneTimeout = 1500 * time.Millisecond
	}
	maxRetries := opts.maxRetries
	if maxRetries == 0 {
		maxRetries = 5
	}
	deadline := opts.deadline
	if deadline == 0 {
		deadline = 15 * time.Second
	}

	sender := NewSender(SenderOptions{
		File:        source,
		Send:        func(f []byte) error { return link.send(dirS2R, f) },
		SendDir:     keys.O2J,
		RecvDir:     keys.J2O,
		BlockSize:   blockSize,
		FrameSize:   frameSize,
		Window:      window,
		AckTimeout:  ackTimeout,
		MaxRetries:  maxRetries,
		DoneTimeout: doneTimeout,
	})
	receiver := NewReceiver(ReceiverOptions{
		Send:        func(f []byte) error { return link.send(dirR2S, f) },
		SendDir:     keys.J2O,
		RecvDir:     keys.O2J,
		Destination: dest,
	})

	go func() {
		for {
			if link.isClosed() {
				return
			}
			f, ok := <-link.s2r
			if !ok {
				return
			}
			receiver.Handle(f)
		}
	}()
	go func() {
		for {
			if link.isClosed() {
				return
			}
			f, ok := <-link.r2s
			if !ok {
				return
			}
			sender.Handle(f)
		}
	}()
	if opts.cutover != nil {
		go func() {
			for link.counts[dirS2R][FrameManifest] == 0 && !link.isClosed() {
				time.Sleep(2 * time.Millisecond)
			}
			opts.cutover(link, sender)
		}()
	}

	recvCtx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	runErrCh := make(chan error, 1)
	go func() {
		_, e := sender.Run(context.Background())
		runErrCh <- e
	}()

	// The receiver aborts with FailCanceled (not a wrapped context error) when
	// the harness deadline fires, so "settled" must mean the receiver actually
	// completed on its own, not merely that the deadline fired.
	recvRes, recvErr := receiver.Wait(recvCtx)
	recvSettled := recvErr == nil
	var runErr error
	select {
	case runErr = <-runErrCh:
	case <-time.After(deadline):
		t.Fatalf("sender.Run did not return within the deadline (recvErr=%v)", recvErr)
	}
	var recvDigest string
	if recvErr == nil {
		recvDigest = recvRes.Digest
	}
	return faultResult{runErr: runErr, recvErr: recvErr, sink: defaultSink, recvSettled: recvSettled, recvDigest: recvDigest}
}

func (r faultResult) wantSuccess(t *testing.T, data []byte) {
	t.Helper()
	if r.runErr != nil {
		t.Fatalf("sender: %v", r.runErr)
	}
	if r.recvErr != nil {
		t.Fatalf("receiver: %v", r.recvErr)
	}
	if string(r.sink.Bytes()) != string(data) {
		t.Fatal("received bytes differ from source")
	}
	if !r.sink.IsClosed() {
		t.Fatal("sink was not closed on success")
	}
	want := sha256.Sum256(data)
	if got := r.recvDigest; got != hex.EncodeToString(want[:]) {
		t.Fatalf("digest mismatch: got %s", got)
	}
}

// wantCleanAbort asserts the transfer failed on at least one side and the sink
// was never committed.
func (r faultResult) wantCleanAbort(t *testing.T) {
	t.Helper()
	if r.runErr == nil && r.recvErr == nil {
		t.Fatal("transfer settled cleanly; expected a failure on at least one side")
	}
	if r.sink.IsClosed() {
		t.Error("sink was closed despite a failed transfer")
	}
}

func testData(n int, mul byte) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte((i*int(mul) + 7) & 0xff)
	}
	return data
}

// --- SB-1120: the shim itself ---

// TestFaultShimPassesEverything: an empty script must behave exactly like the
// plain loopback.
func TestFaultShimPassesEverything(t *testing.T) {
	res := runFaultLoopback(t, testData(100_000, 131), 1024, 256, 4, faultScript{}, nil, faultRunOptions{})
	res.wantSuccess(t, testData(100_000, 131))
}

// TestFaultDuplicateDataIsIgnored: a duplicated data frame is a replay; the
// receiver drops it and the transfer completes.
func TestFaultDuplicateDataIsIgnored(t *testing.T) {
	data := testData(50_000, 53)
	script := faultScript{}.
		at(dirS2R, FrameBlockData, fPass, fDuplicate)
	res := runFaultLoopback(t, data, 1024, 256, 4, script, nil, faultRunOptions{})
	res.wantSuccess(t, data)
}

// TestFaultDuplicateAckIsIgnored: a duplicated ACK must not corrupt sender
// accounting.
func TestFaultDuplicateAckIsIgnored(t *testing.T) {
	data := testData(50_000, 11)
	script := faultScript{}.
		at(dirR2S, FrameAck, fDuplicate)
	res := runFaultLoopback(t, data, 1024, 256, 4, script, nil, faultRunOptions{})
	res.wantSuccess(t, data)
}

// TestFaultRecoversFromLostAck: a lost ACK is recovered by the acknowledgement
// timeout retransmitting the block.
func TestFaultRecoversFromLostAck(t *testing.T) {
	data := testData(100_000, 7)
	script := faultScript{}.
		at(dirR2S, FrameAck, fDrop)
	res := runFaultLoopback(t, data, 1024, 256, 4, script, nil,
		faultRunOptions{ackTimeout: 120 * time.Millisecond, maxRetries: 5})
	res.wantSuccess(t, data)
}

// TestFaultLateDoneStillSucceeds: a Done that arrives 300 ms late (slow but
// alive receiver) completes the transfer within the deadline.
func TestFaultLateDoneStillSucceeds(t *testing.T) {
	data := testData(50_000, 29)
	script := faultScript{}.
		at(dirR2S, FrameDone, fLate)
	res := runFaultLoopback(t, data, 1024, 256, 4, script, nil,
		faultRunOptions{doneTimeout: 5 * time.Second})
	res.wantSuccess(t, data)
}

// TestFaultStaleNackIsHarmless (SB-1124): a NACK for an already-acknowledged
// block is injected directly into the sender's inbound stream at the exact next
// counter; the sender requeues and resends, the receiver ignores the replay,
// and the transfer completes.
func TestFaultStaleNackIsHarmless(t *testing.T) {
	data := testData(100_000, 31)
	keys, err := DeriveTransferKeys(loopbackMaster())
	if err != nil {
		t.Fatal(err)
	}
	link := newFaultLink(faultScript{}, nil)
	sink := &MemorySink{}
	sender := NewSender(SenderOptions{
		File:        BytesSource(data, FileMeta{Name: "f", Size: int64(len(data)), Mime: "application/octet-stream", LastModified: 1}, 0),
		Send:        func(f []byte) error { return link.send(dirS2R, f) },
		SendDir:     keys.O2J,
		RecvDir:     keys.J2O,
		BlockSize:   1024,
		FrameSize:   256,
		Window:      4,
		AckTimeout:  120 * time.Millisecond,
		MaxRetries:  5,
		DoneTimeout: 5 * time.Second,
	})
	receiver := NewReceiver(ReceiverOptions{
		Send:    func(f []byte) error { return link.send(dirR2S, f) },
		SendDir: keys.J2O,
		RecvDir: keys.O2J,
		Sink:    sink,
	})
	go func() {
		for !link.isClosed() {
			f, ok := <-link.s2r
			if !ok {
				return
			}
			receiver.Handle(f)
		}
	}()
	go func() {
		for !link.isClosed() {
			f, ok := <-link.r2s
			if !ok {
				return
			}
			sender.Handle(f)
			// After the very first inbound control (an ACK for block 0), inject
			// a stale NACK for block 0 sealed under the next expected counter.
			if link.r2sSent.Load() == 1 {
				payload, err := EncodeControl(NewNack(0, 0, NackMissing))
				if err != nil {
					t.Errorf("encode nack: %v", err)
					return
				}
				frame, err := Seal(keys.J2O, 1, FrameHeaderInput{Version: FrameVersion, Type: FrameNack}, payload)
				if err != nil {
					t.Errorf("seal nack: %v", err)
					return
				}
				sender.Handle(frame)
			}
		}
	}()

	recvCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	runErrCh := make(chan error, 1)
	go func() { _, e := sender.Run(context.Background()); runErrCh <- e }()
	_, recvErr := receiver.Wait(recvCtx)
	var runErr error
	select {
	case runErr = <-runErrCh:
	case <-time.After(15 * time.Second):
		t.Fatal("sender did not return")
	}
	if runErr != nil || recvErr != nil {
		t.Fatalf("send=%v receive=%v", runErr, recvErr)
	}
	if string(sink.Bytes()) != string(data) {
		t.Fatal("bytes differ")
	}
}

// TestFaultDuplicateResumeStateIsIdempotent (SB-1124): a duplicated
// resume_state (receiver → sender) is applied once; the resumed transfer
// completes.
func TestFaultDuplicateResumeStateIsIdempotent(t *testing.T) {
	data := testData(80_000, 17)
	keys, err := DeriveTransferKeys(loopbackMaster())
	if err != nil {
		t.Fatal(err)
	}
	script := faultScript{}.
		at(dirR2S, FrameResumeState, fDuplicate)
	link := newFaultLink(script, nil)
	sink := &MemorySink{}
	prefix := 5 * 1024
	_ = sink.Write(0, data[:prefix])
	seed := NewSHA256Digest()
	seed.Update(data[:prefix])
	sender := NewSender(SenderOptions{
		File:        BytesSource(data, FileMeta{Name: "f", Size: int64(len(data)), Mime: "application/octet-stream", LastModified: 1}, 0),
		Send:        func(f []byte) error { return link.send(dirS2R, f) },
		SendDir:     keys.O2J,
		RecvDir:     keys.J2O,
		BlockSize:   1024,
		FrameSize:   256,
		Window:      4,
		AckTimeout:  250 * time.Millisecond,
		MaxRetries:  5,
		DoneTimeout: 5 * time.Second,
		TransferID:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	receiver := NewReceiver(ReceiverOptions{
		Send:    func(f []byte) error { return link.send(dirR2S, f) },
		SendDir: keys.J2O,
		RecvDir: keys.O2J,
		Sink:    sink,
		Resume: &ReceiverResume{
			TransferID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Files:      map[int]ResumeFileProgress{0: {HaveBlocks: 5, SeedDigest: seed}},
		},
	})
	go func() {
		for !link.isClosed() {
			f, ok := <-link.s2r
			if !ok {
				return
			}
			receiver.Handle(f)
		}
	}()
	go func() {
		for !link.isClosed() {
			f, ok := <-link.r2s
			if !ok {
				return
			}
			sender.Handle(f)
		}
	}()
	recvCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	runErrCh := make(chan error, 1)
	go func() { _, e := sender.Run(context.Background()); runErrCh <- e }()
	_, recvErr := receiver.Wait(recvCtx)
	var runErr error
	select {
	case runErr = <-runErrCh:
	case <-time.After(15 * time.Second):
		t.Fatal("sender did not return")
	}
	if runErr != nil || recvErr != nil {
		t.Fatalf("send=%v receive=%v", runErr, recvErr)
	}
	if string(sink.Bytes()) != string(data) {
		t.Fatal("resumed transfer did not reassemble the full file")
	}
}

// --- SB-1121: transport closure at every meaningful phase ---

// TestFaultDroppedDataFailsClosed: the transport is reliable and ordered; a
// dropped data frame is a protocol violation and must abort with integrity,
// never commit the sink.
func TestFaultDroppedDataFailsClosed(t *testing.T) {
	data := testData(50_000, 19)
	script := faultScript{}.
		at(dirS2R, FrameBlockData, fDrop)
	res := runFaultLoopback(t, data, 1024, 256, 4, script, nil, faultRunOptions{})
	res.wantCleanAbort(t)
}

// TestFaultReorderedFrameFailsClosed: reordering breaks the sequential counter
// stream; the transfer must abort with integrity, never commit.
func TestFaultReorderedFrameFailsClosed(t *testing.T) {
	data := testData(50_000, 13)
	script := faultScript{}.
		at(dirS2R, FrameBlockData, fReorder)
	res := runFaultLoopback(t, data, 1024, 256, 4, script, nil, faultRunOptions{})
	res.wantCleanAbort(t)
}

// TestFaultTruncatedDataFrameAbortsWithIntegrity: a half-delivered data frame
// must abort with integrity, never commit the sink.
func TestFaultTruncatedDataFrameAbortsWithIntegrity(t *testing.T) {
	data := testData(50_000, 23)
	script := faultScript{}.
		at(dirS2R, FrameBlockData, fPass, fTruncate)
	res := runFaultLoopback(t, data, 1024, 256, 4, script, nil, faultRunOptions{})
	res.wantCleanAbort(t)
}

// TestFaultCorruptedFrameAbortsWithIntegrity: a flipped payload byte must abort
// with integrity, never commit the sink.
func TestFaultCorruptedFrameAbortsWithIntegrity(t *testing.T) {
	data := testData(50_000, 43)
	script := faultScript{}.
		at(dirS2R, FrameBlockData, fPass, fCorrupt)
	res := runFaultLoopback(t, data, 1024, 256, 4, script, nil, faultRunOptions{})
	res.wantCleanAbort(t)
}

// TestFaultCloseMidTransferExhaustsRetries: the peer dies after the manifest;
// the sender exhausts its retries with a classified failure, the receiver is
// cut off by the harness deadline (peer-death detection is the transport's
// job), and the sink is never committed. No hang.
func TestFaultCloseMidTransferExhaustsRetries(t *testing.T) {
	data := testData(200_000, 37)
	script := faultScript{}.
		at(dirS2R, FrameBlockHash, fPass, fPass, fPass, fPass, fClose)
	res := runFaultLoopback(t, data, 1024, 256, 4, script, nil,
		faultRunOptions{ackTimeout: 120 * time.Millisecond, maxRetries: 3, deadline: 3 * time.Second})
	if res.runErr == nil {
		t.Error("sender returned nil; want retry exhaustion")
	}
	if res.recvSettled {
		t.Error("receiver settled on its own after the peer died; the wire layer cannot detect this")
	}
	res.wantCleanAbort(t)
}

// TestFaultCloseAfterCompleteTimesOutOnDone: the receiver verifies everything,
// sends Done into a dead path, and settles; the sender must not stall waiting
// for Done and instead fail with retry exhaustion (DoneTimeout).
func TestFaultCloseAfterCompleteTimesOutOnDone(t *testing.T) {
	data := testData(100_000, 41)
	script := faultScript{}.
		at(dirR2S, FrameDone, fClose)
	res := runFaultLoopback(t, data, 1024, 256, 4, script, nil,
		faultRunOptions{doneTimeout: 300 * time.Millisecond})
	if res.runErr == nil {
		t.Fatal("sender completed cleanly; want Done-timeout failure")
	}
	if !strings.Contains(res.runErr.Error(), "Done") {
		t.Fatalf("sender error = %v; want a Done-related failure", res.runErr)
	}
	if res.recvErr != nil {
		t.Fatalf("receiver should have settled after sending Done, got: %v", res.recvErr)
	}
	if !res.sink.IsClosed() {
		t.Error("sink not closed though the receiver verified the file")
	}
}

// TestFaultLateControlAfterSettlementIsIgnored (SB-1124): controls arriving
// after the sender settled are dropped.
func TestFaultLateControlAfterSettlementIsIgnored(t *testing.T) {
	data := testData(40_000, 3)
	script := faultScript{}.
		at(dirR2S, FrameDone, fDuplicate)
	res := runFaultLoopback(t, data, 1024, 256, 4, script, nil, faultRunOptions{})
	res.wantSuccess(t, data)
}
