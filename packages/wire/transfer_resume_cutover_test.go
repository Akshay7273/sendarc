package wire

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// runResumeFaultLoopback wires a resumable sender to a reloaded receiver (seeded like a
// durable reload) over a fault link, drives a cutover, and returns both sides' outcomes.
func runResumeFaultLoopback(t *testing.T, data []byte, blockSize int, haveBlocks int, script faultScript, cutoverAfter func(link *faultLink, sender *Sender)) (error, error) {
	t.Helper()
	keys, err := DeriveTransferKeys(loopbackMaster())
	if err != nil {
		t.Fatal(err)
	}
	link := newFaultLink(script, nil)
	sink := &MemorySink{}
	prefix := haveBlocks * blockSize
	if prefix > len(data) {
		prefix = len(data)
	}
	seed := NewSHA256Digest()
	if prefix > 0 {
		_ = sink.Write(0, data[:prefix])
		seed.Update(data[:prefix])
	}
	fp, err := ManifestFingerprint(Manifest{
		Type:       FrameManifest,
		TransferID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Files: []FileEntry{{
			Idx: 0, Name: "f", Size: int64(len(data)), Mime: "application/octet-stream",
			LastModified: 1, BlockSize: blockSize, Blocks: (len(data)-1)/blockSize + 1,
			FileDigest: hexSHA256(data),
		}},
		TotalSize: int64(len(data)),
	})
	if err != nil {
		t.Fatal(err)
	}

	sender := NewSender(SenderOptions{
		File:        BytesSource(data, FileMeta{Name: "f", Size: int64(len(data)), Mime: "application/octet-stream", LastModified: 1}, 0),
		Send:        func(f []byte) error { return link.send(dirS2R, f) },
		SendDir:     keys.O2J,
		RecvDir:     keys.J2O,
		BlockSize:   blockSize,
		FrameSize:   256,
		Window:      4,
		AckTimeout:  250 * time.Millisecond,
		MaxRetries:  5,
		DoneTimeout: 2 * time.Second,
		TransferID:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	receiver := NewReceiver(ReceiverOptions{
		Send:    func(f []byte) error { return link.send(dirR2S, f) },
		SendDir: keys.J2O,
		RecvDir: keys.O2J,
		Sink:    sink,
		Resume: &ReceiverResume{
			TransferID:          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			ManifestFingerprint: fp,
			Files:               map[int]ResumeFileProgress{0: {HaveBlocks: haveBlocks, SeedDigest: seed}},
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

	var cutoverOnce atomic.Bool
	go func() {
		for !link.isClosed() {
			if cutoverAfter != nil && !cutoverOnce.Swap(true) {
				cutoverAfter(link, sender)
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	runCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	runErrCh := make(chan error, 1)
	go func() {
		_, e := sender.Run(runCtx)
		runErrCh <- e
	}()
	_, recvErr := receiver.Wait(runCtx)
	var runErr error
	select {
	case runErr = <-runErrCh:
	case <-time.After(10 * time.Second):
		t.Fatal("sender.Run did not return after cutover")
	}
	return runErr, recvErr
}

// TestResumeNegotiationConvergesAfterCutover pins the recovery this PR exists for: the
// receiver's one-shot resume_state is lost at the moment of a direct→relay cutover, so the
// sender waits in resume negotiation forever. On cutover the sender retransmits the
// manifest; the receiver re-answers with the exact same fingerprint-bound resume_state, and
// the sender's idempotent duplicate handling lets the resumed stream proceed.
func TestResumeNegotiationConvergesAfterCutover(t *testing.T) {
	data := testData(64_000, 61)
	script := faultScript{}.at(dirR2S, FrameResumeState, fDrop)
	cutoverAfter := func(link *faultLink, sender *Sender) {
		for !link.manifestSeen() && !link.isClosed() {
			time.Sleep(2 * time.Millisecond)
		}
		sender.TransportChanged()
	}
	runErr, recvErr := runResumeFaultLoopback(t, data, 1024, 5, script, cutoverAfter)
	if runErr != nil {
		t.Fatalf("sender: %v", runErr)
	}
	if recvErr != nil {
		t.Fatalf("receiver: %v", recvErr)
	}
}

// TestAllCompleteResumeWithLostDone pins settlement when the resume seed already holds the
// whole file: nothing is streamed, and if the receiver's Done is lost at the cutover moment,
// the sender's Complete retransmission must draw a fresh Done from the settled receiver.
func TestAllCompleteResumeWithLostDone(t *testing.T) {
	data := testData(8_000, 3)
	blocks := (len(data)-1)/1024 + 1
	script := faultScript{}.at(dirR2S, FrameDone, fDrop)
	cutoverAfter := func(link *faultLink, sender *Sender) {
		for !link.completeSeen() && !link.isClosed() {
			time.Sleep(2 * time.Millisecond)
		}
		sender.TransportChanged()
	}
	runErr, recvErr := runResumeFaultLoopback(t, data, 1024, blocks, script, cutoverAfter)
	if runErr != nil {
		t.Fatalf("sender: %v", runErr)
	}
	if recvErr != nil {
		t.Fatalf("receiver: %v", recvErr)
	}
}
