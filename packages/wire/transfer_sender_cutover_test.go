package wire

import (
	"context"
	"testing"
	"time"
)

// TestSenderRetransmitsCompleteOnCutover pins the terminal-frame recovery that a
// direct→relay cutover depends on. The sender's Complete is a one-shot frame: it
// is not acknowledged and, before this fix, had no retransmission on a path
// change. If Complete is lost (queued into a data channel that is torn down at
// the moment every block is acknowledged), the receiver never settles, never
// sends Done, and the sender pins in waitDone until its DoneTimeout.
//
// The harness drops the first FrameComplete, then simulates the cutover by
// calling TransportChanged once the sender has attempted Complete — exactly the
// sequence the CLI driver performs when it switches a live transfer to the
// relay. The sender must retransmit Complete on the new path so the receiver
// settles and Done resolves.
func TestSenderRetransmitsCompleteOnCutover(t *testing.T) {
	data := testData(64_000, 41)
	keys, err := DeriveTransferKeys(loopbackMaster())
	if err != nil {
		t.Fatal(err)
	}
	link := newFaultLink(faultScript{}.at(dirS2R, FrameComplete, fDrop), nil)
	doneTimeout := 2 * time.Second // keep the no-fix failure fast
	sink := &MemorySink{}

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
		DoneTimeout: doneTimeout,
	})
	receiver := NewReceiver(ReceiverOptions{
		Send:    func(f []byte) error { return link.send(dirR2S, f) },
		SendDir: keys.J2O,
		RecvDir: keys.O2J,
		Sink:    sink,
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

	// Once the sender has attempted Complete (its only terminal frame), simulate
	// the cutover by telling it the path changed. With the fix it retransmits
	// Complete; without it the receiver never settles and waitDone times out.
	go func() {
		for !link.completeSeen() && !link.isClosed() {
			time.Sleep(2 * time.Millisecond)
		}
		sender.TransportChanged()
	}()

	runCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	runErrCh := make(chan error, 1)
	go func() {
		_, e := sender.Run(runCtx)
		runErrCh <- e
	}()
	recvRes, recvErr := receiver.Wait(runCtx)
	var runErr error
	select {
	case runErr = <-runErrCh:
	case <-time.After(10 * time.Second):
		t.Fatal("sender.Run did not return; Complete retransmission missing")
	}
	if runErr != nil {
		t.Fatalf("sender: %v", runErr)
	}
	if recvErr != nil {
		t.Fatalf("receiver: %v", recvErr)
	}
	if string(sink.Bytes()) != string(data) {
		t.Fatal("received bytes differ from source after Complete retransmission")
	}
	if recvRes.Digest == "" {
		t.Fatal("receiver did not produce a digest")
	}
}
