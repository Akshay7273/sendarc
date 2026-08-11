package relay

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sendbeam/cli/internal/rendezvous"
)

type fakeSignal struct {
	mu     sync.Mutex
	msgs   []rendezvous.Message
	binary [][]byte
}

func (s *fakeSignal) Send(msg rendezvous.Message) error {
	s.mu.Lock()
	s.msgs = append(s.msgs, msg)
	s.mu.Unlock()
	return nil
}

func (s *fakeSignal) SendBinary(frame []byte) error {
	s.mu.Lock()
	s.binary = append(s.binary, append([]byte(nil), frame...))
	s.mu.Unlock()
	return nil
}

func TestConnNegotiatesCreditAndSendsWithinIt(t *testing.T) {
	sig := &fakeSignal{}
	c := New(sig)
	if err := c.Open(); err != nil {
		t.Fatal(err)
	}
	if !c.HandleMessage(rendezvous.Message{Type: rendezvous.TypeRelayReady}) {
		t.Fatal("relay_ready was not handled")
	}
	c.HandleMessage(rendezvous.Message{Type: rendezvous.TypeCredit, Bytes: 32})
	if err := c.Send([]byte("sealed frame")); err != nil {
		t.Fatal(err)
	}
	sig.mu.Lock()
	defer sig.mu.Unlock()
	if len(sig.msgs) != 2 || sig.msgs[0].Type != rendezvous.TypeRelayOpen ||
		sig.msgs[1].Type != rendezvous.TypeRelayCredit || sig.msgs[1].Bytes != windowBytes {
		t.Fatalf("control messages = %+v", sig.msgs)
	}
	if len(sig.binary) != 1 || string(sig.binary[0]) != "sealed frame" {
		t.Fatalf("binary = %q", sig.binary)
	}
}

func TestConnBuffersOneWindowUntilConsumerAndReplenishesAfterConsumption(t *testing.T) {
	sig := &fakeSignal{}
	c := New(sig)
	c.HandleMessage(rendezvous.Message{Type: rendezvous.TypeRelayReady})
	frame := make([]byte, creditBatch)
	c.HandleBinary(frame)
	got := make(chan int, 1)
	c.OnData(func(data []byte) { got <- len(data) })
	select {
	case size := <-got:
		if size != len(frame) {
			t.Fatalf("size = %d", size)
		}
	case <-time.After(time.Second):
		t.Fatal("buffered frame was not delivered")
	}
	sig.mu.Lock()
	defer sig.mu.Unlock()
	if len(sig.msgs) != 2 || sig.msgs[1].Bytes != creditBatch {
		t.Fatalf("credit messages = %+v", sig.msgs)
	}
}

func TestConnCloseUnblocksCreditWaiter(t *testing.T) {
	c := New(&fakeSignal{})
	result := make(chan error, 1)
	go func() { result <- c.Send([]byte("blocked")) }()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("blocked send returned nil after close")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not unblock send")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if err := c.WaitReady(ctx); err == nil {
		t.Fatal("closed unready relay unexpectedly became ready")
	}
}
