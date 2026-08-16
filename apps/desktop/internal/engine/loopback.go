package engine

import (
	"context"
	"sync"

	"github.com/sendbeam/engine/rendezvous"
)

// loopbackRelay is an in-process stand-in for the signaling + encrypted relay
// server. It mirrors the server's dispatch (create → created; join blocks until
// the room exists; relay-open gating; relay credit) so a self-check can drive a
// full engine transfer with no network. It is the same shape the engine parity
// tests use to exercise the public API.
type loopbackRelay struct {
	off     *loopbackEnd
	join    *loopbackEnd
	room    int
	created chan struct{}
	once    sync.Once
	mu      sync.Mutex
}

func newLoopbackRelay() *loopbackRelay {
	r := &loopbackRelay{room: 7, created: make(chan struct{})}
	r.off = newLoopbackEnd(r, "offerer")
	r.join = newLoopbackEnd(r, "joiner")
	return r
}

func (r *loopbackRelay) partner(e *loopbackEnd) *loopbackEnd {
	if e == r.off {
		return r.join
	}
	return r.off
}

// route mirrors the server's dispatch; a join blocks until the room exists,
// matching the guarantee that a joiner cannot pair before the offerer.
func (r *loopbackRelay) route(from *loopbackEnd, m rendezvous.Message) {
	switch m.Type {
	case "create":
		room := r.room
		from.enqueue(rendezvous.Message{Type: "created", Room: &room})
		r.once.Do(func() { close(r.created) })
	case "join":
		<-r.created
		r.off.enqueue(rendezvous.Message{Type: "peer-joined", Role: r.off.role})
		r.join.enqueue(rendezvous.Message{Type: "peer-joined", Role: r.join.role})
	case rendezvous.TypeRelayOpen:
		r.mu.Lock()
		from.relayOpen = true
		other := r.partner(from)
		ready := other.relayOpen
		r.mu.Unlock()
		if ready {
			from.enqueue(rendezvous.Message{Type: rendezvous.TypeRelayReady})
			other.enqueue(rendezvous.Message{Type: rendezvous.TypeRelayReady})
		} else {
			other.enqueue(rendezvous.Message{Type: rendezvous.TypeRelayRequired})
		}
	case rendezvous.TypeRelayCredit:
		r.partner(from).enqueue(rendezvous.Message{Type: rendezvous.TypeCredit, Bytes: m.Bytes})
	default:
		r.partner(from).enqueue(m)
	}
}

// loopbackEnd is one side of the relay; it satisfies transfer.Signal so a
// driver adopts it exactly as it would a real *wsclient.ReconnectingSignal.
type loopbackEnd struct {
	hub       *loopbackRelay
	role      string
	in        chan rendezvous.Message
	bin       chan []byte
	relayOpen bool
	once      sync.Once
	done      chan struct{}
}

func newLoopbackEnd(hub *loopbackRelay, role string) *loopbackEnd {
	return &loopbackEnd{
		hub: hub, role: role,
		in: make(chan rendezvous.Message, 256), bin: make(chan []byte, 256),
		done: make(chan struct{}),
	}
}

// SetResume satisfies transfer.ReconnectSetter; the loopback never reconnects.
func (e *loopbackEnd) SetResume(_ int, _ string) {}

func (e *loopbackEnd) Send(m rendezvous.Message) error {
	e.hub.route(e, m)
	return nil
}

func (e *loopbackEnd) SendBinary(frame []byte) error {
	e.hub.partner(e).enqueueBinary(frame)
	return nil
}

func (e *loopbackEnd) Run(ctx context.Context, onMessage func(rendezvous.Message), onBinary func([]byte)) error {
	for {
		select {
		case m := <-e.in:
			onMessage(m)
		case frame := <-e.bin:
			onBinary(frame)
		case <-e.done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (e *loopbackEnd) Close() { e.once.Do(func() { close(e.done) }) }

func (e *loopbackEnd) enqueueBinary(frame []byte) {
	select {
	case e.bin <- append([]byte(nil), frame...):
	case <-e.done:
	}
}

func (e *loopbackEnd) enqueue(m rendezvous.Message) {
	select {
	case e.in <- m:
	case <-e.done:
	}
}
