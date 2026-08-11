// Package relay implements the CLI's credit-gated opaque binary transport over the adopted
// signaling WebSocket. It never sees plaintext; transfer frames remain sealed end to end.
package relay

import (
	"context"
	"errors"
	"sync"

	"github.com/sendbeam/cli/internal/rendezvous"
)

const (
	windowBytes = int64(1 * 1024 * 1024)
	creditBatch = windowBytes / 2
)

var errClosed = errors.New("relay: connection closed")

// Signal is the serialized WebSocket write surface supplied by the transfer driver.
type Signal interface {
	Send(rendezvous.Message) error
	SendBinary([]byte) error
}

// Conn is a bounded, bidirectional transfer byte path.
type Conn struct {
	sig Signal

	mu           sync.Mutex
	cond         *sync.Cond
	opened       bool
	ready        bool
	closed       bool
	credit       int64
	consumed     int64
	handler      func([]byte)
	pending      [][]byte
	pendingBytes int64
	readyCh      chan struct{}
	readyOnce    sync.Once
}

// New creates an unopened relay connection over sig.
func New(sig Signal) *Conn {
	c := &Conn{sig: sig, readyCh: make(chan struct{})}
	c.cond = sync.NewCond(&c.mu)
	return c
}

// Open opts into relay once. The server asks the partner to do the same.
func (c *Conn) Open() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errClosed
	}
	if c.opened {
		c.mu.Unlock()
		return nil
	}
	c.opened = true
	c.mu.Unlock()
	return c.sig.Send(rendezvous.NewRelayOpen())
}

// WaitReady waits until both peers have opted in and initial receive credit is granted.
func (c *Conn) WaitReady(ctx context.Context) error {
	select {
	case <-c.readyCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Ready is closed exactly once after the server confirms both peers opted in.
func (c *Conn) Ready() <-chan struct{} { return c.readyCh }

// HandleMessage consumes relay control messages and reports whether it recognized the type.
func (c *Conn) HandleMessage(msg rendezvous.Message) bool {
	switch msg.Type {
	case rendezvous.TypeRelayRequired:
		_ = c.Open()
		return true
	case rendezvous.TypeRelayReady:
		c.readyOnce.Do(func() {
			c.mu.Lock()
			c.ready = true
			c.mu.Unlock()
			_ = c.sig.Send(rendezvous.NewRelayCredit(windowBytes))
			close(c.readyCh)
		})
		return true
	case rendezvous.TypeCredit:
		if msg.Bytes <= 0 {
			return true
		}
		c.mu.Lock()
		c.credit += msg.Bytes
		c.cond.Broadcast()
		c.mu.Unlock()
		return true
	default:
		return false
	}
}

// Send waits for receiver-granted capacity, then emits one opaque binary frame.
func (c *Conn) Send(frame []byte) error {
	size := int64(len(frame))
	c.mu.Lock()
	for !c.closed && (!c.ready || c.credit < size) {
		c.cond.Wait()
	}
	if c.closed {
		c.mu.Unlock()
		return errClosed
	}
	c.credit -= size
	c.mu.Unlock()
	return c.sig.SendBinary(frame)
}

// OnData installs the transfer consumer and drains the at-most-one-window early buffer.
func (c *Conn) OnData(handler func([]byte)) {
	c.mu.Lock()
	if c.handler != nil {
		c.mu.Unlock()
		return
	}
	c.handler = handler
	pending := c.pending
	c.pending = nil
	c.pendingBytes = 0
	c.mu.Unlock()
	for _, frame := range pending {
		c.consume(frame, handler)
	}
}

// HandleBinary is called serially by the WebSocket read loop.
func (c *Conn) HandleBinary(frame []byte) {
	copyFrame := append([]byte(nil), frame...)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	handler := c.handler
	if handler == nil {
		if c.pendingBytes+int64(len(copyFrame)) <= windowBytes {
			c.pending = append(c.pending, copyFrame)
			c.pendingBytes += int64(len(copyFrame))
		}
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	c.consume(copyFrame, handler)
}

func (c *Conn) consume(frame []byte, handler func([]byte)) {
	handler(frame)
	c.mu.Lock()
	c.consumed += int64(len(frame))
	grant := int64(0)
	if c.consumed >= creditBatch {
		grant = c.consumed
		c.consumed = 0
	}
	c.mu.Unlock()
	if grant > 0 {
		_ = c.sig.Send(rendezvous.NewRelayCredit(grant))
	}
}

// Close is idempotent and wakes senders blocked on credit.
func (c *Conn) Close() error {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		c.cond.Broadcast()
	}
	c.mu.Unlock()
	return nil
}
