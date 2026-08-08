package rtc

import (
	"errors"
	"sync"

	"github.com/pion/webrtc/v4"
)

// DataConn wraps the open "sendarc" DataChannel as the byte transport the transfer engine rides
// on: Send emits one frame, OnData registers the inbound handler, Close tears it down. It is the
// Go counterpart of the browser peer's channel/onData surface, adapted for pion's threading:
// pion delivers inbound messages on its own goroutine, so a single pump goroutine serializes
// delivery to preserve arrival order, and outbound Send is flow-controlled against the channel's
// SCTP buffer.

// Flow-control watermarks for the send side. Send pauses once the channel's buffered amount
// exceeds maxBufferedAmount and resumes when it drains below bufferedAmountLowThreshold —
// otherwise a fast local reader could queue the whole file into SCTP memory. These bound
// buffering, not throughput; the transfer's own block window is the primary limiter.
const (
	maxBufferedAmount          = 8 * 1024 * 1024
	bufferedAmountLowThreshold = 1 * 1024 * 1024
)

// errConnClosed is returned by Send once the channel has closed, so a blocked sender unblocks
// with a definite error rather than hanging.
var errConnClosed = errors.New("rtc: data channel closed")

// DataConn is the transport half of a Peer. Obtain it from Peer.Channel; it is created open.
type DataConn struct {
	dc *webrtc.DataChannel

	mu     sync.Mutex
	cond   *sync.Cond // signals Send when the buffered amount drains or the channel closes
	closed bool

	inbox        chan []byte
	handler      func(frame []byte)
	handlerReady chan struct{}
	done         chan struct{}
}

// newDataConn wraps dc and starts serving inbound frames. Frames that arrive before OnData is
// called are queued (bounded by inbox); once a handler is registered the pump delivers them in
// order, then streams subsequent frames as they arrive.
func newDataConn(dc *webrtc.DataChannel) *DataConn {
	c := &DataConn{
		dc:           dc,
		inbox:        make(chan []byte, 64),
		handlerReady: make(chan struct{}),
		done:         make(chan struct{}),
	}
	c.cond = sync.NewCond(&c.mu)

	dc.SetBufferedAmountLowThreshold(bufferedAmountLowThreshold)
	dc.OnBufferedAmountLow(func() { c.cond.Broadcast() })

	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		// Copy: pion may reuse msg.Data after this callback returns, and the frame is queued.
		frame := append([]byte(nil), msg.Data...)
		select {
		case c.inbox <- frame:
		case <-c.done:
		}
	})
	dc.OnClose(func() { c.shutdown() })

	go c.pump()
	return c
}

// Send transmits one frame, blocking while the channel's send buffer is above the high
// watermark so the whole file is never queued at once. It returns errConnClosed if the channel
// closes while waiting.
func (c *DataConn) Send(frame []byte) error {
	c.mu.Lock()
	for !c.closed && c.dc.BufferedAmount() >= maxBufferedAmount {
		c.cond.Wait()
	}
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return errConnClosed
	}
	return c.dc.Send(frame)
}

// OnData registers the inbound frame handler and flushes any frames buffered before this call,
// in arrival order. It is meant to be called once, right after the channel opens.
func (c *DataConn) OnData(handler func(frame []byte)) {
	c.mu.Lock()
	if c.handler != nil {
		c.mu.Unlock()
		return
	}
	c.handler = handler
	c.mu.Unlock()
	close(c.handlerReady)
}

// Close closes the underlying channel. It is idempotent and unblocks any waiting Send.
func (c *DataConn) Close() error {
	c.shutdown()
	return c.dc.Close()
}

// pump waits for a handler, then delivers queued and live frames in order until the channel
// closes. A single goroutine guarantees ordered, non-overlapping delivery even though pion
// enqueues from its own read goroutine.
func (c *DataConn) pump() {
	select {
	case <-c.handlerReady:
	case <-c.done:
		return
	}
	c.mu.Lock()
	handler := c.handler
	c.mu.Unlock()
	for {
		select {
		case frame := <-c.inbox:
			handler(frame)
		case <-c.done:
			return
		}
	}
}

// shutdown marks the connection closed, stops the pump, and wakes any blocked Send. It runs on
// both an explicit Close and pion's OnClose, so it is idempotent.
func (c *DataConn) shutdown() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	close(c.done)
	c.cond.Broadcast()
	c.mu.Unlock()
}
