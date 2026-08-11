package transfer

import (
	"errors"
	"sync"

	relaytransport "github.com/sendbeam/cli/internal/relay"
	"github.com/sendbeam/cli/internal/rtc"
)

// adaptiveConn starts on an open direct channel and atomically converges onto the session relay.
// Frames accepted by the old channel may be lost during cutover; the transfer engines recover
// their unacknowledged block window after the switch callback.
type adaptiveConn struct {
	direct *rtc.DataConn
	relay  *relaytransport.Conn

	mu          sync.Mutex
	path        string
	closed      bool
	switchErr   error
	switchDone  chan struct{}
	switchOnce  sync.Once
	onSwitch    func()
	hookCalled  bool
	onTransport func(string)
}

func newAdaptiveConn(
	direct *rtc.DataConn,
	relay *relaytransport.Conn,
	onTransport func(string),
) *adaptiveConn {
	c := &adaptiveConn{
		direct: direct, relay: relay, path: "direct", switchDone: make(chan struct{}),
		onTransport: onTransport,
	}
	go func() {
		select {
		case <-direct.Done():
			c.requestRelay()
		case <-c.switchDone:
		}
	}()
	go func() {
		select {
		case <-relay.Ready():
			c.activateRelay()
		case <-c.switchDone:
		}
	}()
	return c
}

func (c *adaptiveConn) Send(frame []byte) error {
	c.mu.Lock()
	path, closed := c.path, c.closed
	c.mu.Unlock()
	if closed {
		return errors.New("transfer: connection closed")
	}
	if path == "relay" {
		return c.relay.Send(frame)
	}
	if err := c.direct.Send(frame); err == nil {
		return nil
	}
	c.requestRelay()
	<-c.switchDone
	c.mu.Lock()
	err := c.switchErr
	path = c.path
	c.mu.Unlock()
	if err != nil {
		return err
	}
	if path != "relay" {
		return errors.New("transfer: relay switch did not complete")
	}
	return c.relay.Send(frame)
}

func (c *adaptiveConn) OnData(handler func([]byte)) {
	c.direct.OnData(func(frame []byte) {
		c.mu.Lock()
		active := !c.closed && c.path == "direct"
		c.mu.Unlock()
		if active {
			handler(frame)
		}
	})
	c.relay.OnData(func(frame []byte) {
		c.activateRelay()
		c.mu.Lock()
		active := !c.closed && c.path == "relay"
		c.mu.Unlock()
		if active {
			handler(frame)
		}
	})
}

func (c *adaptiveConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.finishSwitch(errors.New("transfer: connection closed"))
	_ = c.relay.Close()
	return c.direct.Close()
}

func (c *adaptiveConn) SetOnSwitch(handler func()) {
	c.mu.Lock()
	c.onSwitch = handler
	call := c.path == "relay" && !c.hookCalled
	if call {
		c.hookCalled = true
	}
	c.mu.Unlock()
	if call {
		handler()
	}
}

func (c *adaptiveConn) IsRelay() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.path == "relay"
}

// SignalingLost keeps a healthy direct path alive but makes relay activation fail promptly.
func (c *adaptiveConn) SignalingLost(err error) {
	c.finishSwitch(err)
	_ = c.relay.Close()
}

func (c *adaptiveConn) requestRelay() {
	c.mu.Lock()
	blocked := c.closed || c.path == "relay" || c.switchErr != nil
	c.mu.Unlock()
	if blocked {
		return
	}
	if err := c.relay.Open(); err != nil {
		c.finishSwitch(err)
	}
}

func (c *adaptiveConn) activateRelay() {
	c.mu.Lock()
	if c.closed || c.path == "relay" || c.switchErr != nil {
		c.mu.Unlock()
		return
	}
	c.path = "relay"
	hook := c.onSwitch
	if hook != nil {
		c.hookCalled = true
	}
	onTransport := c.onTransport
	c.mu.Unlock()

	if hook != nil {
		hook()
	}
	if onTransport != nil {
		onTransport("relay")
	}
	c.finishSwitch(nil)
	go func() { _ = c.direct.Close() }()
}

func (c *adaptiveConn) finishSwitch(err error) {
	c.switchOnce.Do(func() {
		c.mu.Lock()
		c.switchErr = err
		c.mu.Unlock()
		close(c.switchDone)
	})
}
