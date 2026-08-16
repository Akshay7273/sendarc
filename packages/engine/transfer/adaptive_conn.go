package transfer

import (
	"sync"
	"time"

	relaytransport "github.com/sendbeam/engine/relay"
	"github.com/sendbeam/engine/rtc"
	"github.com/sendbeam/engine/supervisor"
	"github.com/sendbeam/wire"
)

// relaySwitchTimeout bounds how long Send waits for the relay handshake to complete
// after the direct path fails. Without it, a partner that never answers relay_open
// would wedge the engine forever (no deadline exists anywhere else in that path).
const relaySwitchTimeout = 15 * time.Second

// adaptiveConn starts on an open direct channel and atomically converges onto the session relay.
// It uses the supervisor for path state management while preserving the existing blocking-Send
// behavior during cutover.
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

	sv *supervisor.Supervisor
}

func newAdaptiveConn(
	direct *rtc.DataConn,
	relay *relaytransport.Conn,
	onTransport func(string),
	sv *supervisor.Supervisor,
) *adaptiveConn {
	c := &adaptiveConn{
		direct: direct, relay: relay, path: "direct", switchDone: make(chan struct{}),
		onTransport: onTransport, sv: sv,
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
		return wire.Errorf(wire.CodeConnection, "transfer: connection closed")
	}
	if path == "relay" {
		return c.relay.Send(frame)
	}
	if err := c.direct.Send(frame); err == nil {
		return nil
	}
	c.requestRelay()
	select {
	case <-c.switchDone:
	case <-time.After(relaySwitchTimeout):
		return wire.Errorf(wire.CodeRelay, "transfer: relay switch timed out")
	}
	c.mu.Lock()
	err := c.switchErr
	path = c.path
	c.mu.Unlock()
	if err != nil {
		return err
	}
	if path != "relay" {
		return wire.Errorf(wire.CodeRelay, "transfer: relay switch did not complete")
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
	c.finishSwitch(wire.Errorf(wire.CodeConnection, "transfer: connection closed"))
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
		return
	}
	if c.sv != nil {
		_ = c.sv.Warming(supervisor.PathRelay)
		_ = c.sv.Ready(supervisor.PathRelay)
	}
}

// FallbackToRelay starts the encrypted-relay fallback in response to a failed direct recovery.
// It is idempotent: a path already on the relay (or already switching) is a no-op. Called from
// the peer's recovery-failure hook without resetting transfer progress.
func (c *adaptiveConn) FallbackToRelay() { c.requestRelay() }

func (c *adaptiveConn) activateRelay() {
	c.mu.Lock()
	if c.closed || c.path == "relay" || c.switchErr != nil {
		c.mu.Unlock()
		return
	}
	c.path = "relay"
	onTransport := c.onTransport
	c.mu.Unlock()

	if c.sv != nil {
		_ = c.sv.Warming(supervisor.PathRelay)
		_ = c.sv.Ready(supervisor.PathRelay)
		_, _ = c.sv.Activate(supervisor.PathRelay)
	} else if c.onSwitch != nil {
		c.onSwitch()
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
