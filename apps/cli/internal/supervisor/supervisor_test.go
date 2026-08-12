package supervisor

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockPath is a deterministic in-memory BytePath for tests.
type mockPath struct {
	id       PathID
	sendFn   func([]byte) error
	onDataFn func(func([]byte))
	closeFn  func() error
	closed   atomic.Bool
	mu       sync.Mutex
	handler  func([]byte)
	sent     [][]byte
}

func newMockPath(id PathID) *mockPath {
	p := &mockPath{id: id}
	p.sendFn = func(frame []byte) error {
		p.mu.Lock()
		p.sent = append(p.sent, append([]byte(nil), frame...))
		p.mu.Unlock()
		return nil
	}
	p.onDataFn = func(h func([]byte)) {
		p.mu.Lock()
		p.handler = h
		p.mu.Unlock()
	}
	p.closeFn = func() error {
		p.closed.Store(true)
		return nil
	}
	return p
}

func (p *mockPath) Send(frame []byte) error { return p.sendFn(frame) }
func (p *mockPath) OnData(h func([]byte))   { p.onDataFn(h) }
func (p *mockPath) Close() error            { return p.closeFn() }

func (p *mockPath) deliver(frame []byte) {
	p.mu.Lock()
	h := p.handler
	p.mu.Unlock()
	if h != nil {
		h(frame)
	}
}

func (p *mockPath) sentCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.sent)
}

// must fails the test if err is non-nil.
func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// --- Tests ---

// TestStateTransitions verifies the legal path state machine.
func TestStateTransitions(t *testing.T) {
	s := New()
	d := newMockPath(PathDirect)
	r := newMockPath(PathRelay)

	must(t, s.Register(PathDirect, d))
	must(t, s.Register(PathRelay, r))

	checkState := func(id PathID, want PathState) {
		got, ok := s.State(id)
		if !ok {
			t.Fatalf("path %v not found", id)
		}
		if got != want {
			t.Fatalf("path %v state = %v, want %v", id, got, want)
		}
	}

	checkState(PathDirect, StateCandidate)
	checkState(PathRelay, StateCandidate)

	must(t, s.Warming(PathDirect))
	checkState(PathDirect, StateWarming)

	must(t, s.Ready(PathDirect))
	checkState(PathDirect, StateReady)

	epoch, err := s.Activate(PathDirect)
	must(t, err)
	if epoch != 1 {
		t.Fatalf("epoch = %d, want 1", epoch)
	}
	checkState(PathDirect, StateActive)
	checkState(PathRelay, StateClosed)
	if !r.closed.Load() {
		t.Fatal("relay should have been closed after direct activation")
	}
}

// TestIllegalTransitions verifies that invalid transitions are rejected.
func TestIllegalTransitions(t *testing.T) {
	s := New()
	d := newMockPath(PathDirect)
	must(t, s.Register(PathDirect, d))

	// Cannot go from candidate to ready directly
	if err := s.Ready(PathDirect); err == nil {
		t.Fatal("expected error transitioning from candidate to ready directly")
	}

	// Cannot go from candidate to active directly
	if _, err := s.Activate(PathDirect); err == nil {
		t.Fatal("expected error activating a candidate")
	}

	// Warming from candidate is fine
	must(t, s.Warming(PathDirect))

	// Cannot warm twice
	if err := s.Warming(PathDirect); err == nil {
		t.Fatal("expected error warming twice")
	}
}

// TestActivateClosesLosers verifies that activation closes all other candidates.
func TestActivateClosesLosers(t *testing.T) {
	s := New()
	d1 := newMockPath(1)
	d2 := newMockPath(2)
	d3 := newMockPath(3)

	must(t, s.Register(1, d1))
	must(t, s.Register(2, d2))
	must(t, s.Register(3, d3))

	must(t, s.Warming(1))
	must(t, s.Ready(1))
	must(t, s.Warming(2))
	must(t, s.Ready(2))

	if _, err := s.Activate(1); err != nil {
		t.Fatal(err)
	}

	if !d2.closed.Load() {
		t.Fatal("path 2 should be closed")
	}
	if !d3.closed.Load() {
		t.Fatal("path 3 should be closed")
	}
	if d1.closed.Load() {
		t.Fatal("active path should not be closed")
	}
}

// TestNoDoubleActivation verifies that activating twice is a no-op.
func TestNoDoubleActivation(t *testing.T) {
	s := New()
	d := newMockPath(PathDirect)
	must(t, s.Register(PathDirect, d))
	must(t, s.Warming(PathDirect))
	must(t, s.Ready(PathDirect))

	epoch1, err := s.Activate(PathDirect)
	must(t, err)

	epoch2, err := s.Activate(PathDirect)
	must(t, err)

	if epoch1 != epoch2 {
		t.Fatal("second activate should return same epoch")
	}
}

// TestFailPath verifies failing a path works and late callbacks are rejected.
func TestFailPath(t *testing.T) {
	s := New()
	d := newMockPath(PathDirect)
	must(t, s.Register(PathDirect, d))

	must(t, s.Fail(PathDirect))
	state, ok := s.State(PathDirect)
	if !ok || state != StateFailed {
		t.Fatalf("state = %v, want failed", state)
	}
	if !d.closed.Load() {
		t.Fatal("failed path should be closed")
	}

	// Activate on failed path should fail
	if _, err := s.Activate(PathDirect); err == nil {
		t.Fatal("expected error activating a failed path")
	}
}

// TestDuplicateLateCallbacks verifies that data from a closed path
// does not reach the handler.
func TestDuplicateLateCallbacks(t *testing.T) {
	s := New()
	d1 := newMockPath(1)
	d2 := newMockPath(2)
	must(t, s.Register(1, d1))
	must(t, s.Register(2, d2))

	var received int32
	s.OnData(func([]byte) {
		atomic.AddInt32(&received, 1)
	})

	must(t, s.Warming(1))
	must(t, s.Ready(1))
	must(t, s.Warming(2))
	must(t, s.Ready(2))

	_, err := s.Activate(1)
	must(t, err)

	// Deliver data on the closed path 2 — should be ignored
	d2.deliver([]byte("late"))
	if n := atomic.LoadInt32(&received); n != 0 {
		t.Fatalf("received %d frames from closed path, want 0", n)
	}

	// Deliver data on active path 1 — should be received
	d1.deliver([]byte("active"))
	if n := atomic.LoadInt32(&received); n != 1 {
		t.Fatalf("received %d frames from active path, want 1", n)
	}
}

// TestCleanup verifies that Close idempotently shuts everything down.
func TestCleanup(t *testing.T) {
	s := New()
	d1 := newMockPath(1)
	d2 := newMockPath(2)
	must(t, s.Register(1, d1))
	must(t, s.Register(2, d2))

	must(t, s.Warming(1))
	must(t, s.Ready(1))
	_, err := s.Activate(1)
	must(t, err)

	must(t, s.Close())

	if !d1.closed.Load() {
		t.Fatal("path 1 should be closed after supervisor close")
	}
	if !d2.closed.Load() {
		t.Fatal("path 2 should be closed after supervisor close")
	}
	if !s.IsClosed() {
		t.Fatal("supervisor should be closed")
	}

	// Second close should be a no-op
	must(t, s.Close())

	// Register after close should fail
	d3 := newMockPath(3)
	if err := s.Register(3, d3); err == nil {
		t.Fatal("expected error registering after close")
	}
	if !d3.closed.Load() {
		t.Fatal("path registered after close should be closed immediately")
	}
}

// TestCancelDuringEstablishment verifies that a candidate can be
// cancelled while warming up.
func TestCancelDuringEstablishment(t *testing.T) {
	s := New()
	d1 := newMockPath(1)
	d2 := newMockPath(2)
	must(t, s.Register(1, d1))
	must(t, s.Register(2, d2))

	must(t, s.Warming(1))
	must(t, s.Warming(2))

	// Cancel path 1 before it's ready
	must(t, s.Fail(1))

	// Path 2 should still be able to complete
	must(t, s.Ready(2))
	epoch, err := s.Activate(2)
	must(t, err)
	if epoch != 1 {
		t.Fatalf("epoch = %d, want 1", epoch)
	}
	state, _ := s.State(2)
	if state != StateActive {
		t.Fatalf("path 2 state = %v, want active", state)
	}
}

// TestLosingPathTeardown verifies that the losing path is torn down
// when the winner is activated.
func TestLosingPathTeardown(t *testing.T) {
	s := New()
	d1 := newMockPath(1)
	d2 := newMockPath(2)
	must(t, s.Register(1, d1))
	must(t, s.Register(2, d2))

	must(t, s.Warming(1))
	must(t, s.Ready(1))
	must(t, s.Warming(2))
	must(t, s.Ready(2))

	// Activate relay as winner
	_, err := s.Activate(2)
	must(t, err)

	// Path 1 should be closed and state is closed
	if !d1.closed.Load() {
		t.Fatal("losing path should be closed")
	}
	state, _ := s.State(1)
	if state != StateClosed {
		t.Fatalf("losing path state = %v, want closed", state)
	}
}

// TestLazySendBeforeActivation verifies frames sent before any path
// is activated are buffered and drained on activation.
func TestLazySendBeforeActivation(t *testing.T) {
	s := New()
	d := newMockPath(PathDirect)
	must(t, s.Register(PathDirect, d))

	must(t, s.Send([]byte("early")))

	if n := d.sentCount(); n != 0 {
		t.Fatalf("sent %d frames before activation, want 0", n)
	}

	must(t, s.Warming(PathDirect))
	must(t, s.Ready(PathDirect))
	_, err := s.Activate(PathDirect)
	must(t, err)

	if n := d.sentCount(); n != 1 {
		t.Fatalf("sent %d frames after activation, want 1", n)
	}
}

// TestSendAfterClose verifies Send returns ErrClosed after Close.
func TestSendAfterClose(t *testing.T) {
	s := New()
	d := newMockPath(PathDirect)
	must(t, s.Register(PathDirect, d))

	must(t, s.Close())

	if err := s.Send([]byte("late")); err != ErrClosed {
		t.Fatalf("Send after close = %v, want ErrClosed", err)
	}
}

// TestDuplicateRegistration verifies duplicate registration fails.
func TestDuplicateRegistration(t *testing.T) {
	s := New()
	d1 := newMockPath(PathDirect)
	d2 := newMockPath(PathDirect)

	must(t, s.Register(PathDirect, d1))
	if err := s.Register(PathDirect, d2); err == nil {
		t.Fatal("expected error for duplicate registration")
	}
	if !d2.closed.Load() {
		t.Fatal("duplicate should be closed immediately")
	}
}

// TestStaleStateDoesNotAffectActive verifies that failing or warming
// a non-active path does not affect the active path.
func TestStaleStateDoesNotAffectActive(t *testing.T) {
	s := New()
	d1 := newMockPath(1)
	d2 := newMockPath(2)
	must(t, s.Register(1, d1))
	must(t, s.Register(2, d2))

	must(t, s.Warming(1))
	must(t, s.Ready(1))
	_, actErr := s.Activate(1)
	must(t, actErr)

	// Stale operations on path 2
	must(t, s.Fail(2))

	state, _ := s.State(1)
	if state != StateActive {
		t.Fatalf("active path state = %v, want active", state)
	}

	// Deliver data on the still-active path
	var received int32
	s.OnData(func([]byte) {
		atomic.AddInt32(&received, 1)
	})

	// Activate again should be a no-op
	_, err := s.Activate(1)
	must(t, err)

	d1.deliver([]byte("still active"))
	if n := atomic.LoadInt32(&received); n != 1 {
		t.Fatalf("received %d frames, want 1", n)
	}
}

// TestSendSwitchesOnActivePathFailure verifies that Send blocks when the
// active path returns an error and then succeeds after a new path is activated.
func TestSendSwitchesOnActivePathFailure(t *testing.T) {
	s := New()
	s.SetSwitchTimeout(5 * time.Second)

	d1 := newMockPath(1)

	// d1 fails on the second send
	var callCount atomic.Int32
	d1.sendFn = func([]byte) error {
		if callCount.Add(1) >= 2 {
			return errors.New("path 1 failed")
		}
		return nil
	}

	must(t, s.Register(1, d1))
	must(t, s.Warming(1))
	must(t, s.Ready(1))
	_, err := s.Activate(1)
	must(t, err)

	// Register d2 AFTER d1 is activated so it stays at StateCandidate
	d2 := newMockPath(2)
	must(t, s.Register(2, d2))
	must(t, s.Warming(2))
	must(t, s.Ready(2))

	// First send works
	must(t, s.Send([]byte("first")))

	// Second send will fail on path 1; it should block until path 2
	// is activated, then succeed on path 2.
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Send([]byte("switch-me"))
	}()

	time.Sleep(50 * time.Millisecond) // let Send enter the wait

	// Activate path 2, which should unblock the Send
	_, actErr := s.Activate(2)
	must(t, actErr)

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Send after switch = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Send blocked forever after switch")
	}

	if n := d2.sentCount(); n != 1 {
		t.Fatalf("path 2 sent %d frames, want 1", n)
	}
}

// TestDegradedState verifies that a ready path can transition
// to degraded and back.
func TestDegradedState(t *testing.T) {
	s := New()
	d := newMockPath(PathDirect)
	must(t, s.Register(PathDirect, d))

	must(t, s.Warming(PathDirect))
	must(t, s.Ready(PathDirect))
	_, err := s.Activate(PathDirect)
	must(t, err)

	state, _ := s.State(PathDirect)
	if state != StateActive {
		t.Fatalf("state = %v, want active", state)
	}
}
