// Package supervisor owns connection path lifecycle and selection, independent of
// transport details and transfer-engine semantics. It manages candidates, tracks
// their states, and guarantees at most one active path at any time. Stale callbacks
// are rejected via epoch generation, mirroring the browser's GenerationGuard.
package supervisor

import (
	"errors"
	"sync"
	"time"

	"github.com/sendbeam/wire"
)

// ErrClosed is returned by Send/Active once the supervisor has been closed.
var ErrClosed = wire.Errorf(wire.CodeConnection, "supervisor: closed")

// ErrNoActivePath is returned when no path is currently active.
var ErrNoActivePath = errors.New("supervisor: no active path")

// defaultSwitchTimeout is the default bound for how long Send waits for a new
// active path after the previous one fails.
const defaultSwitchTimeout = 15 * time.Second

// BytePath is the transport surface the supervisor manages. Every candidate
// must implement Send, OnData, and Close.
type BytePath interface {
	Send([]byte) error
	OnData(func([]byte))
	Close() error
}

// OnSwitch is called when the active path changes. It is the supervisor's
// equivalent of TransportChanged on the transfer engine.
type OnSwitch func()

// pathEntry tracks one candidate within the supervisor.
type pathEntry struct {
	id    PathID
	path  BytePath
	state PathState
}

// Supervisor manages connection path lifecycle and selection.
type Supervisor struct {
	mu sync.Mutex

	paths  map[PathID]*pathEntry
	active *pathEntry
	epoch  uint64
	closed bool

	onSwitch OnSwitch

	// lazySend records frames that arrive before any path is active.
	lazySend [][]byte

	// switchCh is closed when a new path becomes active after a failure,
	// allowing Send to block until the switch completes.
	switchCh chan struct{}

	// switchTimeout bounds how long Send waits for a new active path
	// after the previous one fails.
	switchTimeout time.Duration
}

// New creates a supervisor.
func New() *Supervisor {
	return &Supervisor{
		paths:         make(map[PathID]*pathEntry),
		switchCh:      make(chan struct{}),
		switchTimeout: defaultSwitchTimeout,
	}
}

// SetOnSwitch registers a callback invoked when the active path changes.
func (s *Supervisor) SetOnSwitch(fn OnSwitch) {
	s.mu.Lock()
	s.onSwitch = fn
	s.mu.Unlock()
}

// Register adds a candidate path. If the supervisor is already closed the
// candidate is closed immediately. id must be unique.
func (s *Supervisor) Register(id PathID, p BytePath) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		_ = p.Close()
		return ErrClosed
	}
	if _, exists := s.paths[id]; exists {
		_ = p.Close()
		return wire.Errorf(wire.CodeConnection, "supervisor: duplicate path id %v", id)
	}
	s.paths[id] = &pathEntry{id: id, path: p, state: StateCandidate}
	return nil
}

// Warming transitions a candidate from candidate to warming.
func (s *Supervisor) Warming(id PathID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.transitionLocked(id, StateCandidate, StateWarming)
}

// Ready transitions a candidate from warming to ready.
func (s *Supervisor) Ready(id PathID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.transitionLocked(id, StateWarming, StateReady)
}

// Fail transitions a candidate to failed from any non-terminal state.
func (s *Supervisor) Fail(id PathID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.paths[id]
	if !ok {
		return wire.Errorf(wire.CodeConnection, "supervisor: unknown path %v", id)
	}
	if entry.state == StateClosed || entry.state == StateFailed {
		return nil
	}
	entry.state = StateFailed
	_ = entry.path.Close()
	return nil
}

// Activate promotes a candidate to active and closes all other candidates.
// It returns the epoch at which this activation is valid.
func (s *Supervisor) Activate(id PathID) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return 0, ErrClosed
	}
	entry, ok := s.paths[id]
	if !ok {
		return 0, wire.Errorf(wire.CodeConnection, "supervisor: unknown path %v", id)
	}
	if entry.state == StateClosed || entry.state == StateFailed {
		return 0, wire.Errorf(wire.CodeConnection, "supervisor: cannot activate %v path (state=%v)", id, entry.state)
	}
	if s.active != nil && s.active.id == id && s.active.state == StateActive {
		return s.epoch, nil
	}

	s.epoch++
	if entry.state != StateReady && entry.state != StateActive {
		return 0, wire.Errorf(wire.CodeConnection, "supervisor: path %v cannot activate from state %v", id, entry.state)
	}
	entry.state = StateActive
	s.active = entry

	for _, other := range s.paths {
		if other.id != id && other.state != StateClosed && other.state != StateFailed {
			other.state = StateClosed
			_ = other.path.Close()
		}
	}

	s.drainLazyLocked()
	s.broadcastSwitchLocked()

	epoch := s.epoch
	if s.onSwitch != nil {
		s.onSwitch()
	}
	return epoch, nil
}

// Active returns the active BytePath and its current epoch. Returns
// ErrNoActivePath if no path is active, ErrClosed if the supervisor is closed.
func (s *Supervisor) Active() (BytePath, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, 0, ErrClosed
	}
	if s.active == nil {
		return nil, 0, ErrNoActivePath
	}
	return s.active.path, s.epoch, nil
}

// Send delivers a frame to the active path, or buffers it if none is active yet.
// If the active path returns an error, it blocks until a new active path is
// promoted (or the switch timeout expires or the supervisor closes).
func (s *Supervisor) Send(frame []byte) error {
	for {
		ch, err := s.sendOne(frame)
		if err == nil {
			return nil
		}
		// If the error is ErrClosed or a connection-level error, try to
		// wait for a switch.
		if errors.Is(err, ErrClosed) {
			return err
		}
		// Wait for a new active path.
		select {
		case <-ch:
			continue
		case <-time.After(s.switchTimeout):
			return wire.Errorf(wire.CodeConnection, "supervisor: switch timeout")
		}
	}
}

// sendOne tries to send on the active path. On success returns (nil, nil).
// On an active-path failure returns (switchCh, error) so the caller can wait
// for a new path. On closed returns (nil, ErrClosed).
func (s *Supervisor) sendOne(frame []byte) (<-chan struct{}, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrClosed
	}
	if s.active == nil {
		s.lazySend = append(s.lazySend, append([]byte(nil), frame...))
		s.mu.Unlock()
		return nil, nil
	}
	path := s.active.path
	ch := s.switchCh
	s.mu.Unlock()

	err := path.Send(frame)
	if err == nil {
		return nil, nil
	}
	// On error, check if the supervisor was closed during the Send call.
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil, ErrClosed
	}
	return ch, err
}

// OnData registers a handler for inbound frames. If data arrives on a
// non-active path that is ready, the supervisor activates it automatically.
func (s *Supervisor) OnData(handler func([]byte)) {
	s.mu.Lock()
	paths := make([]*pathEntry, 0, len(s.paths))
	for _, entry := range s.paths {
		paths = append(paths, entry)
	}
	s.mu.Unlock()

	for _, entry := range paths {
		entry.path.OnData(func(frame []byte) {
			deliver, promoted := s.promoteOnData(entry)
			if !deliver {
				return
			}
			if promoted {
				handler(frame)
				return
			}
			handler(frame)
		})
	}
}

// promoteOnData checks whether data from entry should be delivered and
// promotes the entry to active if it is ready. Returns (deliver, promoted).
func (s *Supervisor) promoteOnData(entry *pathEntry) (bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return false, false
	}
	if s.active != nil && s.active.id == entry.id && entry.state == StateActive {
		return true, false
	}
	if entry.state == StateReady {
		entry.state = StateActive
		s.active = entry
		s.epoch++
		var closables []BytePath
		for _, other := range s.paths {
			if other.id != entry.id && other.state != StateClosed && other.state != StateFailed {
				other.state = StateClosed
				closables = append(closables, other.path)
			}
		}
		s.broadcastSwitchLocked()
		s.mu.Unlock()
		for _, p := range closables {
			_ = p.Close()
		}
		if s.onSwitch != nil {
			s.onSwitch()
		}
		s.mu.Lock()
		return true, true
	}
	return false, false
}

// Close shuts down all paths and marks the supervisor as closed. Idempotent.
func (s *Supervisor) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	paths := make([]BytePath, 0, len(s.paths))
	for _, entry := range s.paths {
		paths = append(paths, entry.path)
	}
	s.paths = nil
	s.active = nil
	s.broadcastSwitchLocked()
	s.mu.Unlock()

	var firstErr error
	for _, p := range paths {
		if err := p.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// State returns the current state of a registered path.
func (s *Supervisor) State(id PathID) (PathState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.paths[id]
	if !ok {
		return StateClosed, false
	}
	return entry.state, true
}

// IsClosed reports whether the supervisor is closed.
func (s *Supervisor) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// SetSwitchTimeout sets the maximum time Send will wait for a new active
// path after the current one fails. For testing only.
func (s *Supervisor) SetSwitchTimeout(d time.Duration) {
	s.mu.Lock()
	s.switchTimeout = d
	s.mu.Unlock()
}

// Epoch returns the current epoch (activation generation).
func (s *Supervisor) Epoch() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.epoch
}

// --- internal ---

func (s *Supervisor) transitionLocked(id PathID, from, to PathState) error {
	if s.closed {
		return ErrClosed
	}
	entry, ok := s.paths[id]
	if !ok {
		return wire.Errorf(wire.CodeConnection, "supervisor: unknown path %v", id)
	}
	if entry.state != from {
		return wire.Errorf(wire.CodeConnection, "supervisor: path %v state %v cannot transition to %v", id, entry.state, to)
	}
	entry.state = to
	return nil
}

func (s *Supervisor) broadcastSwitchLocked() {
	old := s.switchCh
	s.switchCh = make(chan struct{})
	close(old)
}

func (s *Supervisor) drainLazyLocked() {
	if len(s.lazySend) == 0 {
		return
	}
	buf := s.lazySend
	s.lazySend = nil
	if s.active == nil {
		return
	}
	path := s.active.path
	for _, frame := range buf {
		_ = path.Send(frame)
	}
}
