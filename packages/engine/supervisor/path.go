package supervisor

import "sync/atomic"

// PathState represents the lifecycle of a connection candidate.
type PathState int

const (
	// StateCandidate is a new candidate that is not yet being established.
	StateCandidate PathState = iota
	// StateWarming is a candidate whose establishment has begun.
	StateWarming
	// StateReady is a candidate that is open but not yet selected.
	StateReady
	// StateActive is the single candidate currently carrying bytes.
	StateActive
	// StateDegraded is an active candidate that is underperforming.
	StateDegraded
	// StateFailed is a candidate that could not be established.
	StateFailed
	// StateClosed is a candidate that was shut down after losing selection.
	StateClosed
)

func (s PathState) String() string {
	switch s {
	case StateCandidate:
		return "candidate"
	case StateWarming:
		return "warming"
	case StateReady:
		return "ready"
	case StateActive:
		return "active"
	case StateDegraded:
		return "degraded"
	case StateFailed:
		return "failed"
	case StateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

// Epoch is a monotonic counter that invalidates stale callbacks,
// mirroring GenerationGuard semantics.
type Epoch struct {
	val atomic.Uint64
}

// NewEpoch returns a supervisor path epoch initialized to zero.
func NewEpoch() *Epoch { return &Epoch{} }

// Current returns the current epoch generation.
func (e *Epoch) Current() uint64 { return e.val.Load() }

// Bump advances the epoch and returns its new value.
func (e *Epoch) Bump() uint64 { return e.val.Add(1) }

// IsCurrent reports whether captured is the current epoch generation.
func (e *Epoch) IsCurrent(captured uint64) bool { return captured == e.val.Load() }

// PathID uniquely identifies a candidate within a supervisor.
type PathID int

const (
	// PathDirect identifies the direct WebRTC path.
	PathDirect PathID = iota
	// PathRelay identifies the encrypted relay path.
	PathRelay
)
