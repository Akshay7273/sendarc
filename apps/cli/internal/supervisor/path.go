package supervisor

import "sync/atomic"

// PathState represents the lifecycle of a connection candidate.
type PathState int

const (
	StateCandidate PathState = iota
	StateWarming
	StateReady
	StateActive
	StateDegraded
	StateFailed
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

func NewEpoch() *Epoch { return &Epoch{} }

func (e *Epoch) Current() uint64 { return e.val.Load() }

func (e *Epoch) Bump() uint64 { return e.val.Add(1) }

func (e *Epoch) IsCurrent(captured uint64) bool { return captured == e.val.Load() }

// PathID uniquely identifies a candidate within a supervisor.
type PathID int

const (
	PathDirect PathID = iota
	PathRelay
)
