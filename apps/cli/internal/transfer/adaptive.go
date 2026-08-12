package transfer

import (
	"sync"
	"time"
)

// This file implements the adaptive direct/relay selection policy that replaces the old
// blind fixed-duration fallback. Rather than waiting out an arbitrary window before opening
// the relay, the policy watches ICE progress telemetry and warms the relay only when the
// direct path is shown (or strongly indicated) not to be viable.
//
// The policy is deliberately transport-agnostic: it consumes ordinary gathering/connection
// state names so the same decision logic is mirrored verbatim in the browser
// (apps/web/src/lib/transfer/adaptive.ts). Both peers must agree on the method, not on
// timing — each race resolves on whichever path becomes ready first locally.
type adaptiveGathering string

const (
	gatheringNew       adaptiveGathering = "new"
	gatheringGathering adaptiveGathering = "gathering"
	gatheringComplete  adaptiveGathering = "complete"
)

type adaptiveConnection string

const (
	connNew          adaptiveConnection = "new"
	connChecking     adaptiveConnection = "checking"
	connConnected    adaptiveConnection = "connected"
	connCompleted    adaptiveConnection = "completed"
	connDisconnected adaptiveConnection = "disconnected"
	connFailed       adaptiveConnection = "failed"
	connClosed       adaptiveConnection = "closed"
)

// AdaptiveEvent is a single ICE progress observation fed to the policy.
type AdaptiveEvent struct {
	Gathering adaptiveGathering
	// Connection is the ICE connection state. Empty means no state change yet.
	Connection adaptiveConnection
	// HasServerReflexive reports whether the gathering pass produced at least one
	// srflx/prflx/relay candidate — the strongest hint that a direct path is viable through
	// NAT. Host-only candidates alone are not a server-reflexive hint.
	HasServerReflexive bool
	// HasAnyCandidate reports whether gathering produced any candidate at all (including host).
	// Zero candidates means there is no direct path to attempt.
	HasAnyCandidate bool
}

// AdaptiveDecision is the policy's reasoning for a single observation.
type AdaptiveDecision string

const (
	// DecisionContinue means keep letting the direct path race; do not warm the relay yet.
	DecisionContinue AdaptiveDecision = "continue"
	// DecisionWarmRelay means the direct path is not viable (or stalled) — start warming the
	// encrypted relay so it can win the race promptly.
	DecisionWarmRelay AdaptiveDecision = "warm-relay"
	// DecisionDirectWon means the direct path connected; the relay, if warmed, should be closed.
	DecisionDirectWon AdaptiveDecision = "direct-won"
)

// AdaptivePolicy decides when to warm the relay based on ICE progress. It is a state machine
// driven by AdaptiveEvent observations. It owns no goroutines and serializes its own state, so
// it is safe to feed from multiple ICE callbacks concurrently.
type AdaptivePolicy struct {
	mu        sync.Mutex
	startedAt time.Time
	now       func() time.Time

	scalableDirect   bool
	directViableHint bool
	anyCandidate     bool
	escalDeadline    time.Time
	escalation       time.Duration

	// settled is set once the policy commits to a terminal outcome (warm-relay or direct-won);
	// subsequent observations are ignored.
	settled      bool
	settledDecis AdaptiveDecision
}

// NewAdaptivePolicy creates a policy. escalation bounds how long direct may silently stall
// (ICE connection still "checking" with no viable hint) before the relay is warmed. Zero uses
// a sane production default.
func NewAdaptivePolicy(escalation time.Duration) *AdaptivePolicy {
	if escalation <= 0 {
		escalation = 10 * time.Second
	}
	return &AdaptivePolicy{
		startedAt:      time.Now(),
		now:            time.Now,
		scalableDirect: true,
		escalation:     escalation,
	}
}

// setClock overrides the clock used for escalation deadlines. For tests only.
func (p *AdaptivePolicy) setClock(now func() time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.now = now
}

// Observe feeds one ICE progress event and returns the resulting decision. Once a terminal
// outcome is reached (direct-won or warm-relay), later observations return the settled
// decision.
func (p *AdaptivePolicy) Observe(ev AdaptiveEvent) AdaptiveDecision {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.observeLocked(ev)
}

func (p *AdaptivePolicy) observeLocked(ev AdaptiveEvent) AdaptiveDecision {
	if p.settled {
		return p.settledDecis
	}
	if ev.HasServerReflexive {
		p.directViableHint = true
	}
	if ev.HasAnyCandidate {
		p.anyCandidate = true
	}

	switch ev.Connection {
	case connConnected, connCompleted:
		return p.settle(DecisionDirectWon)
	case connFailed:
		return p.settle(DecisionWarmRelay)
	}

	// Gathering finished having produced no candidate at all: there is no direct path to
	// attempt, so warm the relay immediately. This is V12-PR03's "start fallback immediately
	// when direct has no viable hints".
	if !p.anyCandidate && ev.Gathering == gatheringComplete {
		return p.settle(DecisionWarmRelay)
	}

	if p.anyCandidate {
		// We have at least a host candidate: a direct path is plausible (loopback / LAN).
		// Keep racing it with no absolute fallback once a server-reflexive hint appears, and a
		// bounded escalation otherwise (host-only may or may not reach across NAT).
		if !p.directViableHint {
			p.escalDeadline = p.armEscalation(p.escalDeadline)
			if p.now().After(p.escalDeadline) {
				return p.settle(DecisionWarmRelay)
			}
			return DecisionContinue
		}
		p.escalDeadline = time.Time{}
		return DecisionContinue
	}

	// No candidates gathered yet and gathering not complete. Arm a bounded escalation so a
	// stalled ICE start eventually falls back to the relay.
	p.escalDeadline = p.armEscalation(p.escalDeadline)
	if p.now().After(p.escalDeadline) {
		return p.settle(DecisionWarmRelay)
	}
	return DecisionContinue
}

// armEscalation returns the escalation deadline, arming it if it is not yet set.
func (p *AdaptivePolicy) armEscalation(deadline time.Time) time.Time {
	if !deadline.IsZero() {
		return deadline
	}
	return p.now().Add(p.escalation)
}

// settle commits the policy to a terminal outcome and returns it.
func (p *AdaptivePolicy) settle(d AdaptiveDecision) AdaptiveDecision {
	p.settled = true
	p.settledDecis = d
	p.scalableDirect = d == DecisionDirectWon
	return d
}

// ScalableDirect reports whether the policy still considers the direct path scalable. After a
// relay warm or direct win this is false. Informational only.
func (p *AdaptivePolicy) ScalableDirect() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.scalableDirect
}
