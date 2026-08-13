package transfer

import (
	"testing"
	"time"
)

func testObserve(t *testing.T, p *AdaptivePolicy, ev AdaptiveEvent) AdaptiveDecision {
	t.Helper()
	return p.Observe(ev)
}

// TestAdaptiveDirectWins proves the policy chooses direct when a server-reflexive hint is seen
// and the connection comes up before any fallback.
func TestAdaptiveDirectWins(t *testing.T) {
	p := NewAdaptivePolicy(0)
	for _, ev := range []AdaptiveEvent{
		{Gathering: gatheringNew, Connection: connNew},
		{Gathering: gatheringGathering, Connection: connChecking, HasAnyCandidate: true},
		{Connection: connChecking, HasAnyCandidate: true, HasServerReflexive: true},
		{Gathering: gatheringGathering},
		{Connection: connConnected, HasAnyCandidate: true, HasServerReflexive: true},
	} {
		if d := testObserve(t, p, ev); d != DecisionContinue && d != DecisionDirectWon {
			t.Fatalf("unexpected decision %q on %+v", d, ev)
		}
	}
	if d := p.Observe(AdaptiveEvent{Connection: connConnected}); d != DecisionDirectWon {
		t.Fatalf("expected direct-won after connected, got %q", d)
	}
}

// TestAdaptiveRelayWinsNoCandidates proves the policy warms the relay immediately when
// gathering completes having produced no candidate at all (no direct path to attempt).
func TestAdaptiveRelayWinsNoCandidates(t *testing.T) {
	p := NewAdaptivePolicy(0)
	if d := testObserve(t, p, AdaptiveEvent{Gathering: gatheringComplete}); d != DecisionWarmRelay {
		t.Fatalf("expected warm-relay on zero-candidate gathering complete, got %q", d)
	}
}

// TestAdaptiveHostOnlyKeepsRacing proves host-only candidates (loopback/LAN) keep direct in
// the race rather than falling back immediately: direct can still connect without STUN.
func TestAdaptiveHostOnlyKeepsRacing(t *testing.T) {
	var fake time.Time
	p := NewAdaptivePolicy(5 * time.Second)
	p.setClock(func() time.Time { return fake })

	if d := testObserve(t, p, AdaptiveEvent{Gathering: gatheringComplete, HasAnyCandidate: true}); d != DecisionContinue {
		t.Fatalf("host-only gathering complete should keep racing, got %q", d)
	}
	fake = fake.Add(2 * time.Second)
	if d := testObserve(t, p, AdaptiveEvent{Connection: connChecking, HasAnyCandidate: true}); d != DecisionContinue {
		t.Fatalf("host-only should still race before deadline, got %q", d)
	}
	if d := testObserve(t, p, AdaptiveEvent{Connection: connConnected}); d != DecisionDirectWon {
		t.Fatalf("host-only direct reached connected; want direct-won, got %q", d)
	}
}

// TestAdaptiveRelayWinsOnICEFailed proves a failed ICE connection triggers an immediate relay
// warm regardless of hints.
func TestAdaptiveRelayWinsOnICEFailed(t *testing.T) {
	p := NewAdaptivePolicy(0)
	if d := testObserve(t, p, AdaptiveEvent{Connection: connFailed}); d != DecisionWarmRelay {
		t.Fatalf("expected warm-relay on ICE failed, got %q", d)
	}
}

// TestAdaptiveLateDirect keeps racing when a server-reflexive hint has appeared, so a
// slow-but-healthy direct path is not preempted by an escalation deadline.
func TestAdaptiveLateDirect(t *testing.T) {
	var fake time.Time
	p := NewAdaptivePolicy(5 * time.Second)
	p.setClock(func() time.Time { return fake })

	if d := testObserve(t, p, AdaptiveEvent{Connection: connChecking, HasAnyCandidate: true, HasServerReflexive: true}); d != DecisionContinue {
		t.Fatalf("expected continue on srflx hint, got %q", d)
	}
	fake = fake.Add(10 * time.Hour)
	if d := testObserve(t, p, AdaptiveEvent{Gathering: gatheringGathering, Connection: connChecking}); d != DecisionContinue {
		t.Fatalf("expected continue past deadline with srflx hint, got %q", d)
	}
	if d := testObserve(t, p, AdaptiveEvent{Connection: connConnected}); d != DecisionDirectWon {
		t.Fatalf("expected direct-won for late direct, got %q", d)
	}
}

// TestAdaptiveBothReady lets both paths be viable and then the race resolves on whichever
// connects first; the policy commits to direct-won on connected and keeps that decision.
func TestAdaptiveBothReady(t *testing.T) {
	p := NewAdaptivePolicy(0)
	testObserve(t, p, AdaptiveEvent{Connection: connChecking, HasAnyCandidate: true, HasServerReflexive: true})
	if d := testObserve(t, p, AdaptiveEvent{Connection: connConnected}); d != DecisionDirectWon {
		t.Fatalf("expected direct-won, got %q", d)
	}
	if d := testObserve(t, p, AdaptiveEvent{Connection: connFailed}); d != DecisionDirectWon {
		t.Fatalf("settled decision flipped to %q", d)
	}
	if !p.ScalableDirect() {
		t.Fatal("ScalableDirect should remain true after direct-won")
	}
}

// TestAdaptiveSimultaneousFailure verifies that, with no candidate, a stalled-then-failed
// connection resolves to a relay warm (bounded by escalation, then confirmed).
func TestAdaptiveSimultaneousFailure(t *testing.T) {
	var fake time.Time
	p := NewAdaptivePolicy(2 * time.Second)
	p.setClock(func() time.Time { return fake })

	if d := testObserve(t, p, AdaptiveEvent{Connection: connChecking}); d != DecisionContinue {
		t.Fatalf("expected continue while checking, got %q", d)
	}
	fake = fake.Add(3 * time.Second)
	if d := testObserve(t, p, AdaptiveEvent{Connection: connFailed}); d != DecisionWarmRelay {
		t.Fatalf("expected warm-relay on failed after escalation window, got %q", d)
	}
}

// TestAdaptiveCancelDuringRace verifies the policy remains quiescent and never settles on
// either path when only transient/new observations arrive (the driver cancels via context).
func TestAdaptiveCancelDuringRace(t *testing.T) {
	p := NewAdaptivePolicy(10 * time.Second)
	if d := testObserve(t, p, AdaptiveEvent{Gathering: gatheringNew}); d != DecisionContinue {
		t.Fatalf("expected continue on new, got %q", d)
	}
	if d := testObserve(t, p, AdaptiveEvent{Gathering: gatheringGathering, Connection: connChecking}); d != DecisionContinue {
		t.Fatalf("expected continue while racing, got %q", d)
	}
	if !p.ScalableDirect() {
		t.Fatal("policy should still consider direct scalable while racing")
	}
}

// TestAdaptiveEscalationBoundedNoCandidates proves that, without any candidate and without a
// gathering-complete event, the bounded escalation past its deadline warms the relay.
func TestAdaptiveEscalationBoundedNoCandidates(t *testing.T) {
	var fake time.Time
	p := NewAdaptivePolicy(2 * time.Second)
	p.setClock(func() time.Time { return fake })

	testObserve(t, p, AdaptiveEvent{Connection: connChecking})
	fake = fake.Add(1 * time.Second)
	if d := testObserve(t, p, AdaptiveEvent{Connection: connChecking}); d != DecisionContinue {
		t.Fatalf("expected continue before deadline, got %q", d)
	}
	fake = fake.Add(2 * time.Second)
	if d := testObserve(t, p, AdaptiveEvent{Connection: connChecking}); d != DecisionWarmRelay {
		t.Fatalf("expected warm-relay after deadline, got %q", d)
	}
}

// TestAdaptiveEscalationBoundedHostOnly proves a host-only direct path that never connects
// still falls back once the bounded escalation deadline passes.
func TestAdaptiveEscalationBoundedHostOnly(t *testing.T) {
	var fake time.Time
	p := NewAdaptivePolicy(2 * time.Second)
	p.setClock(func() time.Time { return fake })

	testObserve(t, p, AdaptiveEvent{Gathering: gatheringComplete, HasAnyCandidate: true})
	fake = fake.Add(1 * time.Second)
	if d := testObserve(t, p, AdaptiveEvent{Connection: connChecking}); d != DecisionContinue {
		t.Fatalf("expected continue before deadline, got %q", d)
	}
	fake = fake.Add(3 * time.Second)
	if d := testObserve(t, p, AdaptiveEvent{Connection: connChecking}); d != DecisionWarmRelay {
		t.Fatalf("expected warm-relay after deadline for stuck host-only, got %q", d)
	}
}

// TestAdaptiveDefaultEscalationFasterThanLegacyBlindTimer pins the production default
// escalation window below the old blind ~8s fallback timer, so restrictive-network
// fallback (udp-blocked / host-only symmetric NAT) engages sooner than the legacy baseline.
func TestAdaptiveDefaultEscalationFasterThanLegacyBlindTimer(t *testing.T) {
	const legacyBlindTimer = 8 * time.Second
	p := NewAdaptivePolicy(0)
	if got := p.escalation; got <= 0 || got >= legacyBlindTimer {
		t.Fatalf("default escalation = %v, want 0 < escalation < %v so restrictive fallback beats the legacy blind timer", got, legacyBlindTimer)
	}
}
