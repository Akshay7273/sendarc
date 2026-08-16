package transfer

import (
	"testing"
	"time"
)

// The adaptive selection policy adds negligible cost per ICE observation; these benchmarks
// guard that doing the right thing on the direct/relay race does not become a hot path.

// BenchmarkAdaptivePolicyObserveThroughput measures per-observation decision cost (the
// policy is called from every ICE gathering/connection state change).
func BenchmarkAdaptivePolicyObserveThroughput(b *testing.B) {
	p := NewAdaptivePolicy(0)
	ev := AdaptiveEvent{
		Gathering:          gatheringGathering,
		Connection:         connChecking,
		HasServerReflexive: true,
		HasAnyCandidate:    true,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.Observe(ev)
	}
}

// BenchmarkAdaptiveHostOnlyDecisionToWarm measures how quickly the policy produces a
// warm-relay decision for a host-only direct attempt that stalls past its escalation window
// (the fallback that replaces the old blind fixed-duration timer).
func BenchmarkAdaptiveHostOnlyDecisionToWarm(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var fake time.Time
		p := NewAdaptivePolicy(10 * time.Second)
		p.setClock(func() time.Time { return fake })
		_ = p.Observe(AdaptiveEvent{Gathering: gatheringComplete, HasAnyCandidate: true})
		fake = fake.Add(11 * time.Second)
		_ = p.Observe(AdaptiveEvent{Connection: connChecking, HasAnyCandidate: true})
	}
}
