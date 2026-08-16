package rtc

import (
	"context"
	"testing"
	"time"
)

// These benchmarks measure time-to-active-path and time-to-first-payload for the direct
// WebRTC path, separately from throughput. They are the CLI analogue of the adaptive racing
// policy's "connect fast" goal: warming the relay must never slow a healthy direct connect.

// BenchmarkPeerTimeToActivePathDirect measures the latency from peer construction to an open
// DataChannel (the "active path") on a loopback direct connection.
func BenchmarkPeerTimeToActivePathDirect(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		offerer, joiner := linkedPeers(b)

		start := time.Now()
		oc, err := offerer.Channel(ctx)
		if err != nil {
			b.Fatalf("offerer channel: %v", err)
		}
		jc, err := joiner.Channel(ctx)
		if err != nil {
			b.Fatalf("joiner channel: %v", err)
		}
		elapsed := time.Since(start)

		b.StopTimer()
		b.ReportMetric(elapsed.Seconds()*1000, "ms/active-path")

		// Give the goroutines a moment to settle and avoid leaking negotiation loops.
		_ = oc
		_ = jc
		_ = offerer.Close()
		_ = joiner.Close()
		b.StartTimer()
	}
}

// BenchmarkPeerTimeToFirstPayloadDirect measures the latency from peer construction to the
// first data frame delivered across an open channel.
func BenchmarkPeerTimeToFirstPayloadDirect(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	payload := []byte("first-payload-benchmark-frame")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		offerer, joiner := linkedPeers(b)

		first := make(chan struct{}, 1)
		start := time.Now()
		oc, err := offerer.Channel(ctx)
		if err != nil {
			b.Fatalf("offerer channel: %v", err)
		}
		jc, err := joiner.Channel(ctx)
		if err != nil {
			b.Fatalf("joiner channel: %v", err)
		}
		jc.OnData(func([]byte) {
			select {
			case first <- struct{}{}:
			default:
			}
		})
		if err := oc.Send(payload); err != nil {
			b.Fatalf("send: %v", err)
		}
		<-first
		elapsed := time.Since(start)

		b.StopTimer()
		b.ReportMetric(elapsed.Seconds()*1000, "ms/first-payload")
		_ = offerer.Close()
		_ = joiner.Close()
		b.StartTimer()
	}
}
