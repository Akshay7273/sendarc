package main

import (
	"math"
	"testing"
	"time"
)

func TestProgressRateAndETAStabilizeWithinFiveSeconds(t *testing.T) {
	now := time.Unix(0, 0)
	p := newProgressWithClock(10_000, func() time.Time { return now })
	p.report(0)
	for second := 1; second <= 5; second++ {
		now = now.Add(time.Second)
		p.report(int64(second * 1000))
	}
	p.mu.Lock()
	rate, eta := p.rateAndETA()
	p.mu.Unlock()
	if math.Abs(rate-1000) > 0.01 {
		t.Fatalf("rate = %f, want 1000", rate)
	}
	if eta != 5*time.Second {
		t.Fatalf("eta = %s, want 5s", eta)
	}
}

func TestProgressNeverRegresses(t *testing.T) {
	p := newProgressWithClock(100, time.Now)
	p.report(50)
	p.report(40)
	p.mu.Lock()
	got := p.bytes
	p.mu.Unlock()
	if got != 50 {
		t.Fatalf("bytes = %d, want monotonic 50", got)
	}
}

func TestFormatETARoundsUpWhileWorkRemains(t *testing.T) {
	if got := formatETA(100 * time.Millisecond); got != "1s remaining" {
		t.Fatalf("formatETA() = %q, want %q", got, "1s remaining")
	}
}
