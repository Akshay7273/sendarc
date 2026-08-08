package signal

import (
	"sync"
	"time"
)

// tokenBucket is a minimal token-bucket rate limiter. It refills continuously at a
// fixed rate up to a burst capacity; allow reports whether one token is available
// and, if so, spends it. It is safe for concurrent use.
type tokenBucket struct {
	mu     sync.Mutex
	tokens float64
	burst  float64
	rate   float64 // tokens per second
	last   time.Time
}

func newTokenBucket(burst int, perSec float64) *tokenBucket {
	return &tokenBucket{
		tokens: float64(burst),
		burst:  float64(burst),
		rate:   perSec,
		last:   time.Now(),
	}
}

func (b *tokenBucket) allow() bool {
	return b.allowAt(time.Now())
}

// allowAt is the time-injectable core, kept separate so tests can drive it
// deterministically.
func (b *tokenBucket) allowAt(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(b.burst, b.tokens+elapsed*b.rate)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
