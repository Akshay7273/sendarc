package wire

import (
	"time"
)

// ICEConfigTTL bounds how long a runtime-fetched ICE config may be reused before it must be
// re-fetched. It exists so that any short-lived TURN credential an operator publishes never
// outlives its validity in a client cache. Config without credentials may be held longer, but
// enforcing a single TTL is simpler and safe: the endpoint is tiny and served with no-cache.
const ICEConfigTTL = 15 * time.Minute

// ICEConfigCache holds a fetched ICE config and the time it was obtained so callers can refuse
// to reuse short-lived credentials past ICEConfigTTL.
type ICEConfigCache struct {
	Entries []ICEEntry
	Fetched time.Time
}

// NewICEConfigCache records a freshly fetched config at now.
func NewICEConfigCache(entries []ICEEntry, now time.Time) *ICEConfigCache {
	return &ICEConfigCache{Entries: entries, Fetched: now}
}

// Stale reports whether the config has been cached longer than ICEConfigTTL. A stale config
// must be re-fetched (or have its credential-bearing entries dropped) before reuse.
func (c *ICEConfigCache) Stale(now time.Time) bool {
	return !c.Fetched.IsZero() && now.Sub(c.Fetched) >= ICEConfigTTL
}
