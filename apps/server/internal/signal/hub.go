package signal

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Hub owns every room and the goroutine that reaps idle ones. A room holds at most
// two peers — the offerer that created it and the joiner that paired in.
type Hub struct {
	cfg    Config
	logger *slog.Logger

	mu    sync.Mutex
	rooms map[int]*room

	// connLimiters is the per-IP connection-rate limiter, checked at upgrade time.
	connMu       sync.Mutex
	connLimiters map[string]*tokenBucket
}

type room struct {
	number   int
	offerer  *peer
	joiner   *peer
	lastSeen time.Time
}

// NewHub builds a Hub and starts its reaper. The reaper stops when ctx is canceled.
func NewHub(ctx context.Context, cfg Config, logger *slog.Logger) *Hub {
	h := &Hub{
		cfg:          cfg,
		logger:       orDiscard(logger),
		rooms:        make(map[int]*room),
		connLimiters: make(map[string]*tokenBucket),
	}
	go h.reap(ctx)
	return h
}

// allowConnection reports whether a new connection from ip is within the per-IP
// connection-rate limit.
func (h *Hub) allowConnection(ip string) bool {
	h.connMu.Lock()
	defer h.connMu.Unlock()
	b, ok := h.connLimiters[ip]
	if !ok {
		b = newTokenBucket(h.cfg.ConnBurst, h.cfg.ConnPerSec)
		h.connLimiters[ip] = b
	}
	return b.allow()
}

// createRoom allocates the smallest free room number, seats p as its offerer, and
// returns the room number.
func (h *Hub) createRoom(p *peer) int {
	h.mu.Lock()
	defer h.mu.Unlock()

	n := 0
	for {
		if _, taken := h.rooms[n]; !taken {
			break
		}
		n++
	}
	h.rooms[n] = &room{number: n, offerer: p, lastSeen: time.Now()}
	p.room = n
	p.role = roleOfferer
	return n
}

// join seats p as the joiner of an existing room and returns the offerer it paired
// with. It enforces strict 1:1 pairing: an unknown or already-full room is refused.
func (h *Hub) join(p *peer, number int) (*peer, string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	r, ok := h.rooms[number]
	if !ok {
		return nil, errUnknownRoom
	}
	if r.joiner != nil || r.offerer == nil {
		return nil, errRoomFull
	}
	r.joiner = p
	r.lastSeen = time.Now()
	p.room = number
	p.role = roleJoiner
	return r.offerer, ""
}

// partner returns the other peer in p's room, or nil if the room is gone or p is not
// yet paired. It also refreshes the room's activity timestamp.
func (h *Hub) partner(p *peer) *peer {
	h.mu.Lock()
	defer h.mu.Unlock()

	r, ok := h.rooms[p.room]
	if !ok {
		return nil
	}
	r.lastSeen = time.Now()
	switch p {
	case r.offerer:
		return r.joiner
	case r.joiner:
		return r.offerer
	default:
		return nil
	}
}

// remove drops p from its room. If a partner remains it is returned so the caller can
// notify it; the room is then deleted when either peer leaves.
func (h *Hub) remove(p *peer) *peer {
	h.mu.Lock()
	defer h.mu.Unlock()

	r, ok := h.rooms[p.room]
	if !ok {
		return nil
	}
	var other *peer
	switch p {
	case r.offerer:
		other = r.joiner
	case r.joiner:
		other = r.offerer
	default:
		return nil
	}
	delete(h.rooms, r.number)
	return other
}

// reap periodically frees rooms whose last activity is older than the idle timeout,
// closing any sockets still attached. It runs until ctx is canceled.
func (h *Hub) reap(ctx context.Context) {
	interval := h.cfg.IdleTimeout / 2
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			h.reapOnce(now)
		}
	}
}

func (h *Hub) reapOnce(now time.Time) {
	h.mu.Lock()
	var stale []*room
	for n, r := range h.rooms {
		if now.Sub(r.lastSeen) > h.cfg.IdleTimeout {
			stale = append(stale, r)
			delete(h.rooms, n)
		}
	}
	h.mu.Unlock()

	for _, r := range stale {
		h.logger.Info("signal: reaping idle room", "room", r.number)
		for _, p := range []*peer{r.offerer, r.joiner} {
			if p != nil {
				p.close(byeFrame("idle timeout"))
			}
		}
	}
}

// roomCount reports the number of live rooms (used by tests).
func (h *Hub) roomCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.rooms)
}
