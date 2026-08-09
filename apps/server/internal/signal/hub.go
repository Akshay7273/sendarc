package signal

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/coder/websocket"
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
	number     int
	offerer    *peer
	joiner     *peer
	lastSeen   time.Time
	relayBytes int64
}

// openRelay opts p into the binary path and coordinates a room-wide cutover. The first peer asks
// its partner to follow; the second makes the path ready for both.
func (h *Hub) openRelay(p *peer) (other *peer, ready bool, code string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	r, ok := h.rooms[p.room]
	if !ok {
		return nil, false, errNotPaired
	}
	other = roomPartner(r, p)
	if other == nil {
		return nil, false, errNotPaired
	}
	p.relayOpen = true
	r.lastSeen = time.Now()
	return other, other.relayOpen, ""
}

// grantRelayCredit caps a receiver's grant to one configured window and returns the actual grant
// forwarded to its sending partner.
func (h *Hub) grantRelayCredit(receiver *peer, requested int64) (*peer, int64, string) {
	if requested <= 0 || requested > h.cfg.RelayWindowBytes {
		return nil, 0, errRelayCredit
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	r, ok := h.rooms[receiver.room]
	if !ok {
		return nil, 0, errNotPaired
	}
	sender := roomPartner(r, receiver)
	if sender == nil || !receiver.relayOpen || !sender.relayOpen {
		return nil, 0, errRelayNotReady
	}
	grant := min(requested, h.cfg.RelayWindowBytes-sender.relayCredit)
	if grant <= 0 {
		return sender, 0, ""
	}
	sender.relayCredit += grant
	r.lastSeen = time.Now()
	return sender, grant, ""
}

// forwardRelay reserves sender credit and room byte budget before handing one opaque frame to the
// partner's bounded writer queue. No encrypted frame contents are parsed or logged.
func (h *Hub) forwardRelay(sender *peer, data []byte) string {
	size := int64(len(data))
	if size <= 0 || size > h.cfg.MaxRelayFrameBytes {
		return errRelayLimit
	}
	if !sender.relayRate.allowN(float64(size)) {
		return errRelayLimit
	}

	h.mu.Lock()
	r, ok := h.rooms[sender.room]
	if !ok {
		h.mu.Unlock()
		return errNotPaired
	}
	other := roomPartner(r, sender)
	if other == nil || !sender.relayOpen || !other.relayOpen {
		h.mu.Unlock()
		return errRelayNotReady
	}
	if sender.relayCredit < size {
		h.mu.Unlock()
		return errRelayCredit
	}
	if size > h.cfg.RelayMaxSessionBytes-r.relayBytes {
		h.mu.Unlock()
		return errRelayLimit
	}
	sender.relayCredit -= size
	r.relayBytes += size
	r.lastSeen = time.Now()
	h.mu.Unlock()

	if !other.tryEnqueue(websocket.MessageBinary, append([]byte(nil), data...)) {
		return errRelayLimit
	}
	return ""
}

func roomPartner(r *room, p *peer) *peer {
	if p == r.offerer {
		return r.joiner
	}
	if p == r.joiner {
		return r.offerer
	}
	return nil
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

// resume re-attaches p to a vacated slot of an existing (lingering) room after the peer
// reloaded and lost its ephemeral session. Only the slot for the claimed role may be
// filled, and only if empty; the room and its number are unchanged. It returns the
// surviving partner so the caller can prompt both sides to re-run the handshake.
func (h *Hub) resume(p *peer, number int, role string) (*peer, string) {
	if role != roleOfferer && role != roleJoiner {
		return nil, errBadMessage
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	r, ok := h.rooms[number]
	if !ok {
		return nil, errUnknownRoom
	}
	switch role {
	case roleOfferer:
		if r.offerer != nil {
			return nil, errRoomFull
		}
		r.offerer = p
	case roleJoiner:
		if r.joiner != nil {
			return nil, errRoomFull
		}
		r.joiner = p
	}
	p.room = number
	p.role = role
	r.lastSeen = time.Now()
	return roomPartner(r, p), ""
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

// vacate frees p's slot after an unexpected socket drop. If a partner remains, the room
// is kept — only p's slot is cleared — so the departed peer can reload and re-attach
// (see resume) within the idle window; the partner is returned so the caller can tell it
// to wait. If p was the last peer, the room is deleted and nil is returned.
func (h *Hub) vacate(p *peer) *peer {
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
		r.offerer = nil
	case r.joiner:
		other = r.offerer
		r.joiner = nil
	default:
		return nil
	}
	if other == nil {
		delete(h.rooms, r.number)
		return nil
	}
	r.lastSeen = time.Now()
	return other
}

// discard tears down p's whole room after a graceful bye. Any remaining partner is
// returned so the caller can close it too — a bye ends the session for both peers and is
// never resumable.
func (h *Hub) discard(p *peer) *peer {
	h.mu.Lock()
	defer h.mu.Unlock()

	r, ok := h.rooms[p.room]
	if !ok {
		return nil
	}
	other := roomPartner(r, p)
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
