package signal

import (
	"context"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// newTestPeer builds a peer without a socket, for hub-logic tests that never write.
func newTestPeer() *peer {
	return &peer{
		room:             -1,
		send:             make(chan outboundFrame, sendBuffer),
		relayRate:        newTokenBucket(1<<20, 1<<20),
		relayControlRate: newTokenBucket(128, 64),
		done:             make(chan struct{}),
		closed:           make(chan struct{}),
	}
}

func testHub(t *testing.T) *Hub {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return NewHub(ctx, DefaultConfig(), nil)
}

func TestCreateRoomAllocatesSmallestFree(t *testing.T) {
	h := testHub(t)

	a, b, c := newTestPeer(), newTestPeer(), newTestPeer()
	if n := h.createRoom(a); n != 0 {
		t.Fatalf("first room = %d, want 0", n)
	}
	if n := h.createRoom(b); n != 1 {
		t.Fatalf("second room = %d, want 1", n)
	}
	if n := h.createRoom(c); n != 2 {
		t.Fatalf("third room = %d, want 2", n)
	}

	// Freeing room 1 makes it the smallest free slot again.
	h.remove(b)
	d := newTestPeer()
	if n := h.createRoom(d); n != 1 {
		t.Fatalf("reused room = %d, want 1", n)
	}
}

func TestJoinPairsAndIsOneToOne(t *testing.T) {
	h := testHub(t)
	off := newTestPeer()
	room := h.createRoom(off)

	join := newTestPeer()
	other, code := h.join(join, room)
	if code != "" {
		t.Fatalf("join failed: %s", code)
	}
	if other != off {
		t.Fatal("join did not return the offerer")
	}
	if off.role != roleOfferer || join.role != roleJoiner {
		t.Fatalf("roles = %q/%q", off.role, join.role)
	}

	// A second join for the same room is refused: strict 1:1.
	third := newTestPeer()
	if _, code := h.join(third, room); code != errRoomFull {
		t.Fatalf("third join code = %q, want %q", code, errRoomFull)
	}
}

func TestJoinUnknownRoom(t *testing.T) {
	h := testHub(t)
	if _, code := h.join(newTestPeer(), 999); code != errUnknownRoom {
		t.Fatalf("code = %q, want %q", code, errUnknownRoom)
	}
}

func TestPartnerAndRemove(t *testing.T) {
	h := testHub(t)
	off := newTestPeer()
	room := h.createRoom(off)
	join := newTestPeer()
	if _, code := h.join(join, room); code != "" {
		t.Fatalf("join: %s", code)
	}

	if h.partner(off) != join || h.partner(join) != off {
		t.Fatal("partner lookup wrong")
	}

	// Removing one peer returns the other and deletes the room.
	if other := h.remove(off); other != join {
		t.Fatal("remove did not surface the partner")
	}
	if h.roomCount() != 0 {
		t.Fatalf("room count = %d, want 0", h.roomCount())
	}
	if h.partner(join) != nil {
		t.Fatal("partner of a removed room should be nil")
	}
}

func TestReapClosesIdleRooms(t *testing.T) {
	h := testHub(t)
	off := newTestPeer()
	h.createRoom(off)

	// Backdate the room past the idle timeout, then reap.
	h.mu.Lock()
	for _, r := range h.rooms {
		r.lastSeen = time.Now().Add(-2 * h.cfg.IdleTimeout)
	}
	h.mu.Unlock()

	h.reapOnce(time.Now())
	if h.roomCount() != 0 {
		t.Fatalf("room count after reap = %d, want 0", h.roomCount())
	}
	select {
	case <-off.done:
		// closed as expected
	default:
		t.Fatal("reaped peer was not closed")
	}
}

func TestTokenBucket(t *testing.T) {
	b := newTokenBucket(2, 1) // burst 2, 1 token/sec
	t0 := time.Now()

	if !b.allowAt(t0) {
		t.Fatal("first call should be allowed by burst")
	}
	if !b.allowAt(t0) {
		t.Fatal("second call should be allowed by burst")
	}
	if b.allowAt(t0) {
		t.Fatal("third call in the same instant should be denied")
	}
	if !b.allowAt(t0.Add(time.Second)) {
		t.Fatal("one token should have refilled after a second")
	}
	if b.allowAt(t0.Add(time.Second)) {
		t.Fatal("only one token should refill per second")
	}
}

func TestTokenBucketWeightedBytes(t *testing.T) {
	b := newTokenBucket(10, 10)
	t0 := time.Now()
	if !b.allowNAt(7, t0) || b.allowNAt(4, t0) {
		t.Fatal("weighted burst accounting did not enforce the byte ceiling")
	}
	if !b.allowNAt(4, t0.Add(100*time.Millisecond)) {
		t.Fatal("weighted bucket did not refill one byte")
	}
}

func TestPeerRelayQueueIsByteBounded(t *testing.T) {
	h := testHub(t)
	h.cfg.RelayQueueBytes = 32
	p := newTestPeer()
	p.hub = h
	if !p.tryEnqueue(websocket.MessageBinary, make([]byte, 24)) {
		t.Fatal("first bounded relay frame was refused")
	}
	if p.tryEnqueue(websocket.MessageBinary, make([]byte, 9)) {
		t.Fatal("queue accepted bytes above its configured ceiling")
	}
	p.queueMu.Lock()
	queued := p.queuedBytes
	p.queueMu.Unlock()
	if queued != 24 {
		t.Fatalf("queued bytes = %d, want 24", queued)
	}
}
