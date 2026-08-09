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

	// Freeing room 1 makes it the smallest free slot again. b is the lone peer, so
	// vacate deletes the room outright.
	h.vacate(b)
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

func TestPartnerLookup(t *testing.T) {
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
}

// A partnered peer that drops leaves the room lingering with its slot vacated, so the
// dropped peer can reload and re-attach. The room is only deleted when the last peer goes.
func TestVacateLingersThenDeletes(t *testing.T) {
	h := testHub(t)
	off := newTestPeer()
	room := h.createRoom(off)
	join := newTestPeer()
	if _, code := h.join(join, room); code != "" {
		t.Fatalf("join: %s", code)
	}

	// The offerer drops: its slot is vacated, the joiner surfaces, and the room lingers.
	if other := h.vacate(off); other != join {
		t.Fatal("vacate did not surface the surviving partner")
	}
	if h.roomCount() != 1 {
		t.Fatalf("room count after one drop = %d, want 1 (lingering)", h.roomCount())
	}
	if h.partner(join) != nil {
		t.Fatal("partner of a vacated slot should be nil until a peer re-attaches")
	}

	// The joiner drops too: now the room is empty and deleted.
	if other := h.vacate(join); other != nil {
		t.Fatalf("vacating the last peer should return nil, got %v", other)
	}
	if h.roomCount() != 0 {
		t.Fatalf("room count after last drop = %d, want 0", h.roomCount())
	}
}

// resume re-attaches a reloaded peer to its vacated slot and surfaces the waiting partner.
func TestResumeReattachesVacatedSlot(t *testing.T) {
	h := testHub(t)
	off := newTestPeer()
	room := h.createRoom(off)
	join := newTestPeer()
	if _, code := h.join(join, room); code != "" {
		t.Fatalf("join: %s", code)
	}

	// The offerer drops; the room lingers with the offerer slot empty.
	h.vacate(off)

	// A reloaded offerer resumes into the vacated slot and gets the waiting joiner back.
	reoff := newTestPeer()
	other, code := h.resume(reoff, room, roleOfferer)
	if code != "" {
		t.Fatalf("resume failed: %s", code)
	}
	if other != join {
		t.Fatal("resume did not surface the waiting partner")
	}
	if reoff.room != room || reoff.role != roleOfferer {
		t.Fatalf("resumed peer state = room %d role %q", reoff.room, reoff.role)
	}
	if h.partner(join) != reoff || h.partner(reoff) != join {
		t.Fatal("pairing not restored after resume")
	}
}

// resume is refused when the target slot is still occupied or the room is unknown.
func TestResumeRefusesOccupiedOrUnknown(t *testing.T) {
	h := testHub(t)
	off := newTestPeer()
	room := h.createRoom(off)
	join := newTestPeer()
	if _, code := h.join(join, room); code != "" {
		t.Fatalf("join: %s", code)
	}

	// Both slots are occupied: claiming the offerer role is refused.
	if _, code := h.resume(newTestPeer(), room, roleOfferer); code != errRoomFull {
		t.Fatalf("resume into occupied slot code = %q, want %q", code, errRoomFull)
	}
	// An unknown room is refused.
	if _, code := h.resume(newTestPeer(), 999, roleJoiner); code != errUnknownRoom {
		t.Fatalf("resume into unknown room code = %q, want %q", code, errUnknownRoom)
	}
	// A bad role is rejected before any room lookup.
	if _, code := h.resume(newTestPeer(), room, "bogus"); code != errBadMessage {
		t.Fatalf("resume with bad role code = %q, want %q", code, errBadMessage)
	}
}

// discard tears down the whole room on a graceful bye and surfaces the partner to close.
func TestDiscardTearsDownRoom(t *testing.T) {
	h := testHub(t)
	off := newTestPeer()
	room := h.createRoom(off)
	join := newTestPeer()
	if _, code := h.join(join, room); code != "" {
		t.Fatalf("join: %s", code)
	}

	if other := h.discard(off); other != join {
		t.Fatal("discard did not surface the partner")
	}
	if h.roomCount() != 0 {
		t.Fatalf("room count after discard = %d, want 0", h.roomCount())
	}
}

// A lingering half-empty room is still bounded by the idle reaper: a peer that drops and
// never returns cannot pin server memory beyond the idle timeout.
func TestReapClosesLingeringRoom(t *testing.T) {
	h := testHub(t)
	off := newTestPeer()
	room := h.createRoom(off)
	join := newTestPeer()
	if _, code := h.join(join, room); code != "" {
		t.Fatalf("join: %s", code)
	}
	h.vacate(off) // room now lingers with only the joiner attached

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
	case <-join.done:
		// the surviving peer was closed as expected
	default:
		t.Fatal("reaped lingering room did not close its surviving peer")
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

func TestPeerRelayQueueBackpressuresAtMessageCapacity(t *testing.T) {
	h := testHub(t)
	p := newTestPeer()
	p.hub = h
	for i := 0; i < cap(p.send); i++ {
		if !p.tryEnqueue(websocket.MessageBinary, []byte{byte(i)}) {
			t.Fatalf("frame %d was refused before the channel reached capacity", i)
		}
	}
	result := make(chan bool, 1)
	go func() { result <- p.tryEnqueue(websocket.MessageBinary, []byte("next")) }()
	select {
	case <-result:
		t.Fatal("enqueue did not apply backpressure to a momentarily full channel")
	case <-time.After(10 * time.Millisecond):
	}
	frame := <-p.send
	p.releaseQueued(int64(len(frame.data)))
	select {
	case ok := <-result:
		if !ok {
			t.Fatal("enqueue was refused after the writer made room")
		}
	case <-time.After(time.Second):
		t.Fatal("enqueue did not resume after the writer made room")
	}
}
