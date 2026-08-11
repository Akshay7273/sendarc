package rtc

import (
	"context"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/sendbeam/cli/internal/rendezvous"
	"github.com/sendbeam/wire"
)

// hostOnly forces ICE to gather host candidates only (no STUN), so the loopback test needs no
// network egress: on a machine with a working loopback the two peers connect over 127.0.0.1.
var hostOnly = []webrtc.ICEServer{}

// linkedPeers wires an offerer and a joiner mouth-to-ear over two buffered signaling channels,
// each drained by a goroutine that feeds the other peer's Accept. Decoupling through channels
// (rather than calling Accept inline from Send) avoids re-entrancy: handling an offer synchronously
// signs and sends the answer, which would otherwise recurse back into the sender.
func linkedPeers(t *testing.T) (offerer, joiner *Peer) {
	t.Helper()
	offAuth, joinAuth := newPair(testRoom)

	toJoiner := make(chan rendezvous.Message, 64)
	toOfferer := make(chan rendezvous.Message, 64)

	var err error
	offerer, err = NewPeer(PeerOptions{
		Role:       wire.RoleOfferer,
		Auth:       offAuth,
		ICEServers: hostOnly,
		Send:       func(m rendezvous.Message) error { toJoiner <- m; return nil },
	})
	if err != nil {
		t.Fatalf("new offerer: %v", err)
	}
	joiner, err = NewPeer(PeerOptions{
		Role:       wire.RoleJoiner,
		Auth:       joinAuth,
		ICEServers: hostOnly,
		Send:       func(m rendezvous.Message) error { toOfferer <- m; return nil },
	})
	if err != nil {
		_ = offerer.Close()
		t.Fatalf("new joiner: %v", err)
	}

	done := make(chan struct{})
	go func() {
		for {
			select {
			case m := <-toJoiner:
				joiner.Accept(m)
			case <-done:
				return
			}
		}
	}()
	go func() {
		for {
			select {
			case m := <-toOfferer:
				offerer.Accept(m)
			case <-done:
				return
			}
		}
	}()
	t.Cleanup(func() {
		close(done)
		_ = offerer.Close()
		_ = joiner.Close()
	})
	return offerer, joiner
}

// TestPeerLoopbackConnectsAndTransfersBytes is the end-to-end proof that the pion negotiation
// works: two peers reach an open channel over authenticated signaling and carry bytes in both
// directions, in order. It exercises the real ICE/DTLS/SCTP stack over host candidates.
func TestPeerLoopbackConnectsAndTransfersBytes(t *testing.T) {
	offerer, joiner := linkedPeers(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	offConn, err := offerer.Channel(ctx)
	if err != nil {
		t.Fatalf("offerer channel: %v", err)
	}
	joinConn, err := joiner.Channel(ctx)
	if err != nil {
		t.Fatalf("joiner channel: %v", err)
	}

	fromOfferer := make(chan []byte, 8)
	fromJoiner := make(chan []byte, 8)
	joinConn.OnData(func(f []byte) { fromOfferer <- f })
	offConn.OnData(func(f []byte) { fromJoiner <- f })

	if err := offConn.Send([]byte("ping")); err != nil {
		t.Fatalf("offerer send: %v", err)
	}
	if got := recvWithin(t, fromOfferer); string(got) != "ping" {
		t.Fatalf("joiner received %q, want ping", got)
	}

	if err := joinConn.Send([]byte("pong")); err != nil {
		t.Fatalf("joiner send: %v", err)
	}
	if got := recvWithin(t, fromJoiner); string(got) != "pong" {
		t.Fatalf("offerer received %q, want pong", got)
	}
}

// TestPeerBuffersInboundBeforeHandler pins the browser peer's buffering contract: frames that
// arrive before OnData is registered are held and flushed in order once it is, so the first
// blocks a fast sender emits are never lost.
func TestPeerBuffersInboundBeforeHandler(t *testing.T) {
	offerer, joiner := linkedPeers(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	offConn, err := offerer.Channel(ctx)
	if err != nil {
		t.Fatalf("offerer channel: %v", err)
	}
	joinConn, err := joiner.Channel(ctx)
	if err != nil {
		t.Fatalf("joiner channel: %v", err)
	}

	// Send before the joiner registers a handler; the frame must be buffered, not dropped.
	if err := offConn.Send([]byte("early")); err != nil {
		t.Fatalf("offerer send: %v", err)
	}
	// Give the frame time to land in the joiner's inbox ahead of registration.
	time.Sleep(200 * time.Millisecond)

	got := make(chan []byte, 1)
	joinConn.OnData(func(f []byte) { got <- f })
	if b := recvWithin(t, got); string(b) != "early" {
		t.Fatalf("buffered frame = %q, want early", b)
	}
}

func recvWithin(t *testing.T, ch <-chan []byte) []byte {
	t.Helper()
	select {
	case b := <-ch:
		return b
	case <-time.After(30 * time.Second):
		t.Fatal("timed out waiting for frame")
		return nil
	}
}
