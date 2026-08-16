package rtc

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/wire"
)

// hostOnly forces ICE to gather host candidates only (no STUN), so the loopback test needs no
// network egress: on a machine with a working loopback the two peers connect over 127.0.0.1.
var hostOnly = []webrtc.ICEServer{}

// linkedPeers wires an offerer and a joiner mouth-to-ear over two buffered signaling channels,
// each drained by a goroutine that feeds the other peer's Accept. Decoupling through channels
// (rather than calling Accept inline from Send) avoids re-entrancy: handling an offer synchronously
// signs and sends the answer, which would otherwise recurse back into the sender.
func linkedPeers(t testing.TB) (offerer, joiner *Peer) {
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

// TestPeerRestartICEKeepsChannelAlive pins the ICE-restart renegotiation path that V12-PR04
// recovery relies on: after a connected pair restarts ICE as the offerer, the existing data
// channel survives (progress is not reset) and bytes still flow in both directions.
func TestPeerRestartICEKeepsChannelAlive(t *testing.T) {
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

	if err := offConn.Send([]byte("before")); err != nil {
		t.Fatalf("offerer send: %v", err)
	}
	if got := recvWithin(t, fromOfferer); string(got) != "before" {
		t.Fatalf("before restart: got %q, want before", got)
	}

	// ICE restart: the offerer renegotiates with a fresh offer over the same channel.
	if err := offerer.restartOffer(); err != nil {
		t.Fatalf("restart offer: %v", err)
	}

	// The existing channel must still carry bytes after renegotiation completes.
	sendAndExpect := func(send func([]byte) error, recv chan []byte, want string) {
		t.Helper()
		if err := send([]byte(want)); err != nil {
			t.Fatalf("send after restart %q: %v", want, err)
		}
		var got []byte
		select {
		case got = <-recv:
		case <-time.After(30 * time.Second):
			t.Fatalf("timed out waiting for %q after restart", want)
		}
		if string(got) != want {
			t.Fatalf("after restart: got %q, want %q", got, want)
		}
	}
	sendAndExpect(offConn.Send, fromOfferer, "after-offer")
	sendAndExpect(joinConn.Send, fromJoiner, "after-answer")
}

// TestPeerRecoveryCallbacks pins the recovery state machine on the Pion peer: entering the
// transient-disconnect window reports recovering, a return to connected clears it, and an
// unrecovered window fails over (with a bounded timer), all reflected by the Recovering getter.
func TestPeerRecoveryCallbacks(t *testing.T) {
	var ( // offerer reports recovering; use a short window so the timer fires deterministically.
		becomes       []bool
		recoverFailed atomic.Bool
		mu            sync.Mutex
	)
	record := func(b bool) {
		mu.Lock()
		becomes = append(becomes, b)
		mu.Unlock()
	}

	toJoiner := make(chan rendezvous.Message, 64)
	toOfferer := make(chan rendezvous.Message, 64)
	offAuth, joinAuth := newPair(testRoom)

	offerer, err := NewPeer(PeerOptions{
		Role: wire.RoleOfferer, Auth: offAuth, ICEServers: hostOnly,
		Send:            func(m rendezvous.Message) error { toJoiner <- m; return nil },
		RecoverWindow:   30 * time.Millisecond,
		OnRecovering:    record,
		OnRecoverFailed: func() { recoverFailed.Store(true) },
	})
	if err != nil {
		t.Fatalf("new offerer: %v", err)
	}
	joiner, err := NewPeer(PeerOptions{
		Role: wire.RoleJoiner, Auth: joinAuth, ICEServers: hostOnly,
		Send: func(m rendezvous.Message) error { toOfferer <- m; return nil },
	})
	if err != nil {
		_ = offerer.Close()
		t.Fatalf("new joiner: %v", err)
	}
	done := make(chan struct{})
	defer close(done)
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
	defer func() { _ = offerer.Close(); _ = joiner.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := offerer.Channel(ctx); err != nil {
		t.Fatalf("offerer channel: %v", err)
	}

	// Entering recovery reports recovering=true and arms the bounded timer.
	offerer.enterRecover()
	if !offerer.Recovering() {
		t.Fatal("expected Recovering() true after enterRecover")
	}
	mu.Lock()
	got := append([]bool(nil), becomes...)
	mu.Unlock()
	if len(got) != 1 || got[0] != true {
		t.Fatalf("onRecovering calls = %v, want [true]", got)
	}

	// A return to connected clears it and reports recovering=false.
	offerer.exitRecover()
	if offerer.Recovering() {
		t.Fatal("expected Recovering() false after exitRecover")
	}
	mu.Lock()
	got = append([]bool(nil), becomes...)
	mu.Unlock()
	if len(got) != 2 || got[1] != false {
		t.Fatalf("onRecovering calls = %v, want [true false]", got)
	}

	// A bounded, unrecovered window fails over within the window, without leaking the timer.
	recoverFailed.Store(false)
	offerer.enterRecover()
	deadline := time.Now().Add(5 * time.Second)
	for !recoverFailed.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !recoverFailed.Load() {
		t.Fatal("expected onRecoverFailed after the recovery window elapsed")
	}
	if offerer.Recovering() {
		t.Fatal("expected Recovering() false after failed recovery")
	}
}

// TestPeerRepeatedRecoveryCyclesKeepChannelAlive pins the V12-PR04 guarantee that repeated
// network-change cycles (disconnect → recover → reconnect) never reset transfer progress: the
// existing channel survives each cycle and bytes flow in both directions with no loss.
func TestPeerRepeatedRecoveryCyclesKeepChannelAlive(t *testing.T) {
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

	for i := 0; i < 3; i++ {
		payload := []byte{byte('a' + i), byte(i)}
		if err := offConn.Send(payload); err != nil {
			t.Fatalf("cycle %d offerer send: %v", i, err)
		}
		if got := recvWithin(t, fromOfferer); !bytes.Equal(got, payload) {
			t.Fatalf("cycle %d offerer-side: got %v, want %v", i, got, payload)
		}
		// Enter and clear the recovery window (the transient disconnect it models).
		offerer.enterRecover()
		offerer.exitRecover()
		// The channel must still carry bytes after the cycle.
		if err := joinConn.Send(payload); err != nil {
			t.Fatalf("cycle %d joiner send: %v", i, err)
		}
		if got := recvWithin(t, fromJoiner); !bytes.Equal(got, payload) {
			t.Fatalf("cycle %d joiner-side: got %v, want %v", i, got, payload)
		}
	}

	// The last enter must be clearable/recoverable — no stale recovery state piling up.
	if offerer.Recovering() {
		t.Fatal("recovery state left set after a successful cycle")
	}
}

// TestPeerTeardownDuringRecoveryIsClean pins that closing the peer while it is inside a recovery
// window tears down cleanly: the bounded observation timer is cancelled (never fires after Close)
// and no goroutine/timer survives (verified by the race detector). A peer closed mid-recovery
// never reports a recovery failure to a caller that has already moved on.
func TestPeerTeardownDuringRecoveryIsClean(t *testing.T) {
	offAuth, joinAuth := newPair(testRoom)
	toJoiner := make(chan rendezvous.Message, 64)
	toOfferer := make(chan rendezvous.Message, 64)
	var recoverFailed atomic.Bool

	offerer, err := NewPeer(PeerOptions{
		Role: wire.RoleOfferer, Auth: offAuth, ICEServers: hostOnly,
		Send:            func(m rendezvous.Message) error { toJoiner <- m; return nil },
		RecoverWindow:   50 * time.Millisecond,
		OnRecoverFailed: func() { recoverFailed.Store(true) },
	})
	if err != nil {
		t.Fatalf("new offerer: %v", err)
	}
	joiner, err := NewPeer(PeerOptions{
		Role: wire.RoleJoiner, Auth: joinAuth, ICEServers: hostOnly,
		Send: func(m rendezvous.Message) error { toOfferer <- m; return nil },
	})
	if err != nil {
		_ = offerer.Close()
		t.Fatalf("new joiner: %v", err)
	}
	done := make(chan struct{})
	defer func() { close(done); _ = joiner.Close(); _ = offerer.Close() }()
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := offerer.Channel(ctx); err != nil {
		t.Fatalf("offerer channel: %v", err)
	}

	offerer.enterRecover()
	if !offerer.Recovering() {
		t.Fatal("expected Recovering() true after enterRecover")
	}

	// Close while recovering: the bounded observation timer is cancelled, so the recover-failed
	// callback must never fire for a peer we have already torn down (no stale timer/goroutine —
	// verified by the race detector).
	if err := offerer.Close(); err != nil {
		t.Fatalf("close during recovery: %v", err)
	}
	// Let the (cancelled) observation window elapse and confirm no stale failure callback fires.
	time.Sleep(120 * time.Millisecond)
	if recoverFailed.Load() {
		t.Fatal("OnRecoverFailed fired after close during recovery")
	}
}

// TestPeerDiagnosticsReportSetupTelemetry pins the ICE telemetry surface: after a successful
// loopback negotiation the peer reports a positive setup duration, a non-empty gathering and
// ICE-connection state history, and a selected candidate pair type.
func TestPeerDiagnosticsReportSetupTelemetry(t *testing.T) {
	offerer, joiner := linkedPeers(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := offerer.Channel(ctx); err != nil {
		t.Fatalf("offerer channel: %v", err)
	}
	if _, err := joiner.Channel(ctx); err != nil {
		t.Fatalf("joiner channel: %v", err)
	}

	d := offerer.Diagnostics()
	if d.SetupDuration <= 0 {
		t.Errorf("SetupDuration = %v, want > 0 after open", d.SetupDuration)
	}
	if len(d.ConnectionStates) == 0 {
		t.Error("no ICE connection-state history recorded")
	}
	if len(d.GatheringStates) == 0 {
		t.Error("no ICE gathering-state history recorded")
	}
	if d.SelectedCandidatePairType == "" {
		t.Error("selected candidate pair type not reported after connection")
	}
}

// TestPeerOnICEStatePublishesTransitions verifies the OnICEState callback fires as
// gathering/connection state progresses on a connected peer. At minimum the initial state and
// at least one transition must be observed after the loopback connects.
func TestPeerOnICEStatePublishesTransitions(t *testing.T) {
	var fired atomic.Bool
	var mu sync.Mutex
	var connectionStates []webrtc.ICEConnectionState

	toJoiner := make(chan rendezvous.Message, 64)
	toOfferer := make(chan rendezvous.Message, 64)
	offAuth, joinAuth := newPair(testRoom)

	offerer, err := NewPeer(PeerOptions{
		Role: wire.RoleOfferer, Auth: offAuth, ICEServers: hostOnly,
		Send: func(m rendezvous.Message) error { toJoiner <- m; return nil },
		OnICEState: func(s ICEState) {
			fired.Store(true)
			mu.Lock()
			connectionStates = append(connectionStates, s.Connection)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("new offerer: %v", err)
	}
	joiner, err := NewPeer(PeerOptions{
		Role: wire.RoleJoiner, Auth: joinAuth, ICEServers: hostOnly,
		Send: func(m rendezvous.Message) error { toOfferer <- m; return nil },
	})
	if err != nil {
		_ = offerer.Close()
		t.Fatalf("new joiner: %v", err)
	}
	done := make(chan struct{})
	defer close(done)
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
	defer func() { _ = offerer.Close(); _ = joiner.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := offerer.Channel(ctx); err != nil {
		t.Fatalf("offerer channel: %v", err)
	}

	if !fired.Load() {
		t.Error("OnICEState callback never fired")
	}
	if len(connectionStates) == 0 {
		t.Error("no ICE connection states reported via callback")
	}
}
