package transfer

import (
	"bytes"
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/sendbeam/cli/internal/rendezvous"
	"github.com/sendbeam/wire"
)

// faultPayload builds a deterministic payload crossing block boundaries.
func faultPayload(size int) []byte {
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i*29 + 5)
	}
	return payload
}

// pathLog records every OnTransport report in order.
type pathLog struct {
	mu    sync.Mutex
	paths []string
}

func appendPath(log *pathLog) func(string) {
	return func(path string) {
		log.mu.Lock()
		log.paths = append(log.paths, path)
		log.mu.Unlock()
	}
}

// killBothSignaling simulates the signaling server going away: both sockets die
// while the byte path lives or dies on its own.
func killBothSignaling(hub *relay) {
	hub.off.killSignaling()
	hub.join.killSignaling()
}

// expectCutover asserts a direct→relay cutover path sequence. V12-PR04 may transiently emit a
// "recovering" transport state between direct and relay while the direct peer's ICE observes the
// drop; the meaningful invariant is that the path begins on direct and settles on relay.
func expectCutover(t *testing.T, name string, paths []string) {
	t.Helper()
	if len(paths) < 2 || paths[0] != "direct" || paths[len(paths)-1] != "relay" {
		t.Fatalf("%s paths = %v; want direct first and relay last", name, paths)
	}
	for _, p := range paths[1 : len(paths)-1] {
		if p != "recovering" {
			t.Fatalf("%s paths = %v; unexpected intermediate path %q", name, paths, p)
		}
	}
}

// TestDriverSurvivesSignalingLossOnDirect pins signaling failure is
// independent of the data path — a healthy direct channel finishes the transfer
// with no relay fallback and no error when the signaling socket dies mid-file.
func TestDriverSurvivesSignalingLossOnDirect(t *testing.T) {
	hub := newRelay()
	payload := faultPayload(2*1024*1024 + 77)
	meta := wire.FileMeta{Name: "sig-loss.bin", Size: int64(len(payload)), Mime: "application/octet-stream"}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	type result struct {
		out *Outcome
		err error
	}
	done := make(chan result, 2)
	var once sync.Once
	sendPaths, recvPaths := &pathLog{}, &pathLog{}
	go func() {
		out, err := Run(ctx, hub.off, Spec{
			Session:     rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "alpha-bravo"},
			Source:      wire.BytesSource(payload, meta, 64*1024),
			ICEServers:  []webrtc.ICEServer{},
			OnTransport: appendPath(sendPaths),
			OnProgress: func(bytes int64) {
				if bytes >= 1024*1024 {
					once.Do(func() { killBothSignaling(hub) })
				}
			},
		})
		done <- result{out: out, err: err}
	}()
	go func() {
		out, err := Run(ctx, hub.join, Spec{
			Session:     rendezvous.Options{Role: rendezvous.RoleJoiner, Code: "7-alpha-bravo"},
			DestDir:     dir,
			ICEServers:  []webrtc.ICEServer{},
			OnTransport: appendPath(recvPaths),
		})
		done <- result{out: out, err: err}
	}()

	a, b := <-done, <-done
	if a.err != nil || b.err != nil {
		t.Fatalf("results after signaling loss: %v / %v", a.err, b.err)
	}
	var recv *Outcome
	if a.out.Path != "" {
		recv = a.out
	} else {
		recv = b.out
	}
	got, err := os.ReadFile(recv.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("output differs from source after signaling loss")
	}
	for name, log := range map[string]*pathLog{"sender": sendPaths, "receiver": recvPaths} {
		log.mu.Lock()
		paths := append([]string(nil), log.paths...)
		log.mu.Unlock()
		if len(paths) != 1 || paths[0] != "direct" {
			t.Fatalf("%s paths = %v; want [direct] with signaling dead", name, paths)
		}
	}
}

// TestDriverSignalingLossOnRelayIsFatal pins the relay side: a relay
// transfer needs signaling (credit accounting), so losing it mid-file fails both
// sides with RELAY instead of silently stalling.
func TestDriverSignalingLossOnRelayIsFatal(t *testing.T) {
	hub := newRelay()
	payload := faultPayload(2*1024*1024 + 13)
	meta := wire.FileMeta{Name: "relay-sig-loss.bin", Size: int64(len(payload)), Mime: "application/octet-stream"}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	type result struct {
		out *Outcome
		err error
	}
	done := make(chan result, 2)
	var once sync.Once
	go func() {
		out, err := Run(ctx, hub.off, Spec{
			Session: rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "alpha-bravo"},
			Source:  wire.BytesSource(payload, meta, 64*1024),
			// Explicit empty ICEServers: no direct path may even be attempted.
			ICEServers: []webrtc.ICEServer{},
			ForceRelay: true,
			OnProgress: func(bytes int64) {
				if bytes >= 512*1024 {
					once.Do(func() { killBothSignaling(hub) })
				}
			},
		})
		done <- result{out: out, err: err}
	}()
	go func() {
		out, err := Run(ctx, hub.join, Spec{
			Session:    rendezvous.Options{Role: rendezvous.RoleJoiner, Code: "7-alpha-bravo"},
			DestDir:    dir,
			ICEServers: []webrtc.ICEServer{},
			ForceRelay: true,
		})
		done <- result{out: out, err: err}
	}()

	a, b := <-done, <-done
	if a.err == nil || b.err == nil {
		t.Fatalf("expected both sides to fail on relay signaling loss: %v / %v", a.err, b.err)
	}
	if code := wire.CodeOf(a.err); code != wire.CodeRelay {
		t.Fatalf("sender error code = %s (%v); want RELAY", code, a.err)
	}
	if code := wire.CodeOf(b.err); code != wire.CodeRelay {
		t.Fatalf("receiver error code = %s (%v); want RELAY", code, b.err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("destination contains %d files after a failed transfer; want none", len(entries))
	}
}

// TestDriverCutoverBeforeDataStarts pins cutover phase 1: the direct channel
// dies before the first byte moves and the transfer still completes over the
// relay with identical bytes.
func TestDriverCutoverBeforeDataStarts(t *testing.T) {
	hub := newRelay()
	payload := faultPayload(512*1024 + 21)
	meta := wire.FileMeta{Name: "cutover-early.bin", Size: int64(len(payload)), Mime: "application/octet-stream"}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	trigger := make(chan struct{})
	var triggerOnce sync.Once
	sendPaths, recvPaths := &pathLog{}, &pathLog{}
	type result struct {
		out *Outcome
		err error
	}
	done := make(chan result, 2)
	go func() {
		out, err := Run(ctx, hub.off, Spec{
			Session:     rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "alpha-bravo"},
			Source:      wire.BytesSource(payload, meta, 64*1024),
			ICEServers:  []webrtc.ICEServer{},
			OnTransport: appendPath(sendPaths),
			breakDirect: trigger,
			OnConnect: func() {
				triggerOnce.Do(func() { close(trigger) })
			},
		})
		done <- result{out: out, err: err}
	}()
	go func() {
		out, err := Run(ctx, hub.join, Spec{
			Session:     rendezvous.Options{Role: rendezvous.RoleJoiner, Code: "7-alpha-bravo"},
			DestDir:     dir,
			ICEServers:  []webrtc.ICEServer{},
			OnTransport: appendPath(recvPaths),
		})
		done <- result{out: out, err: err}
	}()

	a, b := <-done, <-done
	if a.err != nil || b.err != nil {
		t.Fatalf("cutover-before-data results: %v / %v", a.err, b.err)
	}
	var recv *Outcome
	if a.out.Path != "" {
		recv = a.out
	} else {
		recv = b.out
	}
	got, err := os.ReadFile(recv.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("output differs from source after early cutover")
	}
	for name, log := range map[string]*pathLog{"sender": sendPaths, "receiver": recvPaths} {
		log.mu.Lock()
		paths := append([]string(nil), log.paths...)
		log.mu.Unlock()
		expectCutover(t, name, paths)
	}
}

// TestDriverCutoverAfterAllDataAcked pins cutover phase 2: every byte has been
// acknowledged before the direct path dies, so the cutover must not fail the
// transfer over lost terminal control frames.
func TestDriverCutoverAfterAllDataAcked(t *testing.T) {
	hub := newRelay()
	payload := faultPayload(1024*1024 + 29)
	meta := wire.FileMeta{Name: "cutover-late.bin", Size: int64(len(payload)), Mime: "application/octet-stream"}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	trigger := make(chan struct{})
	var triggerOnce sync.Once
	sendPaths, recvPaths := &pathLog{}, &pathLog{}
	type result struct {
		out *Outcome
		err error
	}
	done := make(chan result, 2)
	go func() {
		out, err := Run(ctx, hub.off, Spec{
			Session:     rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "alpha-bravo"},
			Source:      wire.BytesSource(payload, meta, 64*1024),
			ICEServers:  []webrtc.ICEServer{},
			OnTransport: appendPath(sendPaths),
			breakDirect: trigger,
			OnProgress: func(bytes int64) {
				if bytes >= meta.Size {
					triggerOnce.Do(func() { close(trigger) })
				}
			},
		})
		done <- result{out: out, err: err}
	}()
	go func() {
		out, err := Run(ctx, hub.join, Spec{
			Session:     rendezvous.Options{Role: rendezvous.RoleJoiner, Code: "7-alpha-bravo"},
			DestDir:     dir,
			ICEServers:  []webrtc.ICEServer{},
			OnTransport: appendPath(recvPaths),
		})
		done <- result{out: out, err: err}
	}()

	a, b := <-done, <-done
	if a.err != nil || b.err != nil {
		t.Fatalf("cutover-after-data results: %v / %v", a.err, b.err)
	}
	var recv *Outcome
	if a.out.Path != "" {
		recv = a.out
	} else {
		recv = b.out
	}
	got, err := os.ReadFile(recv.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("output differs from source after late cutover")
	}
	for name, log := range map[string]*pathLog{"sender": sendPaths, "receiver": recvPaths} {
		log.mu.Lock()
		paths := append([]string(nil), log.paths...)
		log.mu.Unlock()
		if len(paths) < 1 || paths[0] != "direct" {
			t.Fatalf("%s paths = %v; want direct first", name, paths)
		}
	}
}

// TestDriverFallsBackOnFailedDirectRecovery pins the V12-PR04 recovery wiring: when the direct
// path's recovery window fails over (the peer's OnRecoverFailed hook firing), the driver falls
// back to the relay without restarting transfer progress — the transfer still completes with a
// byte-identical file, reporting [direct relay] on both peers.
func TestDriverFallsBackOnFailedDirectRecovery(t *testing.T) {
	hub := newRelay()
	payload := faultPayload(3*1024*1024 + 41)
	meta := wire.FileMeta{Name: "recover-fail.bin", Size: int64(len(payload)), Mime: "application/octet-stream"}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	trigger := make(chan struct{})
	var triggerOnce sync.Once
	sendPaths, recvPaths := &pathLog{}, &pathLog{}
	type result struct {
		out *Outcome
		err error
	}
	done := make(chan result, 2)
	go func() {
		out, err := Run(ctx, hub.off, Spec{
			Session:     rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "alpha-bravo"},
			Source:      wire.BytesSource(payload, meta, 64*1024),
			ICEServers:  []webrtc.ICEServer{},
			OnTransport: appendPath(sendPaths),
			breakDirectRecovery: trigger,
			OnProgress: func(bytes int64) {
				if bytes >= 1024*1024 {
					triggerOnce.Do(func() { close(trigger) })
				}
			},
		})
		done <- result{out: out, err: err}
	}()
	go func() {
		out, err := Run(ctx, hub.join, Spec{
			Session:     rendezvous.Options{Role: rendezvous.RoleJoiner, Code: "7-alpha-bravo"},
			DestDir:     dir,
			ICEServers:  []webrtc.ICEServer{},
			OnTransport: appendPath(recvPaths),
		})
		done <- result{out: out, err: err}
	}()

	a, b := <-done, <-done
	if a.err != nil || b.err != nil {
		t.Fatalf("recovery-fallback results: %v / %v", a.err, b.err)
	}
	var recv *Outcome
	if a.out.Path != "" {
		recv = a.out
	} else {
		recv = b.out
	}
	got, err := os.ReadFile(recv.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("output differs from source after failed direct recovery")
	}
	for name, log := range map[string]*pathLog{"sender": sendPaths, "receiver": recvPaths} {
		log.mu.Lock()
		paths := append([]string(nil), log.paths...)
		log.mu.Unlock()
		expectCutover(t, name, paths)
	}
}
