package wsclient

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/sendbeam/engine/rendezvous"
)

// testResumeServer is a minimal localhost signaling server that supports the room resume flow:
// it replies `resumed` to a resume request and forwards every other inbound message to `inbound`.
// Each accepted connection is served in its own goroutine, like the real server, so a re-dialing
// ReconnectingSignal can re-attach to the room.
type testResumeServer struct {
	url     string
	inbound chan rendezvous.Message
	srv     *http.Server
}

func runTestResumeServer(t *testing.T) *testResumeServer {
	t.Helper()
	s := &testResumeServer{inbound: make(chan rendezvous.Message, 64)}
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = c.Close(websocket.StatusNormalClosure, "") }()
			readCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			for {
				typ, data, err := c.Read(readCtx)
				if err != nil {
					return
				}
				if typ != websocket.MessageText {
					continue
				}
				var m rendezvous.Message
				if json.Unmarshal(data, &m) != nil {
					continue
				}
				if m.Type == "resume" {
					_ = c.Write(readCtx, websocket.MessageText, []byte(`{"type":"resumed","room":7}`))
					continue
				}
				s.inbound <- m
			}
		}()
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s.srv = &http.Server{Handler: mux}
	go func() { _ = s.srv.Serve(ln) }()
	t.Cleanup(func() { _ = s.srv.Close() })
	s.url = "ws://" + ln.Addr().String() + "/ws"
	return s
}

func TestReconnectingSignalSendFlows(t *testing.T) {
	srv := runTestResumeServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sig, err := NewReconnectingSignal(ctx, srv.url, DialOptions{})
	if err != nil {
		t.Fatalf("new reconnecting signal: %v", err)
	}
	defer sig.Close()
	if err := sig.Send(rendezvous.Message{Type: "sdp", Sdp: "hello"}); err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case m := <-srv.inbound:
		if m.Sdp != "hello" {
			t.Fatalf("inbound sdp = %q, want hello", m.Sdp)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no inbound send received")
	}
}

func TestReconnectingSignalResumesAfterDrop(t *testing.T) {
	srv := runTestResumeServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sig, err := NewReconnectingSignal(ctx, srv.url, DialOptions{})
	if err != nil {
		t.Fatalf("new reconnecting signal: %v", err)
	}
	defer sig.Close()
	sig.SetResume(7, "offerer")

	got := make(chan rendezvous.Message, 16)
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_ = sig.Run(ctx, func(m rendezvous.Message) { got <- m }, func(_ []byte) {})
	}()

	// A normal frame forwards and is received by the server.
	if err := sig.Send(rendezvous.Message{Type: "sdp", Sdp: "one"}); err != nil {
		t.Fatalf("send: %v", err)
	}
	waitInbound(t, srv, "one")

	// Drop the underlying socket: Run returns, then re-dials + resumes. The resumed control
	// frame must be consumed internally (never forwarded) and the socket re-established.
	sig.mu.Lock()
	sig.cur.Close()
	sig.mu.Unlock()

	// After reconnect, a send must reach the server again.
	sendAfter := make(chan string, 1)
	go func() {
		for {
			if err := sig.Send(rendezvous.Message{Type: "sdp", Sdp: "after"}); err != nil {
				time.Sleep(20 * time.Millisecond)
				continue
			}
			sendAfter <- "after"
			return
		}
	}()

	select {
	case m := <-srv.inbound:
		if m.Sdp != "after" {
			t.Fatalf("post-reconnect inbound sdp = %q, want after", m.Sdp)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no inbound after reconnect (socket not re-established)")
	}
	select {
	case <-sendAfter:
	default:
	}

	// Control frames must never reach the transfer layer: nothing of type resumed/peer_left
	// may be forwarded, and the only forwarded message here is the sdp we sent.
	sig.Close()
	<-runDone
	closeSelectNothing(t, got)
}

func waitInbound(t *testing.T, srv *testResumeServer, want string) {
	t.Helper()
	select {
	case m := <-srv.inbound:
		if m.Sdp != want {
			t.Fatalf("inbound sdp = %q, want %q", m.Sdp, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for inbound %q", want)
	}
}

// closeSelectNothing asserts that no control-frame was forwarded: draining `got` immediately (it
// may still hold the sdp we sent) yields no resumed/peer_left/peer_rejoined types.
func closeSelectNothing(t *testing.T, got chan rendezvous.Message) {
	t.Helper()
	for {
		select {
		case m := <-got:
			if serverControlTypes[m.Type] {
				t.Fatalf("server control frame %q was forwarded to the transfer layer", m.Type)
			}
		default:
			return
		}
	}
}

func TestReconnectingSignalFilterConsumesControlTypes(t *testing.T) {
	srv := runTestResumeServer(t)
	sig, err := NewReconnectingSignal(context.Background(), srv.url, DialOptions{})
	if err != nil {
		t.Fatalf("new reconnecting signal: %v", err)
	}
	defer sig.Close()

	var forwarded []string
	filtered := sig.filter(func(m rendezvous.Message) { forwarded = append(forwarded, m.Type) })
	for _, typ := range []string{"resumed", "peer_left", "peer_rejoined"} {
		filtered(rendezvous.Message{Type: typ})
	}
	filtered(rendezvous.Message{Type: "sdp"})
	if len(forwarded) != 1 || forwarded[0] != "sdp" {
		t.Fatalf("forwarded = %v, want [sdp]", forwarded)
	}
}
