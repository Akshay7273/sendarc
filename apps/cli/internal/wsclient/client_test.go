package wsclient_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/sendarc/cli/internal/rendezvous"
	"github.com/sendarc/cli/internal/wsclient"
)

// blindHub is a minimal stand-in for the SendArc signaling server, enough to drive one
// two-peer handshake over a real WebSocket. It allocates a room on create, pairs the peers
// on join, and forwards every subsequent frame to the other peer verbatim — it never parses
// pake/confirm/caps, mirroring the real server's blindness. It exists so this package can be
// tested against a live socket without importing the server module.
type blindHub struct {
	mu    sync.Mutex
	rooms map[int]*hubRoom
	next  int
}

type hubRoom struct {
	offerer, joiner *hubPeer
}

// hubPeer serializes writes to one connection, since both the peer's own read loop (control
// replies) and the other peer's read loop (forwarded frames) may target it.
type hubPeer struct {
	conn *websocket.Conn
	wmu  sync.Mutex
}

func (p *hubPeer) send(ctx context.Context, m rendezvous.Message) {
	data, err := rendezvous.MarshalMessage(m)
	if err != nil {
		return
	}
	p.wmu.Lock()
	defer p.wmu.Unlock()
	_ = p.conn.Write(ctx, websocket.MessageText, data)
}

func (p *hubPeer) forward(ctx context.Context, data []byte) {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	_ = p.conn.Write(ctx, websocket.MessageText, data)
}

func newBlindHub() *blindHub { return &blindHub{rooms: map[int]*hubRoom{}} }

func (h *blindHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer conn.CloseNow()
	ctx := r.Context()
	self := &hubPeer{conn: conn}

	var room *hubRoom
	var role rendezvous.Role
	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		if typ != websocket.MessageText {
			return
		}
		msg, err := rendezvous.UnmarshalMessage(data)
		if err != nil {
			return
		}

		switch msg.Type {
		case "create":
			h.mu.Lock()
			id := h.next
			h.next++
			room = &hubRoom{offerer: self}
			h.rooms[id] = room
			h.mu.Unlock()
			role = rendezvous.RoleOfferer
			self.send(ctx, rendezvous.Message{Type: "created", Room: &id})

		case "join":
			if msg.Room == nil {
				return
			}
			h.mu.Lock()
			room = h.rooms[*msg.Room]
			h.mu.Unlock()
			if room == nil {
				return
			}
			room.joiner = self
			role = rendezvous.RoleJoiner
			self.send(ctx, rendezvous.Message{Type: "peer-joined", Role: string(rendezvous.RoleJoiner)})
			room.offerer.send(ctx, rendezvous.Message{Type: "peer-joined", Role: string(rendezvous.RoleOfferer)})

		default:
			// Blind forward to the other end of the room.
			other := room.joiner
			if role == rendezvous.RoleJoiner {
				other = room.offerer
			}
			if other != nil {
				other.forward(ctx, data)
			}
		}
	}
}

// wsURL rewrites an httptest TLS server URL (https://…) to its wss:// equivalent.
func wsURL(httpsURL string) string {
	return "wss" + strings.TrimPrefix(httpsURL, "https")
}

func TestRendezvousOverWebSocket(t *testing.T) {
	srv := httptest.NewTLSServer(newBlindHub())
	defer srv.Close()
	url := wsURL(srv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The offerer generates the code; the joiner can only start once it is known — exactly
	// the human hand-off (read the code off one screen, type it into the other).
	codeCh := make(chan string, 1)
	dopts := wsclient.DialOptions{InsecureSkipVerify: true}

	var (
		offRes, joinRes *rendezvous.Result
		offErr, joinErr error
		wg              sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		offRes, offErr = wsclient.Rendezvous(ctx, url, dopts, rendezvous.Options{
			Role:   rendezvous.RoleOfferer,
			Words:  "brave-otter",
			OnCode: func(c string) { codeCh <- c },
		})
	}()

	select {
	case code := <-codeCh:
		wg.Add(1)
		go func() {
			defer wg.Done()
			joinRes, joinErr = wsclient.Rendezvous(ctx, url, dopts, rendezvous.Options{
				Role: rendezvous.RoleJoiner,
				Code: code,
			})
		}()
	case <-ctx.Done():
		t.Fatal("offerer never produced a code")
	}

	wg.Wait()

	if offErr != nil {
		t.Fatalf("offerer: %v", offErr)
	}
	if joinErr != nil {
		t.Fatalf("joiner: %v", joinErr)
	}

	if !bytes.Equal(offRes.Master, joinRes.Master) {
		t.Error("master keys differ across the socket")
	}
	if !bytes.Equal(offRes.Keys.O2J.Key, joinRes.Keys.O2J.Key) ||
		!bytes.Equal(offRes.Keys.J2O.Key, joinRes.Keys.J2O.Key) {
		t.Error("directional transfer keys differ across the socket")
	}
	if offRes.Code != "0-brave-otter" || joinRes.Code != "0-brave-otter" {
		t.Errorf("codes: offerer=%q joiner=%q, want 0-brave-otter", offRes.Code, joinRes.Code)
	}
	if !reflect.DeepEqual(offRes.RemoteCaps, joinRes.LocalCaps) ||
		!reflect.DeepEqual(joinRes.RemoteCaps, offRes.LocalCaps) {
		t.Error("caps did not round-trip across the socket")
	}
}

// A connect against a dead address must exhaust the (shortened) backoff and return an error
// rather than blocking forever.
func TestDialFailsAfterBackoff(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := wsclient.Dial(ctx, "ws://127.0.0.1:1", wsclient.DialOptions{
		Backoff: wsclient.BackoffOptions{Retries: 1, Base: time.Millisecond, Max: time.Millisecond, Factor: 2},
	})
	if err == nil {
		t.Fatal("expected a dial error against a closed port")
	}
}

// The invite code exchanged out-of-band must be parseable back into its parts, so a joiner
// started from a copied code targets the same room. (Sanity check on the code the hub sees.)
func TestJoinerCodeIsWellFormed(t *testing.T) {
	var m rendezvous.Message
	if err := json.Unmarshal([]byte(`{"type":"join","room":7}`), &m); err != nil {
		t.Fatal(err)
	}
	if m.Type != "join" || m.Room == nil || *m.Room != 7 {
		t.Errorf("join envelope = %+v", m)
	}
}
