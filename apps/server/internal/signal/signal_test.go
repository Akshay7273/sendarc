package signal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// testServer starts an httptest server running the signaling handler with cfg and
// returns its ws:// base URL.
func testServer(t *testing.T, cfg Config) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	hub := NewHub(ctx, cfg, nil)
	srv := httptest.NewServer(hub.Handler(ctx))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
}

type client struct {
	t    *testing.T
	conn *websocket.Conn
}

func dial(t *testing.T, url, origin string) (*client, error) {
	t.Helper()
	opts := &websocket.DialOptions{}
	if origin != "" {
		opts.HTTPHeader = http.Header{"Origin": {origin}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// coder/websocket's Dial documents that the handshake response body never needs
	// to be closed by the caller, so bodyclose's warning does not apply here.
	conn, _, err := websocket.Dial(ctx, url, opts) //nolint:bodyclose // see comment
	if err != nil {
		return nil, err
	}
	c := &client{t: t, conn: conn}
	t.Cleanup(func() { _ = conn.Close(websocket.StatusNormalClosure, "") })
	return c, nil
}

func mustDial(t *testing.T, url string) *client {
	t.Helper()
	c, err := dial(t, url, "")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return c
}

func (c *client) send(v any) {
	c.t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		c.t.Fatalf("marshal: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.conn.Write(ctx, websocket.MessageText, data); err != nil {
		c.t.Fatalf("write: %v", err)
	}
}

// sendRaw writes exact bytes, for asserting verbatim forwarding.
func (c *client) sendRaw(data []byte) {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.conn.Write(ctx, websocket.MessageText, data); err != nil {
		c.t.Fatalf("write raw: %v", err)
	}
}

func (c *client) recv() map[string]any {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	typ, data, err := c.conn.Read(ctx)
	if err != nil {
		c.t.Fatalf("read: %v", err)
	}
	if typ != websocket.MessageText {
		c.t.Fatalf("frame type = %v, want text", typ)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		c.t.Fatalf("unmarshal %q: %v", data, err)
	}
	return m
}

func (c *client) recvRaw() []byte {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, data, err := c.conn.Read(ctx)
	if err != nil {
		c.t.Fatalf("read raw: %v", err)
	}
	return data
}

// pair runs create/join and returns the offerer and joiner clients, both having
// consumed their peer-joined frames.
func pair(t *testing.T, url string) (offerer, joiner *client, room int) {
	t.Helper()
	offerer = mustDial(t, url)
	offerer.send(map[string]any{"type": typeCreate})

	created := offerer.recv()
	if created["type"] != typeCreated {
		t.Fatalf("expected created, got %v", created)
	}
	room = int(created["room"].(float64))

	joiner = mustDial(t, url)
	joiner.send(map[string]any{"type": typeJoin, "room": room})

	oj := offerer.recv()
	jj := joiner.recv()
	if oj["type"] != typePeerJoined || oj["role"] != roleOfferer {
		t.Fatalf("offerer peer-joined wrong: %v", oj)
	}
	if jj["type"] != typePeerJoined || jj["role"] != roleJoiner {
		t.Fatalf("joiner peer-joined wrong: %v", jj)
	}
	return offerer, joiner, room
}

func TestCreateJoinPeerJoined(t *testing.T) {
	url := testServer(t, DefaultConfig())
	_, _, room := pair(t, url)
	if room != 0 {
		t.Fatalf("first room = %d, want 0", room)
	}
}

func TestBlindForwardVerbatim(t *testing.T) {
	url := testServer(t, DefaultConfig())
	offerer, joiner, _ := pair(t, url)

	// A pake frame the server must relay byte-for-byte without inspecting it.
	frame := []byte(`{"type":"pake","msg":"AAECAwQF-_base64url"}`)
	offerer.sendRaw(frame)
	if got := joiner.recvRaw(); string(got) != string(frame) {
		t.Fatalf("forwarded frame = %s, want %s", got, frame)
	}

	// And the reverse direction.
	conf := []byte(`{"type":"confirm","mac":"deadbeef"}`)
	joiner.sendRaw(conf)
	if got := offerer.recvRaw(); string(got) != string(conf) {
		t.Fatalf("forwarded confirm = %s, want %s", got, conf)
	}
}

func TestJoinUnknownRoomOverWire(t *testing.T) {
	url := testServer(t, DefaultConfig())
	c := mustDial(t, url)
	c.send(map[string]any{"type": typeJoin, "room": 4242})
	m := c.recv()
	if m["type"] != typeError || m["code"] != errUnknownRoom {
		t.Fatalf("expected unknown_room error, got %v", m)
	}
}

func TestSecondJoinRejected(t *testing.T) {
	url := testServer(t, DefaultConfig())
	_, _, room := pair(t, url)

	third := mustDial(t, url)
	third.send(map[string]any{"type": typeJoin, "room": room})
	m := third.recv()
	if m["type"] != typeError || m["code"] != errRoomFull {
		t.Fatalf("expected room_full error, got %v", m)
	}
}

func TestForwardBeforePairRejected(t *testing.T) {
	url := testServer(t, DefaultConfig())
	offerer := mustDial(t, url)
	offerer.send(map[string]any{"type": typeCreate})
	if m := offerer.recv(); m["type"] != typeCreated {
		t.Fatalf("expected created, got %v", m)
	}
	// No joiner yet, so a forwardable message has nowhere to go.
	offerer.send(map[string]any{"type": typePake, "msg": "x"})
	if m := offerer.recv(); m["type"] != typeError || m["code"] != errNotPaired {
		t.Fatalf("expected not_paired error, got %v", m)
	}
}

func TestByeNotifiesPartner(t *testing.T) {
	url := testServer(t, DefaultConfig())
	offerer, joiner, _ := pair(t, url)

	offerer.send(map[string]any{"type": typeBye, "reason": "done"})
	m := joiner.recv()
	if m["type"] != typeBye {
		t.Fatalf("partner should receive bye, got %v", m)
	}
}

func TestDisconnectNotifiesPartner(t *testing.T) {
	url := testServer(t, DefaultConfig())
	offerer, joiner, _ := pair(t, url)

	// Offerer drops abruptly; the joiner should be told the peer left.
	_ = offerer.conn.Close(websocket.StatusNormalClosure, "")
	m := joiner.recv()
	if m["type"] != typeBye {
		t.Fatalf("expected bye on partner disconnect, got %v", m)
	}
}

func TestUnknownTypeRejected(t *testing.T) {
	url := testServer(t, DefaultConfig())
	c := mustDial(t, url)
	c.send(map[string]any{"type": "definitely-not-a-real-type"})
	m := c.recv()
	if m["type"] != typeError || m["code"] != errBadMessage {
		t.Fatalf("expected bad_message error, got %v", m)
	}
}

func TestOriginAllowlist(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AllowedOrigins = []string{"https://sendarc.example"}
	url := testServer(t, cfg)

	// An allowed browser origin connects.
	if _, err := dial(t, url, "https://sendarc.example"); err != nil {
		t.Fatalf("allowed origin was rejected: %v", err)
	}
	// A disallowed origin is refused at the upgrade.
	if _, err := dial(t, url, "https://evil.example"); err == nil {
		t.Fatal("disallowed origin should have been rejected")
	}
	// A native client (no Origin header) is always allowed.
	if _, err := dial(t, url, ""); err != nil {
		t.Fatalf("native client (no origin) was rejected: %v", err)
	}
}

func TestMessageSizeCap(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxMessageBytes = 256
	url := testServer(t, cfg)

	c := mustDial(t, url)
	big := make([]byte, cfg.MaxMessageBytes+1)
	for i := range big {
		big[i] = 'a'
	}
	// Writing may succeed locally; the server closes the socket for exceeding the
	// read limit, so a subsequent read fails.
	c.sendRaw(big)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, _, err := c.conn.Read(ctx); err == nil {
		t.Fatal("expected the socket to close after an oversize message")
	}
}
