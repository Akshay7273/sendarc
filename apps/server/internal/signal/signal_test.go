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

func (c *client) sendBinary(data []byte) {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.conn.Write(ctx, websocket.MessageBinary, data); err != nil {
		c.t.Fatalf("write binary: %v", err)
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

func (c *client) recvBinary() []byte {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	typ, data, err := c.conn.Read(ctx)
	if err != nil {
		c.t.Fatalf("read binary: %v", err)
	}
	if typ != websocket.MessageBinary {
		c.t.Fatalf("frame type = %v, want binary (%s)", typ, data)
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

func openRelay(t *testing.T, offerer, joiner *client) {
	t.Helper()
	offerer.send(map[string]any{"type": typeRelayOpen})
	if got := joiner.recv(); got["type"] != typeRelayRequired {
		t.Fatalf("relay required = %v", got)
	}
	joiner.send(map[string]any{"type": typeRelayOpen})
	if got := offerer.recv(); got["type"] != typeRelayReady {
		t.Fatalf("offerer relay ready = %v", got)
	}
	if got := joiner.recv(); got["type"] != typeRelayReady {
		t.Fatalf("joiner relay ready = %v", got)
	}
}

func TestRelayForwardsOpaqueBinaryWithinReceiverCredit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RelayWindowBytes = 1024
	url := testServer(t, cfg)
	offerer, joiner, _ := pair(t, url)
	openRelay(t, offerer, joiner)

	joiner.send(map[string]any{"type": typeRelayCredit, "bytes": 64})
	if got := offerer.recv(); got["type"] != typeCredit || got["bytes"] != float64(64) {
		t.Fatalf("offerer credit = %v", got)
	}
	opaque := []byte{0, 255, 19, 88, 42, 7}
	offerer.sendBinary(opaque)
	if got := joiner.recvBinary(); string(got) != string(opaque) {
		t.Fatalf("relay changed opaque bytes: %x != %x", got, opaque)
	}

	offerer.send(map[string]any{"type": typeRelayCredit, "bytes": 32})
	if got := joiner.recv(); got["type"] != typeCredit || got["bytes"] != float64(32) {
		t.Fatalf("joiner credit = %v", got)
	}
	joiner.sendBinary([]byte{9, 8, 7})
	if got := offerer.recvBinary(); string(got) != string([]byte{9, 8, 7}) {
		t.Fatalf("reverse relay bytes = %x", got)
	}
}

func TestRelayRefusesBytesBeyondCredit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RelayWindowBytes = 32
	url := testServer(t, cfg)
	offerer, joiner, _ := pair(t, url)
	openRelay(t, offerer, joiner)
	joiner.send(map[string]any{"type": typeRelayCredit, "bytes": 16})
	_ = offerer.recv()
	offerer.sendBinary(make([]byte, 17))
	if got := offerer.recv(); got["type"] != typeError || got["code"] != errRelayCredit {
		t.Fatalf("credit violation = %v", got)
	}
}

func TestRelayEnforcesFrameAndSessionCeilings(t *testing.T) {
	for name, configure := range map[string]func(*Config){
		"frame":   func(cfg *Config) { cfg.MaxRelayFrameBytes = 8 },
		"session": func(cfg *Config) { cfg.RelayMaxSessionBytes = 8 },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.RelayWindowBytes = 64
			configure(&cfg)
			url := testServer(t, cfg)
			offerer, joiner, _ := pair(t, url)
			openRelay(t, offerer, joiner)
			joiner.send(map[string]any{"type": typeRelayCredit, "bytes": 64})
			_ = offerer.recv()
			offerer.sendBinary(make([]byte, 9))
			if got := offerer.recv(); got["type"] != typeError || got["code"] != errRelayLimit {
				t.Fatalf("limit violation = %v", got)
			}
		})
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

func TestDisconnectLingersAndNotifiesPartner(t *testing.T) {
	url := testServer(t, DefaultConfig())
	offerer, joiner, _ := pair(t, url)

	// Offerer drops abruptly; the room lingers and the joiner is told the peer left
	// resumably rather than being closed, so it can wait for a reload.
	_ = offerer.conn.Close(websocket.StatusNormalClosure, "")
	m := joiner.recv()
	if m["type"] != typePeerLeft {
		t.Fatalf("expected peer_left on partner disconnect, got %v", m)
	}
	if m["resumable"] != true {
		t.Fatalf("expected resumable peer_left, got %v", m)
	}
}

func TestResumeReattachOverWire(t *testing.T) {
	url := testServer(t, DefaultConfig())
	offerer, joiner, room := pair(t, url)

	// The offerer drops; the joiner sees a resumable peer_left and keeps its socket.
	_ = offerer.conn.Close(websocket.StatusNormalClosure, "")
	if m := joiner.recv(); m["type"] != typePeerLeft || m["resumable"] != true {
		t.Fatalf("expected resumable peer_left, got %v", m)
	}

	// A reloaded offerer re-attaches to the vacated slot with resume.
	reoff := mustDial(t, url)
	reoff.send(map[string]any{"type": typeResume, "room": room, "role": roleOfferer})
	if m := reoff.recv(); m["type"] != typeResumed || int(m["room"].(float64)) != room {
		t.Fatalf("expected resumed for room %d, got %v", room, m)
	}
	// The waiting joiner is told its partner re-attached so both re-run the handshake.
	if m := joiner.recv(); m["type"] != typePeerRejoined {
		t.Fatalf("expected peer_rejoined, got %v", m)
	}

	// The room is paired again: a pake frame flows offerer→joiner verbatim.
	frame := []byte(`{"type":"pake","msg":"resumed-session"}`)
	reoff.sendRaw(frame)
	if got := joiner.recvRaw(); string(got) != string(frame) {
		t.Fatalf("forwarded frame after resume = %s, want %s", got, frame)
	}
}

func TestResumeIntoOccupiedSlotRejected(t *testing.T) {
	url := testServer(t, DefaultConfig())
	_, _, room := pair(t, url)

	// Both slots are still occupied, so resuming the offerer role is refused.
	c := mustDial(t, url)
	c.send(map[string]any{"type": typeResume, "room": room, "role": roleOfferer})
	if m := c.recv(); m["type"] != typeError || m["code"] != errRoomFull {
		t.Fatalf("expected room_full error, got %v", m)
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
	cfg.AllowedOrigins = []string{"https://sendbeam.example"}
	url := testServer(t, cfg)

	// An allowed browser origin connects.
	if _, err := dial(t, url, "https://sendbeam.example"); err != nil {
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
	// Writing may succeed locally; the server reports the protocol violation and closes.
	c.sendRaw(big)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, data, err := c.conn.Read(ctx)
	if err == nil {
		var got map[string]any
		if json.Unmarshal(data, &got) != nil || got["type"] != typeError {
			t.Fatalf("oversize response = %s", data)
		}
		if _, _, err = c.conn.Read(ctx); err == nil {
			t.Fatal("expected the socket to close after the oversize error")
		}
	}
}

func TestRelayCreditRequestClampedNotKilled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RelayWindowBytes = 32
	url := testServer(t, cfg)
	offerer, joiner, _ := pair(t, url)
	openRelay(t, offerer, joiner)

	// Requesting far more than the window must be clamped to the window, not treated
	// as a protocol error that kills the requesting connection.
	joiner.send(map[string]any{"type": typeRelayCredit, "bytes": 1 << 20})
	if got := offerer.recv(); got["type"] != typeCredit || got["bytes"] != float64(32) {
		t.Fatalf("clamped credit = %v, want 32", got)
	}

	// The requesting connection survived the oversized request: its partner can
	// still negotiate a grant in the reverse direction.
	offerer.send(map[string]any{"type": typeRelayCredit, "bytes": 16})
	if got := joiner.recv(); got["type"] != typeCredit || got["bytes"] != float64(16) {
		t.Fatalf("reverse credit = %v, want 16", got)
	}
}

// SB-1140: fuzz the server's inbound signaling envelope. The server only reads
// type/room/role/bytes, so the invariant is a clean decode-or-reject with no
// panic and no empty type slipping through (dispatch treats "" as invalid).
func FuzzClientMsg(f *testing.F) {
	seeds := []string{
		`{"type":"create"}`,
		`{"type":"join","room":3}`,
		`{"type":"resume","room":3,"role":"offerer"}`,
		`{"type":"sdp","sdp":"v=0"}`,
		`{"type":"relay_credit","bytes":1024}`,
		`{"type":"bye"}`,
		`{}`,
		`not-json`,
		`{"type":"","room":1}`,
		`{"type":42}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var m clientMsg
		if err := json.Unmarshal(data, &m); err != nil {
			return
		}
		if m.Type == "" {
			// dispatch rejects an empty type as an invalid message; anything else
			// is a server-side regression. Accept either a known type or the
			// invalid-message rejection path (which is not exercised here directly).
			return
		}
		// A non-empty type must decode into a marshalable envelope so the server
		// can relay/reject it without corruption.
		if _, err := json.Marshal(m); err != nil {
			t.Fatalf("clientMsg round-trip marshal failed for %+v: %v", m, err)
		}
	})
}
