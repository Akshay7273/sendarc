package rendezvous

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/sendbeam/wire"
)

// mockHub stands in for the blind signaling server: it allocates a room, pairs the two
// peers, and forwards pake/confirm/caps verbatim — exactly the envelope the real server
// sees. Every message handed to it is recorded in seen so a test can assert the word code
// never crosses it; onForward can tamper with a forwarded frame.
//
// Unlike the TypeScript MockHub, delivery is queued rather than synchronous. A Session
// serializes its transitions under a mutex, so routing a message straight back into a peer
// that is still inside a handler (e.g. the sealed caps returning to an offerer mid-onConfirm)
// would deadlock. Instead sinkFor only enqueues; run drains the queue, so every Handle runs
// outside any session's lock — deterministic and single-goroutine.
type mockHub struct {
	offerer   *Session
	joiner    *Session
	room      int
	onForward func(Message) Message

	seen  []Message
	queue []routed
}

type routed struct {
	from Role
	msg  Message
}

func newHub(room int) *mockHub {
	return &mockHub{room: room, onForward: func(m Message) Message { return m }}
}

func (h *mockHub) sinkFor(role Role) Sink {
	return SinkFunc(func(m Message) error {
		h.seen = append(h.seen, m)
		h.queue = append(h.queue, routed{from: role, msg: m})
		return nil
	})
}

// run drains the queue until both peers are quiet, dispatching each outbound message to its
// destination the way the server would.
func (h *mockHub) run() {
	for len(h.queue) > 0 {
		r := h.queue[0]
		h.queue = h.queue[1:]
		h.dispatch(r.from, r.msg)
	}
}

func (h *mockHub) dispatch(from Role, msg Message) {
	switch msg.Type {
	case typeCreate:
		room := h.room
		h.offerer.Handle(Message{Type: typeCreated, Room: &room})
	case typeJoin:
		h.offerer.Handle(Message{Type: typePeerJoined, Role: string(RoleOfferer)})
		h.joiner.Handle(Message{Type: typePeerJoined, Role: string(RoleJoiner)})
	default:
		other := h.joiner
		if from == RoleJoiner {
			other = h.offerer
		}
		other.Handle(h.onForward(msg))
	}
}

// makePair wires an offerer/joiner pair to a hub; the joiner is given code out-of-band.
func makePair(h *mockHub, code, words string) (offerer, joiner *Session, phases *[]Phase) {
	seq := &[]Phase{}
	offerer = New(Options{
		Role:      RoleOfferer,
		Transport: h.sinkFor(RoleOfferer),
		Words:     words,
		OnPhase:   func(p Phase) { *seq = append(*seq, p) },
	})
	joiner = New(Options{
		Role:      RoleJoiner,
		Transport: h.sinkFor(RoleJoiner),
		Code:      code,
	})
	h.offerer = offerer
	h.joiner = joiner
	return offerer, joiner, seq
}

func TestSessionReachesSharedKeyAndRoundTripsCaps(t *testing.T) {
	hub := newHub(0)
	offerer, joiner, phases := makePair(hub, "0-brave-otter", "brave-otter")
	offerer.Start()
	joiner.Start()
	hub.run()

	ro, err := offerer.Result()
	if err != nil {
		t.Fatalf("offerer: %v", err)
	}
	rj, err := joiner.Result()
	if err != nil {
		t.Fatalf("joiner: %v", err)
	}

	// Same handshake, same master key and directional keys on both ends.
	if !bytes.Equal(ro.Master, rj.Master) {
		t.Error("master keys differ")
	}
	if !bytes.Equal(ro.Keys.O2J.Key, rj.Keys.O2J.Key) {
		t.Error("o2j keys differ")
	}
	if !bytes.Equal(ro.Keys.J2O.Key, rj.Keys.J2O.Key) {
		t.Error("j2o keys differ")
	}

	if ro.Role != RoleOfferer || rj.Role != RoleJoiner {
		t.Errorf("roles: offerer=%q joiner=%q", ro.Role, rj.Role)
	}
	if ro.Code != "0-brave-otter" || rj.Code != "0-brave-otter" {
		t.Errorf("codes: offerer=%q joiner=%q", ro.Code, rj.Code)
	}

	// Each side received the other's caps.
	if !reflect.DeepEqual(ro.RemoteCaps, rj.LocalCaps) {
		t.Errorf("offerer remote caps %+v != joiner local caps %+v", ro.RemoteCaps, rj.LocalCaps)
	}
	if !reflect.DeepEqual(rj.RemoteCaps, ro.LocalCaps) {
		t.Errorf("joiner remote caps %+v != offerer local caps %+v", rj.RemoteCaps, ro.LocalCaps)
	}

	// The caps exchange consumed counter 0 in each direction; the transfer continues at 1.
	if ro.SendCounter != 1 || ro.RecvCounter != 1 {
		t.Errorf("offerer counters: send=%d recv=%d, want 1/1", ro.SendCounter, ro.RecvCounter)
	}

	if got := offerer.Phase(); got != PhaseEstablished {
		t.Errorf("offerer phase = %q, want established", got)
	}
	want := []Phase{
		PhaseAllocating,
		PhaseWaiting,
		PhaseHandshaking,
		PhaseConfirming,
		PhaseExchangingCaps,
		PhaseEstablished,
	}
	if !reflect.DeepEqual(*phases, want) {
		t.Errorf("offerer phases = %v, want %v", *phases, want)
	}
}

func TestSessionFailsClosedWhenCodesDisagree(t *testing.T) {
	hub := newHub(0)
	// Offerer's words are brave-otter; the joiner types a wrong last word.
	offerer, joiner, _ := makePair(hub, "0-brave-tiger", "brave-otter")
	offerer.Start()
	joiner.Start()
	hub.run()

	assertFailsWith(t, "offerer", offerer, CodeConfirmationFailed)
	assertFailsWith(t, "joiner", joiner, CodeConfirmationFailed)
	if got := offerer.Phase(); got != PhaseFailed {
		t.Errorf("offerer phase = %q, want failed", got)
	}
}

func TestSessionRejectsTamperedCapsFrame(t *testing.T) {
	// Corrupt every forwarded caps frame so both peers' opens fail.
	hub := newHub(0)
	hub.onForward = func(m Message) Message {
		if m.Type != typeCaps {
			return m
		}
		raw, err := b64decode(m.Frame)
		if err != nil {
			t.Fatalf("decode caps frame: %v", err)
		}
		raw[len(raw)-1] ^= 0xff // flip a tag byte
		m.Frame = b64encode(raw)
		return m
	}
	offerer, joiner, _ := makePair(hub, "0-brave-otter", "brave-otter")
	offerer.Start()
	joiner.Start()
	hub.run()

	assertFailsWith(t, "offerer", offerer, CodeBadPeerMessage)
	assertFailsWith(t, "joiner", joiner, CodeBadPeerMessage)
}

func TestSessionNeverLeaksWordCode(t *testing.T) {
	hub := newHub(0)
	offerer, joiner, _ := makePair(hub, "0-brave-otter", "brave-otter")
	offerer.Start()
	joiner.Start()
	hub.run()

	if _, err := offerer.Result(); err != nil {
		t.Fatalf("offerer: %v", err)
	}
	if _, err := joiner.Result(); err != nil {
		t.Fatalf("joiner: %v", err)
	}

	allowed := map[string]bool{
		typeCreate: true, typeJoin: true, typePake: true,
		typeConfirm: true, typeCaps: true, typeBye: true,
	}
	for _, m := range hub.seen {
		if !allowed[m.Type] {
			t.Errorf("server saw disallowed message type %q", m.Type)
		}
		enc, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("marshal seen message: %v", err)
		}
		for _, leak := range []string{"brave", "otter", "words", "code"} {
			if strings.Contains(string(enc), leak) {
				t.Errorf("message %q leaked %q: %s", m.Type, leak, enc)
			}
		}
	}
}

func assertFailsWith(t *testing.T, who string, s *Session, code string) {
	t.Helper()
	_, err := s.Result()
	if err == nil {
		t.Fatalf("%s: expected failure %q, got success", who, code)
	}
	var re *Error
	if !errorsAs(err, &re) {
		t.Fatalf("%s: error %v is not a *rendezvous.Error", who, err)
	}
	if re.Code != code {
		t.Errorf("%s: code = %q, want %q", who, re.Code, code)
	}
}

// errorsAs is a tiny local errors.As so the test needs no extra import beyond the ones it
// already uses; the session only ever settles with a *Error.
func errorsAs(err error, target **Error) bool {
	re, ok := err.(*Error)
	if ok {
		*target = re
	}
	return ok
}

// Guard: the caps payload the session seals must be valid JSON for wire.FrameCaps, so a
// browser peer can parse it. This mirrors DefaultCaps round-tripping through encoding/json.
func TestDefaultCapsJSONShape(t *testing.T) {
	enc, err := json.Marshal(DefaultCaps())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(enc, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["version"] != wire.ProtocolVersion {
		t.Errorf("version = %v, want %q", got["version"], wire.ProtocolVersion)
	}
	// features/sinkHints must serialize as arrays, never null.
	for _, k := range []string{"features", "sinkHints"} {
		if _, ok := got[k].([]any); !ok {
			t.Errorf("%s = %v (%T), want a JSON array", k, got[k], got[k])
		}
	}
}
