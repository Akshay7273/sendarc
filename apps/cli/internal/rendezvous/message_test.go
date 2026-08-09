package rendezvous

import (
	"encoding/json"
	"testing"
)

// TestSDPMessageWireShape pins the sdp envelope, including that seq:0 — the first
// message a sender emits — is present on the wire. A dropped seq:0 would let a peer
// silently accept a replayed first offer, so this guards the pointer-with-omitempty
// choice that keeps the field for authenticated signaling while omitting it elsewhere.
func TestSDPMessageWireShape(t *testing.T) {
	b, err := MarshalMessage(NewSDP(0, "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\n", "dGFn"))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"type": "sdp",
		"sdp":  "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\n",
		"seq":  float64(0),
		"mac":  "dGFn",
	}
	if len(got) != len(want) {
		t.Fatalf("sdp has fields %v, want exactly %v", keysOf(got), keysOf(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("sdp[%q] = %v, want %v", k, got[k], v)
		}
	}
}

// TestICEMessageWireShape pins the ice envelope and a non-zero seq.
func TestICEMessageWireShape(t *testing.T) {
	b, err := MarshalMessage(NewICE(7, "candidate:1 1 udp 2130706431 192.0.2.1 54321 typ host", "bWFj"))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"type": "ice",
		"cand": "candidate:1 1 udp 2130706431 192.0.2.1 54321 typ host",
		"seq":  float64(7),
		"mac":  "bWFj",
	}
	if len(got) != len(want) {
		t.Fatalf("ice has fields %v, want exactly %v", keysOf(got), keysOf(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("ice[%q] = %v, want %v", k, got[k], v)
		}
	}
}

// TestHandshakeMessagesOmitSignalingFields confirms sdp/cand/seq never leak onto a
// handshake message: a create carries only its type.
func TestHandshakeMessagesOmitSignalingFields(t *testing.T) {
	b, err := MarshalMessage(Message{Type: typeCreate})
	if err != nil {
		t.Fatal(err)
	}
	if s := string(b); s != `{"type":"create"}` {
		t.Errorf("create = %s, want {\"type\":\"create\"}", s)
	}
}

func TestRelayControlWireShapes(t *testing.T) {
	open, err := MarshalMessage(NewRelayOpen())
	if err != nil {
		t.Fatal(err)
	}
	if string(open) != `{"type":"relay_open"}` {
		t.Fatalf("relay open = %s", open)
	}
	credit, err := MarshalMessage(NewRelayCredit(524288))
	if err != nil {
		t.Fatal(err)
	}
	if string(credit) != `{"type":"relay_credit","bytes":524288}` {
		t.Fatalf("relay credit = %s", credit)
	}
}

// TestMessageRoundTrip confirms an sdp message survives marshal→unmarshal intact,
// including the pointer seq.
func TestMessageRoundTrip(t *testing.T) {
	orig := NewSDP(3, "sdp-body", "mac-tag")
	b, err := MarshalMessage(orig)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalMessage(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != typeSDP || got.Sdp != "sdp-body" || got.Mac != "mac-tag" {
		t.Errorf("round-trip = %#v", got)
	}
	if got.Seq == nil || *got.Seq != 3 {
		t.Errorf("round-trip seq = %v, want 3", got.Seq)
	}
}

func keysOf(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
