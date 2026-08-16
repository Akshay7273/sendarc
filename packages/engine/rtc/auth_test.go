package rtc

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/wire"
)

const testRoom = 42

// newPair builds an offerer/joiner authenticator sharing a room and confirmation keys, the way
// a completed handshake would. KcA and KcB are distinct so a peer cannot verify its own
// signatures — the crux of the man-in-the-middle defense.
func newPair(room int) (offerer, joiner *SignalAuthenticator) {
	out := &wire.Spake2Output{
		KcA: bytes.Repeat([]byte{0xA1}, 32),
		KcB: bytes.Repeat([]byte{0xB2}, 32),
	}
	return FromSession(wire.RoleOfferer, room, out), FromSession(wire.RoleJoiner, room, out)
}

func TestSignVerifyRoundTripAcrossPeers(t *testing.T) {
	offerer, joiner := newPair(testRoom)

	offer := offerer.SignSDP("v=0\r\no=offer\r\n")
	if offer.Seq == nil || *offer.Seq != 0 {
		t.Fatalf("first sdp seq = %v, want 0", offer.Seq)
	}
	if err := joiner.Verify(offer); err != nil {
		t.Fatalf("joiner rejected genuine offer: %v", err)
	}

	cand := offerer.SignICE("candidate:1 1 udp 1 192.0.2.1 5000 typ host")
	if cand.Seq == nil || *cand.Seq != 1 {
		t.Fatalf("ice seq = %v, want 1 (monotonic across kinds)", cand.Seq)
	}
	if err := joiner.Verify(cand); err != nil {
		t.Fatalf("joiner rejected genuine candidate: %v", err)
	}

	// The reverse direction authenticates under the mirrored keys.
	answer := joiner.SignSDP("v=0\r\no=answer\r\n")
	if err := offerer.Verify(answer); err != nil {
		t.Fatalf("offerer rejected genuine answer: %v", err)
	}
}

func TestVerifyRejectsReplay(t *testing.T) {
	offerer, joiner := newPair(testRoom)
	offer := offerer.SignSDP("v=0\r\n")
	if err := joiner.Verify(offer); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if err := joiner.Verify(offer); err == nil || !strings.Contains(err.Error(), "non-increasing") {
		t.Fatalf("replay accepted: err = %v", err)
	}
}

func TestVerifyRejectsReorder(t *testing.T) {
	offerer, joiner := newPair(testRoom)
	m0 := offerer.SignSDP("a")
	m1 := offerer.SignICE("b")
	m2 := offerer.SignICE("c")

	if err := joiner.Verify(m0); err != nil {
		t.Fatalf("verify m0: %v", err)
	}
	if err := joiner.Verify(m2); err != nil {
		t.Fatalf("verify m2: %v", err)
	}
	// m1 arrives after m2 — strictly-increasing seq rejects the late message.
	if err := joiner.Verify(m1); err == nil || !strings.Contains(err.Error(), "non-increasing") {
		t.Fatalf("out-of-order message accepted: err = %v", err)
	}
}

func TestVerifyRejectsTamperedBody(t *testing.T) {
	offerer, joiner := newPair(testRoom)
	offer := offerer.SignSDP("v=0\r\noriginal\r\n")
	offer.Sdp = "v=0\r\ntampered\r\n" // server swaps the SDP, keeps the tag
	if err := joiner.Verify(offer); err == nil || !strings.Contains(err.Error(), "bad mac") {
		t.Fatalf("tampered body accepted: err = %v", err)
	}
}

func TestVerifyRejectsTamperedMac(t *testing.T) {
	offerer, joiner := newPair(testRoom)
	offer := offerer.SignSDP("v=0\r\n")
	raw, err := base64.RawURLEncoding.DecodeString(offer.Mac)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 0x01
	offer.Mac = base64.RawURLEncoding.EncodeToString(raw)
	if err := joiner.Verify(offer); err == nil || !strings.Contains(err.Error(), "bad mac") {
		t.Fatalf("tampered mac accepted: err = %v", err)
	}
}

func TestVerifyRejectsMalformedMac(t *testing.T) {
	offerer, joiner := newPair(testRoom)
	offer := offerer.SignSDP("v=0\r\n")
	offer.Mac = "not*valid*base64url"
	if err := joiner.Verify(offer); err == nil || !strings.Contains(err.Error(), "malformed mac") {
		t.Fatalf("malformed mac accepted: err = %v", err)
	}
}

// TestVerifyRejectsTypeConfusion pins that the message type is bound into the MAC: relabeling a
// signed sdp as ice (reusing body, seq, and tag) does not verify.
func TestVerifyRejectsTypeConfusion(t *testing.T) {
	offerer, joiner := newPair(testRoom)
	offer := offerer.SignSDP("shared-body")
	forged := rendezvous.NewICE(*offer.Seq, "shared-body", offer.Mac)
	if err := joiner.Verify(forged); err == nil || !strings.Contains(err.Error(), "bad mac") {
		t.Fatalf("type-confused message accepted: err = %v", err)
	}
}

// TestVerifyRejectsForeignRoom pins that the room is bound into the MAC: a tag minted for one
// room does not verify against a verifier scoped to another.
func TestVerifyRejectsForeignRoom(t *testing.T) {
	offerer, _ := newPair(testRoom)
	_, otherJoiner := newPair(testRoom + 1)
	offer := offerer.SignSDP("v=0\r\n")
	if err := otherJoiner.Verify(offer); err == nil || !strings.Contains(err.Error(), "bad mac") {
		t.Fatalf("cross-room message accepted: err = %v", err)
	}
}

// TestVerifyRejectsOwnSignature pins that a peer cannot verify its own messages — the offerer
// verifies with KcB but signs with KcA — which is what stops a server from looping a peer's
// SDP back as if it came from the other side.
func TestVerifyRejectsOwnSignature(t *testing.T) {
	offerer, _ := newPair(testRoom)
	offer := offerer.SignSDP("v=0\r\n")
	if err := offerer.Verify(offer); err == nil || !strings.Contains(err.Error(), "bad mac") {
		t.Fatalf("self-signed message accepted: err = %v", err)
	}
}

func TestVerifyRejectsMissingSeq(t *testing.T) {
	_, joiner := newPair(testRoom)
	msg := rendezvous.Message{Type: "sdp", Sdp: "x", Mac: "AAAA"}
	if err := joiner.Verify(msg); err == nil || !strings.Contains(err.Error(), "missing seq") {
		t.Fatalf("message without seq accepted: err = %v", err)
	}
}

func TestVerifyRejectsNonSignalingType(t *testing.T) {
	_, joiner := newPair(testRoom)
	seq := 0
	msg := rendezvous.Message{Type: "caps", Seq: &seq, Mac: "AAAA"}
	if err := joiner.Verify(msg); err == nil || !strings.Contains(err.Error(), "not a signaling message") {
		t.Fatalf("non-signaling message accepted: err = %v", err)
	}
}
