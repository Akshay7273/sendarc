package wire

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestU32BE(t *testing.T) {
	cases := []struct {
		n    uint32
		want string
	}{
		{0, "00000000"},
		{1, "00000001"},
		{7, "00000007"},
		{0xffffffff, "ffffffff"},
	}
	for _, c := range cases {
		if got := hex.EncodeToString(U32BE(c.n)); got != c.want {
			t.Errorf("U32BE(%d) = %s, want %s", c.n, got, c.want)
		}
	}
}

func TestSignalMacInputShape(t *testing.T) {
	// type || ":" || u32be(room) || ":" || u32be(seq) || ":" || body, colons as literal 0x3a.
	got := SignalMacInput(SignalSDP, 7, 3, "hi")
	want := bytes.Join([][]byte{
		[]byte("sdp"), {':'}, {0, 0, 0, 7}, {':'}, {0, 0, 0, 3}, {':'}, []byte("hi"),
	}, nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("SignalMacInput = %x, want %x", got, want)
	}
}

// The committed cross-implementation vector: the Go MAC must equal the byte the TypeScript
// codec produces for the same inputs, or a browser peer and a CLI peer cannot authenticate.
func TestSignSignalVector(t *testing.T) {
	var doc struct {
		AuthMAC struct {
			KAuthHex string `json:"kAuthHex"`
			Type     string `json:"type"`
			Room     uint32 `json:"room"`
			Seq      uint32 `json:"seq"`
			Body     string `json:"body"`
			MAC      string `json:"mac"`
		} `json:"authmac"`
	}
	loadVectors(t, "sendbeam-crypto.json", &doc)
	v := doc.AuthMAC
	kAuth := mustHex(t, v.KAuthHex)

	got := SignSignal(kAuth, SignalMacType(v.Type), v.Room, v.Seq, v.Body)
	if hex.EncodeToString(got) != v.MAC {
		t.Fatalf("SignSignal = %x, want %s", got, v.MAC)
	}
	if !VerifySignal(kAuth, SignalMacType(v.Type), v.Room, v.Seq, v.Body, mustHex(t, v.MAC)) {
		t.Fatal("VerifySignal rejected the committed vector")
	}
}

func TestVerifySignalRejectsTampering(t *testing.T) {
	kAuth := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	mac := SignSignal(kAuth, SignalSDP, 7, 3, "body")

	if !VerifySignal(kAuth, SignalSDP, 7, 3, "body", mac) {
		t.Fatal("genuine MAC rejected")
	}
	// Every altered field must fail closed.
	if VerifySignal(kAuth, SignalICE, 7, 3, "body", mac) {
		t.Error("type change accepted")
	}
	if VerifySignal(kAuth, SignalSDP, 8, 3, "body", mac) {
		t.Error("room change accepted")
	}
	if VerifySignal(kAuth, SignalSDP, 7, 4, "body", mac) {
		t.Error("seq change accepted")
	}
	if VerifySignal(kAuth, SignalSDP, 7, 3, "body!", mac) {
		t.Error("body change accepted")
	}
	// A flipped bit or a length change in the tag must be rejected.
	bad := append([]byte(nil), mac...)
	bad[0] ^= 0x01
	if VerifySignal(kAuth, SignalSDP, 7, 3, "body", bad) {
		t.Error("flipped MAC bit accepted")
	}
	if VerifySignal(kAuth, SignalSDP, 7, 3, "body", mac[:len(mac)-1]) {
		t.Error("truncated MAC accepted")
	}
}

func TestAuthKeysRolePairing(t *testing.T) {
	out := &Spake2Output{
		KcA: []byte("offerer-confirmation-key-A......."),
		KcB: []byte("joiner-confirmation-key-B......."),
	}
	off := AuthKeys(RoleOfferer, out)
	join := AuthKeys(RoleJoiner, out)

	if !bytes.Equal(off.Sign, out.KcA) || !bytes.Equal(off.Verify, out.KcB) {
		t.Error("offerer must sign with KcA and verify with KcB")
	}
	if !bytes.Equal(join.Sign, out.KcB) || !bytes.Equal(join.Verify, out.KcA) {
		t.Error("joiner must sign with KcB and verify with KcA")
	}
	// The pairing must let each peer verify the other: one signs, the other verifies.
	sign := func(k []byte) []byte { return SignSignal(k, SignalSDP, 1, 0, "x") }
	if !VerifySignal(join.Verify, SignalSDP, 1, 0, "x", sign(off.Sign)) {
		t.Error("joiner cannot verify the offerer's MAC")
	}
	if !VerifySignal(off.Verify, SignalSDP, 1, 0, "x", sign(join.Sign)) {
		t.Error("offerer cannot verify the joiner's MAC")
	}
}
