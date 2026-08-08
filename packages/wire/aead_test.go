package wire

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestKeyScheduleSendarcVector(t *testing.T) {
	sa := loadSendarc(t)
	ks := sa.Keyschedule

	master, err := DeriveMaster(mustHex(t, sa.Spake2.Ke), mustHex(t, sa.Spake2.Transcript))
	if err != nil {
		t.Fatalf("DeriveMaster: %v", err)
	}
	if got := hex.EncodeToString(master); got != ks.Master {
		t.Fatalf("master = %s, want %s", got, ks.Master)
	}

	keys, err := DeriveTransferKeys(master)
	if err != nil {
		t.Fatalf("DeriveTransferKeys: %v", err)
	}
	checkHex(t, 0, "o2jKey", keys.O2J.Key, ks.O2JKey)
	checkHex(t, 0, "o2jSalt", keys.O2J.Salt, ks.O2JSalt)
	checkHex(t, 0, "j2oKey", keys.J2O.Key, ks.J2OKey)
	checkHex(t, 0, "j2oSalt", keys.J2O.Salt, ks.J2OSalt)
}

func TestAeadSealMatchesSendarcVector(t *testing.T) {
	sa := loadSendarc(t)
	if sa.Aead.Direction != "o2j" {
		t.Fatalf("vector direction %q, expected o2j", sa.Aead.Direction)
	}

	master, err := DeriveMaster(mustHex(t, sa.Spake2.Ke), mustHex(t, sa.Spake2.Transcript))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := DeriveTransferKeys(master)
	if err != nil {
		t.Fatal(err)
	}

	header, err := decodeFrameHeader(mustHex(t, sa.Aead.HeaderHex))
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	in := FrameHeaderInput{
		Version:  header.Version,
		Type:     header.Type,
		Flags:    header.Flags,
		FileIdx:  header.FileIdx,
		BlockIdx: header.BlockIdx,
		FrameOff: header.FrameOff,
	}

	frame, err := Seal(keys.O2J, sa.Aead.Counter, in, []byte(sa.Aead.PlaintextUtf8))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if got := hex.EncodeToString(frame); got != sa.Aead.FrameHex {
		t.Fatalf("frame = %s, want %s", got, sa.Aead.FrameHex)
	}

	// And it round-trips back to the plaintext.
	opened, err := Open(keys.O2J, sa.Aead.Counter, frame)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(opened.Plaintext) != sa.Aead.PlaintextUtf8 {
		t.Fatalf("plaintext = %q, want %q", opened.Plaintext, sa.Aead.PlaintextUtf8)
	}
	if opened.Header.Len != uint16(len(sa.Aead.PlaintextUtf8)) {
		t.Fatalf("header len = %d, want %d", opened.Header.Len, len(sa.Aead.PlaintextUtf8))
	}
}

func TestAeadRoundTrip(t *testing.T) {
	keys := testKeys(t)
	in := FrameHeaderInput{Version: 1, Type: FrameBlockData, FileIdx: 3, BlockIdx: 7, FrameOff: 512}
	plaintext := []byte("the quick brown fox jumps over the lazy dog")

	frame, err := Seal(keys.O2J, 42, in, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(keys.O2J, 42, frame)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened.Plaintext, plaintext) {
		t.Error("round-trip plaintext mismatch")
	}
	if opened.Header.FileIdx != 3 || opened.Header.BlockIdx != 7 || opened.Header.FrameOff != 512 {
		t.Errorf("header fields not preserved: %+v", opened.Header)
	}
}

func TestAeadRejectsTampering(t *testing.T) {
	keys := testKeys(t)
	in := FrameHeaderInput{Version: 1, Type: FrameBlockData}
	frame, err := Seal(keys.O2J, 0, in, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("wrong counter", func(t *testing.T) {
		if _, err := Open(keys.O2J, 1, frame); err == nil {
			t.Error("expected auth failure at wrong counter")
		}
	})
	t.Run("wrong direction", func(t *testing.T) {
		if _, err := Open(keys.J2O, 0, frame); err == nil {
			t.Error("expected auth failure with opposite direction key")
		}
	})
	t.Run("tampered ciphertext", func(t *testing.T) {
		bad := bytes.Clone(frame)
		bad[frameHeaderBytes] ^= 0x01
		if _, err := Open(keys.O2J, 0, bad); err == nil {
			t.Error("expected auth failure on flipped ciphertext byte")
		}
	})
	t.Run("tampered header", func(t *testing.T) {
		bad := bytes.Clone(frame)
		bad[1] ^= 0x01 // flip the Type field, which is authenticated as AAD
		if _, err := Open(keys.O2J, 0, bad); err == nil {
			t.Error("expected auth failure on flipped header byte")
		}
	})
	t.Run("truncated", func(t *testing.T) {
		if _, err := Open(keys.O2J, 0, frame[:frameHeaderBytes+aeadTagBytes-1]); err == nil {
			t.Error("expected failure on truncated frame")
		}
	})
}

func TestSealRejectsOversizePayload(t *testing.T) {
	keys := testKeys(t)
	in := FrameHeaderInput{Version: 1, Type: FrameBlockData}
	if _, err := Seal(keys.O2J, 0, in, make([]byte, u16Max+1)); err == nil {
		t.Error("expected Seal to reject a payload larger than u16 max")
	}
}

// testKeys derives a throwaway pair of directional keys for tests that only need a valid
// key, not a fixture-committed one.
func testKeys(t *testing.T) TransferKeys {
	t.Helper()
	master, err := DeriveMaster(bytes.Repeat([]byte{0xab}, 16), []byte("transcript"))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := DeriveTransferKeys(master)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}
