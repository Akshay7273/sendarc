package wire

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestLengthPrefixLE(t *testing.T) {
	// 8-byte little-endian, matching the RFC 9382 transcript encoding.
	if got := hex.EncodeToString(lengthPrefixLE(0)); got != "0000000000000000" {
		t.Errorf("lengthPrefixLE(0) = %s", got)
	}
	if got := hex.EncodeToString(lengthPrefixLE(1)); got != "0100000000000000" {
		t.Errorf("lengthPrefixLE(1) = %s", got)
	}
	if got := hex.EncodeToString(lengthPrefixLE(65)); got != "4100000000000000" {
		t.Errorf("lengthPrefixLE(65) = %s", got)
	}
}

func TestWithLengthPrefix(t *testing.T) {
	got := withLengthPrefix([]byte{0xaa, 0xbb, 0xcc})
	want := append(lengthPrefixLE(3), 0xaa, 0xbb, 0xcc)
	if !bytes.Equal(got, want) {
		t.Errorf("withLengthPrefix = %x, want %x", got, want)
	}
	if empty := withLengthPrefix(nil); !bytes.Equal(empty, lengthPrefixLE(0)) {
		t.Errorf("withLengthPrefix(nil) = %x", empty)
	}
}

func TestHKDFEmptySaltEquivalence(t *testing.T) {
	// A nil salt must behave as RFC 5869's default (HashLen zero bytes), which is the
	// cross-language interop guarantee against WebCrypto's zero-length salt.
	ikm := []byte("input keying material")
	info := []byte("sendarc/1 test")
	withNil, err := hkdfSHA256(ikm, nil, info, 32)
	if err != nil {
		t.Fatal(err)
	}
	withZeros, err := hkdfSHA256(ikm, make([]byte, 32), info, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(withNil, withZeros) {
		t.Error("nil salt and 32 zero bytes should produce identical HKDF output")
	}
}
