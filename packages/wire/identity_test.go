package wire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type IdentityTestVector struct {
	Name        string `json:"name"`
	SeedHex     string `json:"seed_hex"`
	PubKeyHex   string `json:"pub_key_hex"`
	PrivKeyHex  string `json:"priv_key_hex"`
	DeviceID    string `json:"device_id"`
	Fingerprint string `json:"fingerprint"`
	MessageHex  string `json:"message_hex"`
	SigHex      string `json:"sig_hex"`
}

func TestDeviceIdentityGenerationAndSigning(t *testing.T) {
	id, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatalf("GenerateDeviceIdentity: %v", err)
	}

	if !ValidateDeviceID(id.DeviceID) {
		t.Errorf("expected valid device ID, got %q", id.DeviceID)
	}

	if !strings.HasPrefix(id.Fingerprint, FingerprintPrefix) {
		t.Errorf("expected fingerprint prefix %q, got %q", FingerprintPrefix, id.Fingerprint)
	}

	msg := []byte("sendbeam-identity-test-message")
	sig, err := id.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if !VerifyDeviceSignature(id.PublicKey, msg, sig) {
		t.Errorf("signature verification failed for valid message")
	}

	// Corrupted message should fail
	if VerifyDeviceSignature(id.PublicKey, []byte("tampered-message"), sig) {
		t.Errorf("signature verification succeeded for tampered message")
	}

	// Corrupted signature should fail
	corruptedSig := append([]byte(nil), sig...)
	corruptedSig[0] ^= 0xff
	if VerifyDeviceSignature(id.PublicKey, msg, corruptedSig) {
		t.Errorf("signature verification succeeded for corrupted signature")
	}
}

func TestDeterministicIdentityVectors(t *testing.T) {
	// 3 deterministic test seeds (32 bytes each)
	seeds := []struct {
		name    string
		seedHex string
		msg     string
	}{
		{
			name:    "vector-alpha",
			seedHex: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
			msg:     "sendbeam-vector-alpha-hello",
		},
		{
			name:    "vector-beta",
			seedHex: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
			msg:     "sendbeam-vector-beta-pairing-ceremony",
		},
		{
			name:    "vector-gamma",
			seedHex: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
			msg:     "sendbeam-vector-gamma-trusted-session-v2",
		},
	}

	var vectors []IdentityTestVector

	for _, s := range seeds {
		seedBytes, err := hex.DecodeString(s.seedHex)
		if err != nil {
			t.Fatalf("decode seed hex: %v", err)
		}

		priv := ed25519.NewKeyFromSeed(seedBytes)
		pub := priv.Public().(ed25519.PublicKey)

		id, err := NewDeviceIdentity(pub, priv)
		if err != nil {
			t.Fatalf("NewDeviceIdentity: %v", err)
		}

		msgBytes := []byte(s.msg)
		sig, err := id.Sign(msgBytes)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}

		vec := IdentityTestVector{
			Name:        s.name,
			SeedHex:     s.seedHex,
			PubKeyHex:   hex.EncodeToString(pub),
			PrivKeyHex:  hex.EncodeToString(priv),
			DeviceID:    id.DeviceID,
			Fingerprint: id.Fingerprint,
			MessageHex:  hex.EncodeToString(msgBytes),
			SigHex:      hex.EncodeToString(sig),
		}

		// Verify consistency
		if !VerifyDeviceSignature(pub, msgBytes, sig) {
			t.Fatalf("[%s] signature did not verify", s.name)
		}

		// Check public key hash matches DeviceID
		digest := sha256.Sum256(pub)
		expectedDevID := DeviceIDPrefix + hex.EncodeToString(digest[:])
		if id.DeviceID != expectedDevID {
			t.Errorf("[%s] DeviceID mismatch: got %s, want %s", s.name, id.DeviceID, expectedDevID)
		}

		vectors = append(vectors, vec)
	}

	// Write vectors to testdata for TypeScript cross-verification
	testdataDir := filepath.Join("testdata")
	_ = os.MkdirAll(testdataDir, 0755)
	vectorFile := filepath.Join(testdataDir, "identity-vectors.json")
	data, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		t.Fatalf("marshal vectors: %v", err)
	}
	if err := os.WriteFile(vectorFile, data, 0644); err != nil {
		t.Fatalf("write vector file: %v", err)
	}
}

func TestParsePublicKeyHexAndValidation(t *testing.T) {
	id, _ := GenerateDeviceIdentity()
	hexPub := id.PublicKeyHex()

	parsedPub, err := ParsePublicKeyHex(hexPub)
	if err != nil {
		t.Fatalf("ParsePublicKeyHex: %v", err)
	}
	if !bytes.Equal(parsedPub, id.PublicKey) {
		t.Errorf("parsed public key does not match original")
	}

	// Invalid hex
	if _, err := ParsePublicKeyHex("invalid-hex!"); err == nil {
		t.Errorf("expected error for invalid hex string")
	}

	// Wrong length
	if _, err := ParsePublicKeyHex("01020304"); err == nil {
		t.Errorf("expected error for short public key")
	}
}
