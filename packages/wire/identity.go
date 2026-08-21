package wire

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	// DeviceIDPrefix is the canonical prefix for SendBeam device identifiers.
	DeviceIDPrefix = "sb-dev-"

	// FingerprintPrefix is the canonical prefix for human-verifiable device fingerprints.
	FingerprintPrefix = "SB1-"

	// DeviceKeyAlgorithm specifies the cryptographic signature algorithm.
	DeviceKeyAlgorithm = "Ed25519"
)

var (
	// ErrInvalidPublicKey indicates an Ed25519 public key with invalid size or format.
	ErrInvalidPublicKey = errors.New("invalid public key: expected 32-byte Ed25519 public key")

	// ErrInvalidPrivateKey indicates an Ed25519 private key with invalid size.
	ErrInvalidPrivateKey = errors.New("invalid private key: expected 64-byte Ed25519 private key or 32-byte seed")

	// ErrInvalidDeviceID indicates a malformed or mismatched device ID.
	ErrInvalidDeviceID = errors.New("invalid device id format")

	// ErrInvalidSignature indicates signature verification failure.
	ErrInvalidSignature = errors.New("invalid signature")
)

// DeviceIdentity represents a local long-term device identity backed by an Ed25519 keypair.
type DeviceIdentity struct {
	DeviceID    string            `json:"device_id"`
	Fingerprint string            `json:"fingerprint"`
	PublicKey   ed25519.PublicKey `json:"public_key"`
	PrivateKey  ed25519.PrivateKey `json:"-"`
}

// GenerateDeviceIdentity generates a fresh cryptographic device identity using cryptographically secure random bytes.
func GenerateDeviceIdentity() (*DeviceIdentity, error) {
	return GenerateDeviceIdentityFromReader(rand.Reader)
}

// GenerateDeviceIdentityFromReader generates a device identity from a specified entropy source (useful for deterministic tests).
func GenerateDeviceIdentityFromReader(r io.Reader) (*DeviceIdentity, error) {
	pub, priv, err := ed25519.GenerateKey(r)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return NewDeviceIdentity(pub, priv)
}

// NewDeviceIdentity builds a DeviceIdentity from existing public and private keys.
func NewDeviceIdentity(pub ed25519.PublicKey, priv ed25519.PrivateKey) (*DeviceIdentity, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, ErrInvalidPublicKey
	}
	if len(priv) != ed25519.PrivateKeySize {
		// If 32-byte seed was provided, expand to 64-byte Ed25519 private key
		if len(priv) == ed25519.SeedSize {
			priv = ed25519.NewKeyFromSeed(priv)
		} else {
			return nil, ErrInvalidPrivateKey
		}
	}
	// Verify that the private key matches the public key
	if !pub.Equal(priv.Public().(ed25519.PublicKey)) {
		return nil, errors.New("public key does not match private key")
	}

	devID := DeriveDeviceID(pub)
	fingerprint := DeriveFingerprint(pub)

	return &DeviceIdentity{
		DeviceID:    devID,
		Fingerprint: fingerprint,
		PublicKey:   pub,
		PrivateKey:  priv,
	}, nil
}

// DeriveDeviceID derives the canonical machine-readable DeviceID from an Ed25519 public key.
// The device ID is the SHA-256 hash of the 32-byte public key, hex-encoded with the "sb-dev-" prefix.
func DeriveDeviceID(pub ed25519.PublicKey) string {
	digest := sha256.Sum256(pub)
	return DeviceIDPrefix + hex.EncodeToString(digest[:])
}

// DeriveFingerprint derives a human-verifiable fingerprint string formatted as "SB1-XXXX-XXXX-XXXX-XXXX".
// It takes the first 10 bytes (80 bits) of SHA-256(publicKey), encodes in unpadded Base32,
// and formats into 4 groups of 4 characters.
func DeriveFingerprint(pub ed25519.PublicKey) string {
	digest := sha256.Sum256(pub)
	return FormatFingerprint(digest[:10])
}

// FormatFingerprint formats a 10-byte slice into the canonical "SB1-XXXX-XXXX-XXXX-XXXX" fingerprint string.
func FormatFingerprint(raw10Bytes []byte) string {
	if len(raw10Bytes) < 10 {
		h := sha256.Sum256(raw10Bytes)
		raw10Bytes = h[:10]
	}
	b32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw10Bytes[:10])
	b32 = strings.ToUpper(b32)
	// Ensure exactly 16 characters for 10 bytes
	if len(b32) > 16 {
		b32 = b32[:16]
	} else if len(b32) < 16 {
		b32 = strings.Repeat("0", 16-len(b32)) + b32
	}
	return fmt.Sprintf("%s%s-%s-%s-%s",
		FingerprintPrefix,
		b32[0:4],
		b32[4:8],
		b32[8:12],
		b32[12:16],
	)
}

// Sign signs a message using the device's private key.
func (d *DeviceIdentity) Sign(message []byte) ([]byte, error) {
	if len(d.PrivateKey) == 0 {
		return nil, errors.New("cannot sign: private key is not present")
	}
	return ed25519.Sign(d.PrivateKey, message), nil
}

// VerifyDeviceSignature verifies a signature against a message and an Ed25519 public key.
func VerifyDeviceSignature(pub ed25519.PublicKey, message, signature []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, message, signature)
}

// PublicKeyHex returns the hex-encoded 32-byte public key.
func (d *DeviceIdentity) PublicKeyHex() string {
	return hex.EncodeToString(d.PublicKey)
}

// ParsePublicKeyHex parses a 32-byte hex-encoded Ed25519 public key.
func ParsePublicKeyHex(hexStr string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(strings.TrimSpace(hexStr))
	if err != nil {
		return nil, fmt.Errorf("invalid hex public key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, ErrInvalidPublicKey
	}
	return ed25519.PublicKey(b), nil
}

// ValidateDeviceID checks whether a device ID string is canonically formed.
func ValidateDeviceID(deviceID string) bool {
	if !strings.HasPrefix(deviceID, DeviceIDPrefix) {
		return false
	}
	hexPart := strings.TrimPrefix(deviceID, DeviceIDPrefix)
	if len(hexPart) != 64 {
		return false
	}
	_, err := hex.DecodeString(hexPart)
	return err == nil
}
