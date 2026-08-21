package wire

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strconv"
	"time"
)

// Remote presence and opaque rendezvous handle constants (V15-PR04).
const (
	DomainRendezvousHandle = "sendbeam/2 rendezvous-handle:"
	DomainPresenceProof    = "sendbeam/2 presence-proof:"

	DefaultRendezvousEpochWindow = 15 * time.Minute
	RendezvousHandleHexLength    = 64 // 32 bytes hex encoded
)

var (
	// ErrInvalidHandle indicates a malformed rendezvous handle.
	ErrInvalidHandle = errors.New("invalid rendezvous handle")

	// ErrInvalidProof indicates an invalid presence proof tag.
	ErrInvalidProof = errors.New("invalid presence proof")
)

// DeriveRendezvousHandle derives a 32-byte opaque rendezvous handle for a specific epoch index.
func DeriveRendezvousHandle(kPair []byte, epochIndex int64) string {
	epochStr := strconv.FormatInt(epochIndex, 10)
	mac := hmac.New(sha256.New, kPair)
	mac.Write([]byte(DomainRendezvousHandle))
	mac.Write([]byte(epochStr))
	return hex.EncodeToString(mac.Sum(nil))
}

// DeriveRendezvousHandleForTime derives the opaque handle for a given timestamp and window.
func DeriveRendezvousHandleForTime(kPair []byte, t time.Time, window time.Duration) string {
	if window <= 0 {
		window = DefaultRendezvousEpochWindow
	}
	epochIndex := t.UTC().Unix() / int64(window.Seconds())
	return DeriveRendezvousHandle(kPair, epochIndex)
}

// DeriveRendezvousHandlesWithSkew derives current, previous, and next epoch handles to tolerate clock drift.
func DeriveRendezvousHandlesWithSkew(kPair []byte, t time.Time, window time.Duration) []string {
	if window <= 0 {
		window = DefaultRendezvousEpochWindow
	}
	epochIndex := t.UTC().Unix() / int64(window.Seconds())
	return []string{
		DeriveRendezvousHandle(kPair, epochIndex-1),
		DeriveRendezvousHandle(kPair, epochIndex),
		DeriveRendezvousHandle(kPair, epochIndex+1),
	}
}

// DerivePresenceProof computes an HMAC proof of possession for registering or polling a handle.
func DerivePresenceProof(kPair []byte, handle string, nonce []byte) string {
	mac := hmac.New(sha256.New, kPair)
	mac.Write([]byte(DomainPresenceProof))
	mac.Write([]byte(handle))
	mac.Write(nonce)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyPresenceProof validates an HMAC proof of possession in constant time.
func VerifyPresenceProof(kPair []byte, handle string, nonce []byte, proofHex string) bool {
	proofBytes, err := hex.DecodeString(proofHex)
	if err != nil || len(proofBytes) != sha256.Size {
		return false
	}
	expectedHex := DerivePresenceProof(kPair, handle, nonce)
	expectedBytes, _ := hex.DecodeString(expectedHex)
	return subtle.ConstantTimeCompare(proofBytes, expectedBytes) == 1
}

// ValidateRendezvousHandle checks whether a handle string is a valid 64-character lowercase hex string.
func ValidateRendezvousHandle(handle string) bool {
	if len(handle) != RendezvousHandleHexLength {
		return false
	}
	for i := 0; i < len(handle); i++ {
		c := handle[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// MatchRendezvousHandle checks if a given handle matches any candidate epoch for k_pair.
func MatchRendezvousHandle(kPair []byte, handle string, t time.Time, window time.Duration) bool {
	if !ValidateRendezvousHandle(handle) {
		return false
	}
	candidates := DeriveRendezvousHandlesWithSkew(kPair, t, window)
	for _, cand := range candidates {
		if subtle.ConstantTimeCompare([]byte(cand), []byte(handle)) == 1 {
			return true
		}
	}
	return false
}
