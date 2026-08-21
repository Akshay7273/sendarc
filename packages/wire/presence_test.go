package wire

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type PresenceTestVector struct {
	Name            string   `json:"name"`
	KPairHex        string   `json:"k_pair_hex"`
	Timestamp       string   `json:"timestamp"`
	EpochIndex      int64    `json:"epoch_index"`
	RendezvousHandle string  `json:"rendezvous_handle"`
	SkewHandles     []string `json:"skew_handles"`
	PresenceNonceHex string  `json:"presence_nonce_hex"`
	PresenceProofHex string  `json:"presence_proof_hex"`
	BeaconNonceHex  string   `json:"beacon_nonce_hex"`
	BeaconTagHex    string   `json:"beacon_tag_hex"`
}

func TestPresenceAndLanBeaconVectors(t *testing.T) {
	kPair := sha256.Sum256([]byte("shared-k-pair-presence-vectors-v15"))
	fixedTime, _ := time.Parse(time.RFC3339, "2026-08-21T12:00:00Z")
	window := 15 * time.Minute
	epochIndex := fixedTime.Unix() / int64(window.Seconds())

	handle := DeriveRendezvousHandle(kPair[:], epochIndex)
	skewHandles := DeriveRendezvousHandlesWithSkew(kPair[:], fixedTime, window)

	presenceNonce := sha256.Sum256([]byte("fixed-presence-nonce-1"))
	proof := DerivePresenceProof(kPair[:], handle, presenceNonce[:])

	if !VerifyPresenceProof(kPair[:], handle, presenceNonce[:], proof) {
		t.Fatalf("VerifyPresenceProof failed")
	}

	beaconNonce := sha256.Sum256([]byte("fixed-beacon-nonce-1"))
	beaconTag := DeriveLanBeaconTag(kPair[:], beaconNonce[:16], epochIndex)

	vector := PresenceTestVector{
		Name:             "alice_bob_presence_and_beacon",
		KPairHex:         hex.EncodeToString(kPair[:]),
		Timestamp:        fixedTime.Format(time.RFC3339),
		EpochIndex:       epochIndex,
		RendezvousHandle: handle,
		SkewHandles:      skewHandles,
		PresenceNonceHex: hex.EncodeToString(presenceNonce[:]),
		PresenceProofHex: proof,
		BeaconNonceHex:   hex.EncodeToString(beaconNonce[:16]),
		BeaconTagHex:     hex.EncodeToString(beaconTag),
	}

	vecData, err := json.MarshalIndent([]PresenceTestVector{vector}, "", "  ")
	if err != nil {
		t.Fatalf("marshal test vector: %v", err)
	}

	targetPath := filepath.Join("testdata", "presence-vectors.json")
	if err := os.WriteFile(targetPath, vecData, 0644); err != nil {
		t.Fatalf("write presence-vectors.json: %v", err)
	}
}

func TestPresenceHandleSkewMatching(t *testing.T) {
	kPair := sha256.Sum256([]byte("shared-k-pair-presence-skew"))
	now := time.Now().UTC()
	window := 15 * time.Minute

	handleNow := DeriveRendezvousHandleForTime(kPair[:], now, window)
	if !MatchRendezvousHandle(kPair[:], handleNow, now, window) {
		t.Errorf("handleNow did not match current time")
	}

	// Boundary test: time 10 minutes earlier (within same or adjacent epoch)
	timePast := now.Add(-10 * time.Minute)
	if !MatchRendezvousHandle(kPair[:], handleNow, timePast, window) {
		t.Errorf("handleNow should match within 10 min window")
	}

	// Wrong handle should not match
	wrongKPair := sha256.Sum256([]byte("wrong-k-pair"))
	wrongHandle := DeriveRendezvousHandleForTime(wrongKPair[:], now, window)
	if MatchRendezvousHandle(kPair[:], wrongHandle, now, window) {
		t.Errorf("wrongHandle should not match")
	}
}
