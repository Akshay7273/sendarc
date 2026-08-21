package wire

import (
	"crypto/sha256"
	"testing"
	"time"
)

func TestLanBeaconEncodeDecode(t *testing.T) {
	kPair1 := sha256.Sum256([]byte("kpair-device-1"))
	kPair2 := sha256.Sum256([]byte("kpair-device-2"))

	now := time.Now().UTC().Truncate(time.Second)
	beacon, err := NewLanBeacon(53317, [][]byte{kPair1[:], kPair2[:]}, now, 15*time.Minute)
	if err != nil {
		t.Fatalf("NewLanBeacon error: %v", err)
	}

	data, err := beacon.Encode()
	if err != nil {
		t.Fatalf("beacon.Encode error: %v", err)
	}

	decoded, err := DecodeLanBeacon(data)
	if err != nil {
		t.Fatalf("DecodeLanBeacon error: %v", err)
	}

	if decoded.Port != 53317 {
		t.Errorf("port mismatch: got %d, want 53317", decoded.Port)
	}
	if !decoded.Timestamp.Equal(now) {
		t.Errorf("timestamp mismatch: got %v, want %v", decoded.Timestamp, now)
	}
	if len(decoded.Tags) != 2 {
		t.Fatalf("tag count mismatch: got %d, want 2", len(decoded.Tags))
	}
}

func TestLanBeaconMatching(t *testing.T) {
	kPairAlice := sha256.Sum256([]byte("kpair-alice-tag"))
	kPairBob := sha256.Sum256([]byte("kpair-bob-tag"))
	kPairCharlie := sha256.Sum256([]byte("kpair-charlie-tag"))

	now := time.Now().UTC()
	// Transmitter is Bob advertising to Alice and Charlie
	beacon, err := NewLanBeacon(4000, [][]byte{kPairAlice[:], kPairCharlie[:]}, now, 15*time.Minute)
	if err != nil {
		t.Fatalf("NewLanBeacon error: %v", err)
	}

	// Alice's trust store has Bob and Charlie
	localPairs := map[string][]byte{
		"sb-dev-bob":     kPairAlice[:],   // shared secret with Bob
		"sb-dev-stranger": kPairBob[:],     // stranger
	}

	matched := MatchLanBeacon(beacon, localPairs, now, 15*time.Minute)
	if len(matched) != 1 || matched[0] != "sb-dev-bob" {
		t.Errorf("expected matched [sb-dev-bob], got %v", matched)
	}

	// Stale beacon (> 30 min) should NOT match
	oldTime := now.Add(45 * time.Minute)
	matchedStale := MatchLanBeacon(beacon, localPairs, oldTime, 15*time.Minute)
	if len(matchedStale) != 0 {
		t.Errorf("stale beacon should not match, got %v", matchedStale)
	}
}
