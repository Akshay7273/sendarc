package rendezvous

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

func TestPresenceCoordinator(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	store, _ := trust.NewFileTrustStore(filepath.Join(tmpDir, "presence-trust.json"))
	resolver := trust.NewMemorySecretResolver()

	kPairAlice := sha256.Sum256([]byte("kpair-alice-presence"))
	kPairBob := sha256.Sum256([]byte("kpair-bob-presence"))

	pubA, _, _ := ed25519.GenerateKey(nil)
	pubB, _, _ := ed25519.GenerateKey(nil)

	devAlice := wire.DeriveDeviceID(pubA)
	devBob := wire.DeriveDeviceID(pubB)

	now := time.Now().UTC()

	_ = store.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          devAlice,
		PublicKey:         hex.EncodeToString(pubA),
		LocalLabel:        "Alice",
		PairCredentialRef: "cred-alice",
		FirstSeenAt:       now,
		LastSeenAt:        now,
		Policy:            wire.DefaultTrustPolicy(),
	})
	resolver.SetSecret(devAlice, kPairAlice[:])

	_ = store.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          devBob,
		PublicKey:         hex.EncodeToString(pubB),
		LocalLabel:        "Bob",
		PairCredentialRef: "cred-bob",
		FirstSeenAt:       now,
		LastSeenAt:        now,
		Revoked:           true, // Revoked
		Policy:            wire.DefaultTrustPolicy(),
	})
	resolver.SetSecret(devBob, kPairBob[:])

	coord := NewPresenceCoordinator(store, resolver, 15*time.Minute)

	handles, err := coord.GetActiveHandles(ctx, now)
	if err != nil {
		t.Fatalf("GetActiveHandles: %v", err)
	}

	if _, ok := handles[devAlice]; !ok {
		t.Errorf("Alice handles missing")
	}
	if _, ok := handles[devBob]; ok {
		t.Errorf("Revoked Bob should not have active handles")
	}

	// Inbound presence verification
	handleAlice := wire.DeriveRendezvousHandleForTime(kPairAlice[:], now, 15*time.Minute)
	nonce := sha256.Sum256([]byte("inbound-nonce-1"))
	proofAlice := wire.DerivePresenceProof(kPairAlice[:], handleAlice, nonce[:])

	matchedID, valid := coord.MatchInboundPresence(ctx, handleAlice, nonce[:], proofAlice, now)
	if !valid || matchedID != devAlice {
		t.Errorf("expected match %s, got %v (valid: %v)", devAlice, matchedID, valid)
	}

	// Tampered proof
	_, validTampered := coord.MatchInboundPresence(ctx, handleAlice, nonce[:], hex.EncodeToString(make([]byte, 32)), now)
	if validTampered {
		t.Errorf("tampered proof should not be valid")
	}
}
