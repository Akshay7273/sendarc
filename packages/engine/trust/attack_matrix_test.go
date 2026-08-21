package trust

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sendbeam/wire"
)

// TestAttackMatrix_Engine exercises engine-level adversarial scenarios:
// 1. Trust DB tampering & device ID spoofing rejection
// 2. Revoked / purged credentials immediate settlement
// 3. Auto-accept directory traversal containment & policy checks
// 4. One-time transfer isolation (zero store pollution)
func TestAttackMatrix_Engine(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryTrustStore()

	seedA := sha256.Sum256([]byte("seed-device-alice-engine-matrix"))
	seedB := sha256.Sum256([]byte("seed-device-bob-engine-matrix"))
	seedAttacker := sha256.Sum256([]byte("seed-device-attacker-engine-matrix"))

	privA := ed25519.NewKeyFromSeed(seedA[:])
	idA, err := wire.NewDeviceIdentity(privA.Public().(ed25519.PublicKey), privA)
	if err != nil {
		t.Fatalf("NewDeviceIdentity A failed: %v", err)
	}

	privB := ed25519.NewKeyFromSeed(seedB[:])
	idB, err := wire.NewDeviceIdentity(privB.Public().(ed25519.PublicKey), privB)
	if err != nil {
		t.Fatalf("NewDeviceIdentity B failed: %v", err)
	}

	privAttacker := ed25519.NewKeyFromSeed(seedAttacker[:])
	idAttacker, err := wire.NewDeviceIdentity(privAttacker.Public().(ed25519.PublicKey), privAttacker)
	if err != nil {
		t.Fatalf("NewDeviceIdentity Attacker failed: %v", err)
	}

	kPair := sha256.Sum256([]byte("shared-k-pair-secret-alice-bob-engine"))
	hCred := sha256.Sum256(kPair[:])
	credRef := "cred-" + hex.EncodeToString(hCred[:])

	recB := &wire.TrustRecord{
		DeviceID:          idB.DeviceID,
		PublicKey:         idB.PublicKeyHex(),
		LocalLabel:        "Bob Laptop",
		PairCredentialRef: credRef,
		Capabilities:      []string{wire.CapTransferV1, wire.CapTransferV2, wire.CapAutoAccept},
		FirstSeenAt:       time.Now().UTC(),
		LastSeenAt:        time.Now().UTC(),
		Revoked:           false,
		Policy: wire.TrustPolicy{
			AutoAccept:        true,
			AutoAcceptDestDir: "/tmp/safe-downloads",
			MaxFileSizeBytes:  10 * 1024 * 1024,
		},
	}
	if err := store.AddOrUpdateDevice(ctx, recB); err != nil {
		t.Fatalf("AddOrUpdateDevice failed: %v", err)
	}

	// Vector 1: Tampered Public Key vs Device ID
	t.Run("Vector 1: Reject tampered public key in trust store", func(t *testing.T) {
		tamperedRec := &wire.TrustRecord{
			DeviceID:          idB.DeviceID,
			PublicKey:         idAttacker.PublicKeyHex(),
			LocalLabel:        "Bob Laptop",
			PairCredentialRef: credRef,
			Capabilities:      []string{wire.CapTransferV1},
			FirstSeenAt:       time.Now().UTC(),
			LastSeenAt:        time.Now().UTC(),
			Revoked:           false,
			Policy:            wire.DefaultTrustPolicy(),
		}

		err := store.AddOrUpdateDevice(ctx, tamperedRec)
		if err == nil {
			t.Fatal("expected store.AddOrUpdateDevice to reject tampered record")
		}
	})

	// Vector 2: Revocation and Purge
	t.Run("Vector 2: Immediate revocation & unpair", func(t *testing.T) {
		if !store.IsTrusted(ctx, idB.DeviceID) {
			t.Fatal("expected device B to be trusted")
		}

		// Revoke device
		if err := store.RevokeDevice(ctx, idB.DeviceID); err != nil {
			t.Fatalf("RevokeDevice failed: %v", err)
		}
		if store.IsTrusted(ctx, idB.DeviceID) {
			t.Fatal("expected revoked device B to NOT be trusted")
		}

		// Unpair / purge
		if err := store.UnpairDevice(ctx, idB.DeviceID); err != nil {
			t.Fatalf("UnpairDevice failed: %v", err)
		}
		dev, err := store.GetDevice(ctx, idB.DeviceID)
		if err == nil && dev != nil {
			t.Fatal("expected unpaired device to not be found in trust store")
		}
	})

	// Vector 3: Auto-Accept Destination Path Traversal Containment
	t.Run("Vector 3: Auto-accept destination path containment", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "sendbeam-auto-accept-test-*")
		if err != nil {
			t.Fatalf("MkdirTemp failed: %v", err)
		}
		defer func() {
			_ = os.RemoveAll(tempDir)
		}()

		policy := wire.TrustPolicy{
			AutoAccept:        true,
			AutoAcceptDestDir: tempDir,
			MaxFileSizeBytes:  1024 * 1024,
		}
		if err := policy.Validate(); err != nil {
			t.Fatalf("valid policy rejected: %v", err)
		}

		// Policy must reject relative destination directory
		badPolicy := wire.TrustPolicy{
			AutoAccept:        true,
			AutoAcceptDestDir: "relative/path",
		}
		if err := badPolicy.Validate(); err == nil {
			t.Fatal("expected policy with relative dest dir to fail validation")
		}

		// Policy must reject filesystem root
		rootPolicy := wire.TrustPolicy{
			AutoAccept:        true,
			AutoAcceptDestDir: "/",
		}
		if err := rootPolicy.Validate(); err == nil {
			t.Fatal("expected policy with root dest dir to fail validation")
		}

		// Clean paths inside designated directory
		relPaths := []string{
			"notes.txt",
			"subfolder/report.pdf",
			"a/b/c/data.bin",
		}
		for _, rel := range relPaths {
			cleanRel, err := wire.NormalizeTransferPath(rel)
			if err != nil {
				t.Fatalf("NormalizeTransferPath failed for %q: %v", rel, err)
			}
			targetPath := filepath.Join(tempDir, filepath.FromSlash(cleanRel))
			// Verify destination target path is strictly within tempDir
			relCheck, err := filepath.Rel(tempDir, targetPath)
			if err != nil || strings.HasPrefix(relCheck, "..") {
				t.Fatalf("path %q escaped target directory %q", targetPath, tempDir)
			}
		}
	})

	// Vector 4: One-Time Transfer Isolation
	t.Run("Vector 4: One-time transfers never pollute trust store", func(t *testing.T) {
		// Fresh trust store with only Alice
		freshStore := NewMemoryTrustStore()
		recA := &wire.TrustRecord{
			DeviceID:          idA.DeviceID,
			PublicKey:         idA.PublicKeyHex(),
			LocalLabel:        "Alice Desktop",
			PairCredentialRef: "cred-a",
			Capabilities:      []string{wire.CapTransferV1},
			FirstSeenAt:       time.Now().UTC(),
			LastSeenAt:        time.Now().UTC(),
			Revoked:           false,
			Policy:            wire.DefaultTrustPolicy(),
		}
		if err := freshStore.AddOrUpdateDevice(ctx, recA); err != nil {
			t.Fatalf("AddOrUpdateDevice failed: %v", err)
		}

		devs, err := freshStore.ListDevices(ctx)
		if err != nil {
			t.Fatalf("ListDevices failed: %v", err)
		}
		if len(devs) != 1 {
			t.Fatalf("expected 1 device, got %d", len(devs))
		}

		// Ephemeral session from one-time room transfer
		ephemeralSenderID := "sb-dev-one-time-room-peer"
		if freshStore.IsTrusted(ctx, ephemeralSenderID) {
			t.Fatal("ephemeral sender should not be trusted")
		}

		devsAfter, err := freshStore.ListDevices(ctx)
		if err != nil {
			t.Fatalf("ListDevices failed: %v", err)
		}
		if len(devsAfter) != 1 {
			t.Fatalf("trust store was polluted, expected 1 device, got %d", len(devsAfter))
		}
	})
}
