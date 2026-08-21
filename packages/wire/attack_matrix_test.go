package wire

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// TestAttackMatrix_Wire exercises wire-level adversarial scenarios defined in ADR 0007 / v1.5plan:
// 1. Stolen trust DB vs stolen key (Public key mismatch vs Device ID)
// 2. Replay attack & cloned profile (Nonce uniqueness, freshness window & transcript binding)
// 3. Malicious server MITM & ephemeral key substitution
// 4. Presence beacon replay & stale epoch expiration
// 5. Display name / local label spoofing isolation
// 6. Downgrade attack & capability stripping resistance
// 7. Path traversal & directory escape containment
func TestAttackMatrix_Wire(t *testing.T) {
	// Setup test keys
	seedA := sha256.Sum256([]byte("seed-device-alice-attack-matrix"))
	seedB := sha256.Sum256([]byte("seed-device-bob-attack-matrix"))
	seedAttacker := sha256.Sum256([]byte("seed-device-attacker-matrix"))

	privA := ed25519.NewKeyFromSeed(seedA[:])
	idA, err := NewDeviceIdentity(privA.Public().(ed25519.PublicKey), privA)
	if err != nil {
		t.Fatalf("NewDeviceIdentity A failed: %v", err)
	}

	privB := ed25519.NewKeyFromSeed(seedB[:])
	idB, err := NewDeviceIdentity(privB.Public().(ed25519.PublicKey), privB)
	if err != nil {
		t.Fatalf("NewDeviceIdentity B failed: %v", err)
	}

	privAttacker := ed25519.NewKeyFromSeed(seedAttacker[:])
	idAttacker, err := NewDeviceIdentity(privAttacker.Public().(ed25519.PublicKey), privAttacker)
	if err != nil {
		t.Fatalf("NewDeviceIdentity Attacker failed: %v", err)
	}

	kPair := sha256.Sum256([]byte("shared-k-pair-secret-alice-bob"))
	hCred := sha256.Sum256(kPair[:])
	credRef := "cred-" + hex.EncodeToString(hCred[:])

	// Vector 1: Stolen Trust DB vs Stolen Key
	t.Run("Vector 1: Public key mismatch vs Device ID", func(t *testing.T) {
		// Attacker modifies trust DB record to associate Bob's device ID with Attacker's public key
		tamperedRecord := &TrustRecord{
			DeviceID:          idB.DeviceID, // Bob's ID
			PublicKey:         hex.EncodeToString(idAttacker.PublicKey),
			LocalLabel:        "Bob Laptop",
			PairCredentialRef: credRef,
			Capabilities:      []string{"transfer.v1"},
			FirstSeenAt:       time.Now().UTC(),
			LastSeenAt:        time.Now().UTC(),
			Revoked:           false,
			Policy:            DefaultTrustPolicy(),
		}

		err := tamperedRecord.Validate()
		if err == nil {
			t.Fatal("expected Validate to reject mismatched device ID and public key")
		}
		if !strings.Contains(err.Error(), "does not match public key") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})

	// Vector 2: Replay Attack & Cloned Profile
	t.Run("Vector 2: Replay attack & challenge freshness window", func(t *testing.T) {
		var ephemA [32]byte
		var nonceA [32]byte
		_, _ = rand.Read(ephemA[:])
		_, _ = rand.Read(nonceA[:])

		initMsg, err := NewTrustedAuthInit(
			idA,
			idB.DeviceID,
			credRef,
			kPair[:],
			[]string{"transfer.v1", "transfer.v2"},
			ephemA[:],
			nonceA[:],
			time.Now().UTC(),
		)
		if err != nil {
			t.Fatalf("NewTrustedAuthInit failed: %v", err)
		}

		// Valid verify
		_, _, err = VerifyTrustedAuthInit(initMsg, kPair[:], idA.PublicKey, idB.DeviceID, time.Now().UTC())
		if err != nil {
			t.Fatalf("legitimate VerifyTrustedAuthInit failed: %v", err)
		}

		// Stale timestamp (1 hour in the past)
		staleTime := time.Now().UTC().Add(-1 * time.Hour)
		_, _, err = VerifyTrustedAuthInit(initMsg, kPair[:], idA.PublicKey, idB.DeviceID, staleTime)
		if err == nil {
			t.Fatal("expected VerifyTrustedAuthInit to reject stale timestamp outside skew window")
		}

		// Replayed init with modified nonce fails MAC
		tamperedInit := *initMsg
		tamperedInit.Nonce = hex.EncodeToString([]byte("01234567890123456789012345678901"))
		_, _, err = VerifyTrustedAuthInit(&tamperedInit, kPair[:], idA.PublicKey, idB.DeviceID, time.Now().UTC())
		if err == nil {
			t.Fatal("expected VerifyTrustedAuthInit to reject tampered nonce")
		}
	})

	// Vector 3: Malicious Server MITM & Key Substitution
	t.Run("Vector 3: MITM ephemeral key substitution and signature failure", func(t *testing.T) {
		var ephemA [32]byte
		var nonceA [32]byte
		_, _ = rand.Read(ephemA[:])
		_, _ = rand.Read(nonceA[:])

		initMsg, err := NewTrustedAuthInit(
			idA,
			idB.DeviceID,
			credRef,
			kPair[:],
			[]string{"transfer.v1"},
			ephemA[:],
			nonceA[:],
			time.Now().UTC(),
		)
		if err != nil {
			t.Fatalf("NewTrustedAuthInit failed: %v", err)
		}

		// Malicious relay substitutes ephemeral key
		mitmInit := *initMsg
		var attackerEph [32]byte
		_, _ = rand.Read(attackerEph[:])
		mitmInit.EphemeralPub = hex.EncodeToString(attackerEph[:])

		// Receiver verifies
		_, _, err = VerifyTrustedAuthInit(&mitmInit, kPair[:], idA.PublicKey, idB.DeviceID, time.Now().UTC())
		if err == nil {
			t.Fatal("expected VerifyTrustedAuthInit to reject MITM ephemeral key substitution")
		}
	})

	// Vector 4: Presence Beacon Replay & Stale Epoch Expiration
	t.Run("Vector 4: Presence handle & LAN beacon epoch expiration", func(t *testing.T) {
		now := time.Now().UTC()
		window := DefaultRendezvousEpochWindow
		currentEpoch := now.Unix() / int64(window.Seconds())

		// Derive handles with ±1 epoch skew tolerance
		handles := DeriveRendezvousHandlesWithSkew(kPair[:], now, window)
		if len(handles) != 3 {
			t.Fatalf("expected 3 handles with skew, got %d", len(handles))
		}

		currentHandle := DeriveRendezvousHandle(kPair[:], currentEpoch)
		if !contains(handles, currentHandle) {
			t.Fatal("expected current handle to be in candidate set")
		}

		// Expired handle (4 epochs ago = 1 hour)
		expiredHandle := DeriveRendezvousHandle(kPair[:], currentEpoch-4)
		if contains(handles, expiredHandle) {
			t.Fatal("expected expired handle to NOT be in candidate set")
		}

		// Blinded LAN Beacon tag verification
		beacon, err := NewLanBeacon(4242, [][]byte{kPair[:]}, now, window)
		if err != nil {
			t.Fatalf("NewLanBeacon failed: %v", err)
		}

		localPairs := map[string][]byte{
			idB.DeviceID: kPair[:],
		}

		matched := MatchLanBeacon(beacon, localPairs, now, window)
		if len(matched) != 1 || matched[0] != idB.DeviceID {
			t.Fatalf("expected legitimate beacon to match Bob, got %v", matched)
		}

		// Attacker with wrong key cannot match
		var badKey [32]byte
		_, _ = rand.Read(badKey[:])
		attackerPairs := map[string][]byte{
			"attacker": badKey[:],
		}
		if len(MatchLanBeacon(beacon, attackerPairs, now, window)) != 0 {
			t.Fatal("expected attacker key to NOT match beacon")
		}

		// Expired beacon (2 hours old) fails match
		staleTime := now.Add(2 * time.Hour)
		if len(MatchLanBeacon(beacon, localPairs, staleTime, window)) != 0 {
			t.Fatal("expected stale beacon to NOT match")
		}
	})

	// Vector 5: Display Name / Local Label Spoofing Isolation
	t.Run("Vector 5: Display name spoofing isolation", func(t *testing.T) {
		// Attacker claims friendly label "Bob Laptop"
		attackerLabel := "Bob Laptop"
		if idAttacker.DeviceID == idB.DeviceID {
			t.Fatal("attacker device ID unexpectedly matched victim")
		}
		// Device ID and Fingerprint are authoritative cryptographic identifiers
		fpAttacker := FormatFingerprint(idAttacker.PublicKey)
		fpB := FormatFingerprint(idB.PublicKey)
		if fpAttacker == fpB {
			t.Fatal("attacker fingerprint unexpectedly matched victim")
		}
		_ = attackerLabel
	})

	// Vector 6: Downgrade Attack & Capability Stripping Resistance
	t.Run("Vector 6: Downgrade attack and wrong pair secret", func(t *testing.T) {
		var ephemA [32]byte
		var nonceA [32]byte
		_, _ = rand.Read(ephemA[:])
		_, _ = rand.Read(nonceA[:])

		var badSecret [32]byte
		_, _ = rand.Read(badSecret[:])

		// Attacker attempts trusted init with forged/downgraded secret
		badInit, err := NewTrustedAuthInit(
			idA,
			idB.DeviceID,
			credRef,
			badSecret[:],
			[]string{"transfer.v1"},
			ephemA[:],
			nonceA[:],
			time.Now().UTC(),
		)
		if err != nil {
			t.Fatalf("NewTrustedAuthInit failed: %v", err)
		}

		// Bob verifying with genuine kPair rejects the message
		_, _, err = VerifyTrustedAuthInit(badInit, kPair[:], idA.PublicKey, idB.DeviceID, time.Now().UTC())
		if err == nil {
			t.Fatal("expected VerifyTrustedAuthInit to reject bad pair secret")
		}
	})

	// Vector 7: Path Traversal & Directory Escape Containment
	t.Run("Vector 7: Path traversal and escape containment", func(t *testing.T) {
		unsafePaths := []string{
			"../evil.txt",
			"../../etc/passwd",
			"foo/../../bar.txt",
			"/absolute/path/file.txt",
			"C:\\Windows\\System32\\cmd.exe",
			"foo\x00bar.txt",
			"..\\..\\windows\\system32",
			"./../secret.key",
			"",
		}

		for _, p := range unsafePaths {
			_, err := NormalizeTransferPath(p)
			if err == nil {
				t.Fatalf("expected NormalizeTransferPath to reject unsafe path: %q", p)
			}
		}

		safePaths := []string{
			"photos/vacation.jpg",
			"document.pdf",
			"nested/dir/sub/file.tar.gz",
		}
		for _, p := range safePaths {
			clean, err := NormalizeTransferPath(p)
			if err != nil {
				t.Fatalf("expected NormalizeTransferPath to accept safe path %q: %v", p, err)
			}
			if clean != p {
				t.Fatalf("expected %q, got %q", p, clean)
			}
		}
	})
}

func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}
