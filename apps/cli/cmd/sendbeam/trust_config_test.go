package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

func TestFileSecretResolver(t *testing.T) {
	tmpDir := t.TempDir()
	secretPath := filepath.Join(tmpDir, "secrets.json")

	resolver, err := NewFileSecretResolver(secretPath)
	if err != nil {
		t.Fatalf("NewFileSecretResolver: %v", err)
	}

	secretAlice := []byte("01234567890123456789012345678901")
	if err := resolver.SetSecret("dev-alice", secretAlice); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}

	got, err := resolver.ResolvePairSecret(context.Background(), "dev-alice", "")
	if err != nil {
		t.Fatalf("ResolvePairSecret: %v", err)
	}
	if string(got) != string(secretAlice) {
		t.Errorf("secret mismatch: got %v, want %v", got, secretAlice)
	}

	// Reopen from disk
	resolver2, err := NewFileSecretResolver(secretPath)
	if err != nil {
		t.Fatalf("NewFileSecretResolver reopen: %v", err)
	}
	got2, err := resolver2.ResolvePairSecret(context.Background(), "dev-alice", "")
	if err != nil || string(got2) != string(secretAlice) {
		t.Errorf("reopened secret mismatch: %v (err: %v)", got2, err)
	}

	// Delete
	if err := resolver2.DeleteSecret("dev-alice"); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	if _, err := resolver2.ResolvePairSecret(context.Background(), "dev-alice", ""); err == nil {
		t.Errorf("expected error after delete")
	}
}

func TestResolveDevice(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	store, _ := trust.NewFileTrustStore(filepath.Join(tmpDir, "trust.json"))

	pubA, _, _ := ed25519.GenerateKey(nil)
	devAlice := wire.DeriveDeviceID(pubA)

	pubB, _, _ := ed25519.GenerateKey(nil)
	devBob := wire.DeriveDeviceID(pubB)

	now := time.Now().UTC()

	_ = store.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          devAlice,
		PublicKey:         hex.EncodeToString(pubA),
		LocalLabel:        "Alice Laptop",
		PairCredentialRef: "cred-alice",
		FirstSeenAt:       now,
		LastSeenAt:        now,
		Policy:            wire.DefaultTrustPolicy(),
	})

	_ = store.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          devBob,
		PublicKey:         hex.EncodeToString(pubB),
		LocalLabel:        "Bob Phone",
		PairCredentialRef: "cred-bob",
		FirstSeenAt:       now,
		LastSeenAt:        now,
		Policy:            wire.DefaultTrustPolicy(),
	})

	// Match by exact DeviceID
	rec, err := ResolveDevice(ctx, store, devAlice)
	if err != nil || rec.LocalLabel != "Alice Laptop" {
		t.Errorf("match by DeviceID failed: %v", err)
	}

	// Match by @DeviceID
	rec, err = ResolveDevice(ctx, store, "@"+devAlice)
	if err != nil || rec.LocalLabel != "Alice Laptop" {
		t.Errorf("match by @DeviceID failed: %v", err)
	}

	// Match by Label
	rec, err = ResolveDevice(ctx, store, "Bob Phone")
	if err != nil || rec.DeviceID != devBob {
		t.Errorf("match by Label failed: %v", err)
	}

	// Match by @Label
	rec, err = ResolveDevice(ctx, store, "@bob phone")
	if err != nil || rec.DeviceID != devBob {
		t.Errorf("match by @Label failed: %v", err)
	}

	// Match by Fingerprint
	fpAlice := wire.DeriveFingerprint(pubA)
	rec, err = ResolveDevice(ctx, store, fpAlice)
	if err != nil || rec.DeviceID != devAlice {
		t.Errorf("match by Fingerprint failed: %v", err)
	}

	// Not found
	_, err = ResolveDevice(ctx, store, "NonExistent")
	if err == nil {
		t.Errorf("expected error for non-existent device")
	}
}
