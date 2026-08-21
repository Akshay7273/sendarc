package trust

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sendbeam/wire"
)

func TestMemoryTrustStoreOperations(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryTrustStore()

	id, err := wire.GenerateDeviceIdentity()
	if err != nil {
		t.Fatalf("GenerateDeviceIdentity: %v", err)
	}

	rec := &wire.TrustRecord{
		DeviceID:          id.DeviceID,
		PublicKey:         id.PublicKeyHex(),
		LocalLabel:        "Linux Laptop",
		PairCredentialRef: "cred-111",
		Capabilities:      []string{wire.CapTransferV1, wire.CapTransferV2, wire.CapAutoAccept},
		FirstSeenAt:       time.Now().UTC(),
		LastSeenAt:        time.Now().UTC(),
		Revoked:           false,
		Policy: wire.TrustPolicy{
			AutoAccept:        true,
			AutoAcceptDestDir: "/home/user/Downloads",
			MaxFileSizeBytes:  1024 * 1024,
		},
	}

	if store.IsTrusted(ctx, id.DeviceID) {
		t.Errorf("expected device to not be trusted before adding")
	}

	if err := store.AddOrUpdateDevice(ctx, rec); err != nil {
		t.Fatalf("AddOrUpdateDevice: %v", err)
	}

	if !store.IsTrusted(ctx, id.DeviceID) {
		t.Errorf("expected device to be trusted after adding")
	}

	fetched, err := store.GetDevice(ctx, id.DeviceID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if fetched.LocalLabel != "Linux Laptop" {
		t.Errorf("label mismatch: got %s", fetched.LocalLabel)
	}

	list, err := store.ListDevices(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListDevices: %v (len %d)", err, len(list))
	}

	// Update policy
	newPolicy := wire.TrustPolicy{
		AutoAccept:        false,
		AutoAcceptDestDir: "",
		MaxFileSizeBytes:  500,
	}
	if err := store.UpdatePolicy(ctx, id.DeviceID, newPolicy); err != nil {
		t.Fatalf("UpdatePolicy: %v", err)
	}
	fetched, _ = store.GetDevice(ctx, id.DeviceID)
	if fetched.Policy.AutoAccept {
		t.Errorf("expected AutoAccept to be false")
	}

	// Update last seen
	seenTime := time.Now().UTC().Add(time.Hour)
	if err := store.UpdateLastSeen(ctx, id.DeviceID, seenTime); err != nil {
		t.Fatalf("UpdateLastSeen: %v", err)
	}

	// Revoke device
	if err := store.RevokeDevice(ctx, id.DeviceID); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	if store.IsTrusted(ctx, id.DeviceID) {
		t.Errorf("revoked device should not be trusted")
	}
	fetched, _ = store.GetDevice(ctx, id.DeviceID)
	if !fetched.Revoked || fetched.RevokedAt == nil {
		t.Errorf("expected Revoked=true and RevokedAt set")
	}

	// Unpair device
	if err := store.UnpairDevice(ctx, id.DeviceID); err != nil {
		t.Fatalf("UnpairDevice: %v", err)
	}
	if _, err := store.GetDevice(ctx, id.DeviceID); err == nil {
		t.Errorf("expected error getting unpaired device")
	}
}

func TestFileTrustStorePersistence(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "trust.json")

	store, err := NewFileTrustStore(filePath)
	if err != nil {
		t.Fatalf("NewFileTrustStore: %v", err)
	}

	id1, _ := wire.GenerateDeviceIdentity()
	rec1 := &wire.TrustRecord{
		DeviceID:          id1.DeviceID,
		PublicKey:         id1.PublicKeyHex(),
		LocalLabel:        "Device 1",
		PairCredentialRef: "cred-1",
		Capabilities:      []string{wire.CapTransferV1},
		FirstSeenAt:       time.Now().UTC(),
		LastSeenAt:        time.Now().UTC(),
		Policy: wire.TrustPolicy{
			AutoAccept: false,
		},
	}

	if err := store.AddOrUpdateDevice(ctx, rec1); err != nil {
		t.Fatalf("AddOrUpdateDevice: %v", err)
	}

	// Verify file was written with 0600 permissions
	fi, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("stat trust file: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("expected 0600 permissions, got %v", fi.Mode().Perm())
	}

	// Reopen file store from disk
	reloadedStore, err := NewFileTrustStore(filePath)
	if err != nil {
		t.Fatalf("reopen NewFileTrustStore: %v", err)
	}

	if !reloadedStore.IsTrusted(ctx, id1.DeviceID) {
		t.Errorf("expected reloaded store to trust device 1")
	}
	fetched, err := reloadedStore.GetDevice(ctx, id1.DeviceID)
	if err != nil || fetched.LocalLabel != "Device 1" {
		t.Fatalf("reloaded GetDevice failed: %v", err)
	}

	// Add second device
	id2, _ := wire.GenerateDeviceIdentity()
	rec2 := &wire.TrustRecord{
		DeviceID:          id2.DeviceID,
		PublicKey:         id2.PublicKeyHex(),
		LocalLabel:        "Device 2",
		PairCredentialRef: "cred-2",
		Capabilities:      []string{wire.CapTransferV2},
		FirstSeenAt:       time.Now().UTC(),
		LastSeenAt:        time.Now().UTC(),
		Policy: wire.TrustPolicy{
			AutoAccept: false,
		},
	}
	if err := reloadedStore.AddOrUpdateDevice(ctx, rec2); err != nil {
		t.Fatalf("Add device 2: %v", err)
	}

	list, _ := reloadedStore.ListDevices(ctx)
	if len(list) != 2 {
		t.Errorf("expected 2 devices, got %d", len(list))
	}
}
