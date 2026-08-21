package engine

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/sendbeam/wire"
)

func TestDeviceService_LifecycleAndPolicy(t *testing.T) {
	tmpDir := t.TempDir()

	var emittedEvent string
	var emittedData any
	emit := func(name string, data any) {
		emittedEvent = name
		emittedData = data
	}
	_ = emittedData

	svc, err := NewDeviceService(emit, tmpDir)
	if err != nil {
		t.Fatalf("NewDeviceService failed: %v", err)
	}
	defer svc.Close()

	// Initial list should be empty
	devs, err := svc.ListTrustedDevices()
	if err != nil {
		t.Fatalf("ListTrustedDevices error: %v", err)
	}
	if len(devs) != 0 {
		t.Fatalf("expected 0 devices, got %d", len(devs))
	}

	// Manually inject a trusted peer record to verify views & honest status
	pubA, _, _ := ed25519.GenerateKey(rand.Reader)
	devID := wire.DeriveDeviceID(pubA)
	pubHex := hex.EncodeToString(pubA)
	now := time.Now().UTC()

	rec := &wire.TrustRecord{
		DeviceID:          devID,
		PublicKey:         pubHex,
		LocalLabel:        "Alice MacBook",
		PairCredentialRef: "test-cred-ref",
		Capabilities:      []string{"transfer.v1", "lan_direct"},
		FirstSeenAt:       now,
		LastSeenAt:        now,
		Policy: wire.TrustPolicy{
			AutoAccept:        false,
			AutoAcceptDestDir: "",
		},
	}

	ctx := context.Background()
	if err := svc.store.AddOrUpdateDevice(ctx, rec); err != nil {
		t.Fatalf("AddOrUpdateDevice failed: %v", err)
	}

	// List should now show 1 device with "online" status (seen within 15 mins)
	devs, err = svc.ListTrustedDevices()
	if err != nil || len(devs) != 1 {
		t.Fatalf("expected 1 device, got %d (err=%v)", len(devs), err)
	}
	if devs[0].LocalLabel != "Alice MacBook" || devs[0].Status != "online" {
		t.Errorf("device view mismatch: %+v", devs[0])
	}

	// Rename device
	if err := svc.RenameDevice(devID, "Alice Work Laptop"); err != nil {
		t.Fatalf("RenameDevice failed: %v", err)
	}
	devs, _ = svc.ListTrustedDevices()
	if devs[0].LocalLabel != "Alice Work Laptop" {
		t.Errorf("rename did not apply: %s", devs[0].LocalLabel)
	}

	// Update Policy - valid
	absDest := filepath.Join(tmpDir, "downloads")
	if err := svc.UpdateDevicePolicy(devID, wire.TrustPolicy{
		AutoAccept:        true,
		AutoAcceptDestDir: absDest,
	}); err != nil {
		t.Fatalf("UpdateDevicePolicy valid failed: %v", err)
	}
	devs, _ = svc.ListTrustedDevices()
	if !devs[0].Policy.AutoAccept || devs[0].Policy.AutoAcceptDestDir != absDest {
		t.Errorf("policy did not apply: %+v", devs[0].Policy)
	}

	// Update Policy - invalid (relative destination path with auto-accept)
	if err := svc.UpdateDevicePolicy(devID, wire.TrustPolicy{
		AutoAccept:        true,
		AutoAcceptDestDir: "relative/path",
	}); err == nil {
		t.Errorf("expected error for relative auto-accept path")
	}

	// Unpair (revoke)
	if err := svc.UnpairDevice(devID, false); err != nil {
		t.Fatalf("UnpairDevice revoke failed: %v", err)
	}
	devs, _ = svc.ListTrustedDevices()
	if devs[0].Status != "revoked" || !devs[0].Revoked {
		t.Errorf("expected revoked status: %+v", devs[0])
	}

	// Unpair (purge)
	if err := svc.UnpairDevice(devID, true); err != nil {
		t.Fatalf("UnpairDevice purge failed: %v", err)
	}
	devs, _ = svc.ListTrustedDevices()
	if len(devs) != 0 {
		t.Errorf("expected 0 devices after purge, got %d", len(devs))
	}

	if emittedEvent != DeviceEventName {
		t.Errorf("expected emitted event %q, got %q", DeviceEventName, emittedEvent)
	}
}
