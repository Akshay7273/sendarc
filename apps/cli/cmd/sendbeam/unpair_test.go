package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

func TestUnpairCommand(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	trustPath := filepath.Join(tmpDir, "trust.json")
	store, _ := trust.NewFileTrustStore(trustPath)

	pubA, _, _ := ed25519.GenerateKey(nil)
	devAlice := wire.DeriveDeviceID(pubA)

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

	// Cancel interactive prompt
	var stdin, stdout, stderr bytes.Buffer
	stdin.WriteString("n\n")
	code := executeUnpair([]string{"--config-dir", tmpDir, "Alice Laptop"}, &stdin, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "cancelled") {
		t.Errorf("expected cancellation: code=%d out=%s", code, stdout.String())
	}

	// Confirm interactive prompt (revokes trust)
	stdin.Reset()
	stdout.Reset()
	stderr.Reset()
	stdin.WriteString("yes\n")
	code = executeUnpair([]string{"--config-dir", tmpDir, "Alice Laptop"}, &stdin, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "Revoked trust") {
		t.Errorf("expected revoked: code=%d out=%s", code, stdout.String())
	}

	// Check record is marked revoked in store
	storeAfterRevoke, _ := trust.NewFileTrustStore(trustPath)
	rec, _ := storeAfterRevoke.GetDevice(ctx, devAlice)
	if rec == nil || !rec.Revoked {
		t.Errorf("expected device to be revoked in store")
	}

	// Purge with --yes and --json
	stdout.Reset()
	stderr.Reset()
	code = executeUnpair([]string{"--config-dir", tmpDir, "--yes", "--purge", "--json", devAlice}, &stdin, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("purge failed: code=%d stderr=%s", code, stderr.String())
	}
	var view UnpairJSONView
	if err := json.Unmarshal(stdout.Bytes(), &view); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if !view.Purged || view.Status != "unpaired" {
		t.Errorf("view mismatch: %+v", view)
	}

	// Verify deleted from store
	storeAfterPurge, _ := trust.NewFileTrustStore(trustPath)
	recAfter, _ := storeAfterPurge.GetDevice(ctx, devAlice)
	if recAfter != nil {
		t.Errorf("expected device to be purged from store")
	}

	// Non-existent device error
	stdout.Reset()
	stderr.Reset()
	code = executeUnpair([]string{"--config-dir", tmpDir, "--yes", "ghost-device"}, &stdin, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1 for non-existent device, got %d", code)
	}
}
