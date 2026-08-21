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

func TestDevicesCommand(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	trustPath := filepath.Join(tmpDir, "trust.json")
	store, _ := trust.NewFileTrustStore(trustPath)

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
		LocalLabel:        "Bob Server",
		PairCredentialRef: "cred-bob",
		FirstSeenAt:       now,
		LastSeenAt:        now,
		Revoked:           true,
		Policy: wire.TrustPolicy{
			AutoAccept:        true,
			AutoAcceptDestDir: "/var/tmp/downloads",
		},
	})

	// Test tabular output
	var stdout, stderr bytes.Buffer
	code := executeDevices([]string{"--config-dir", tmpDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("executeDevices exit code %d, stderr: %s", code, stderr.String())
	}
	outStr := stdout.String()
	if !strings.Contains(outStr, "Alice Laptop") || !strings.Contains(outStr, "Bob Server") {
		t.Errorf("output missing expected devices: %s", outStr)
	}
	if !strings.Contains(outStr, "active") || !strings.Contains(outStr, "revoked") {
		t.Errorf("output missing status: %s", outStr)
	}

	// Test JSON output
	stdout.Reset()
	stderr.Reset()
	code = executeDevices([]string{"--json", "--config-dir", tmpDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("executeDevices --json exit code %d, stderr: %s", code, stderr.String())
	}
	var views []DeviceJSONView
	if err := json.Unmarshal(stdout.Bytes(), &views); err != nil {
		t.Fatalf("failed to parse JSON: %v (raw: %s)", err, stdout.String())
	}
	if len(views) != 2 {
		t.Fatalf("expected 2 devices in JSON, got %d", len(views))
	}
}

func TestDevicesEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := executeDevices([]string{"--config-dir", tmpDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	if !strings.Contains(stdout.String(), "No paired devices found") {
		t.Errorf("expected empty message, got: %s", stdout.String())
	}
}
