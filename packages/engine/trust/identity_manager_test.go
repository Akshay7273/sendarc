package trust

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestIdentityManagerGenerationAndPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "identity.key")

	mgr, err := NewIdentityManager(keyPath)
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}

	id1, err := mgr.GetOrCreateIdentity()
	if err != nil {
		t.Fatalf("GetOrCreateIdentity: %v", err)
	}

	if id1.DeviceID == "" || id1.Fingerprint == "" {
		t.Errorf("expected populated DeviceID and Fingerprint")
	}

	// Verify file mode 0600
	fi, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("expected 0600 permissions, got %v", fi.Mode().Perm())
	}

	// Calling GetOrCreateIdentity again returns the same cached instance
	id2, err := mgr.GetOrCreateIdentity()
	if err != nil {
		t.Fatalf("second GetOrCreateIdentity: %v", err)
	}
	if id1.DeviceID != id2.DeviceID {
		t.Errorf("expected same identity from cache")
	}

	// Reopen with a new manager instance from disk
	mgrReloaded, err := NewIdentityManager(keyPath)
	if err != nil {
		t.Fatalf("reopen NewIdentityManager: %v", err)
	}

	idReloaded, err := mgrReloaded.GetOrCreateIdentity()
	if err != nil {
		t.Fatalf("reloaded GetOrCreateIdentity: %v", err)
	}

	if idReloaded.DeviceID != id1.DeviceID {
		t.Errorf("reloaded device ID mismatch: got %s, want %s", idReloaded.DeviceID, id1.DeviceID)
	}
	if !bytes.Equal(idReloaded.PublicKey, id1.PublicKey) {
		t.Errorf("reloaded public key mismatch")
	}
	if !bytes.Equal(idReloaded.PrivateKey, id1.PrivateKey) {
		t.Errorf("reloaded private key mismatch")
	}

	// Test key rotation
	idRotated, err := mgrReloaded.RotateIdentity()
	if err != nil {
		t.Fatalf("RotateIdentity: %v", err)
	}
	if idRotated.DeviceID == id1.DeviceID {
		t.Errorf("expected new DeviceID after rotation")
	}

	// Verify file now contains rotated key
	mgrAfterRotate, _ := NewIdentityManager(keyPath)
	idAfterRotate, _ := mgrAfterRotate.GetOrCreateIdentity()
	if idAfterRotate.DeviceID != idRotated.DeviceID {
		t.Errorf("persisted key after rotation mismatch")
	}
}
