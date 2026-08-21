package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/sendbeam/wire"
)

var (
	// ErrIdentityNotFound is returned when identity key does not exist.
	ErrIdentityNotFound = errors.New("device identity not found")
)

// IdentityManager manages local device cryptographic identity and seed persistence.
type IdentityManager struct {
	mu           sync.RWMutex
	keyFilePath  string
	currIdentity *wire.DeviceIdentity
}

// NewIdentityManager creates an IdentityManager that persists the device private seed to keyFilePath.
func NewIdentityManager(keyFilePath string) (*IdentityManager, error) {
	cleanPath := filepath.Clean(keyFilePath)
	dir := filepath.Dir(cleanPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create identity directory: %w", err)
	}

	mgr := &IdentityManager{
		keyFilePath: cleanPath,
	}

	return mgr, nil
}

// GetOrCreateIdentity returns the existing device identity or generates and saves a fresh one.
func (m *IdentityManager) GetOrCreateIdentity() (*wire.DeviceIdentity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.currIdentity != nil {
		return m.currIdentity, nil
	}

	// Try loading from file
	id, err := m.loadLocked()
	if err == nil {
		m.currIdentity = id
		return id, nil
	}

	if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, ErrIdentityNotFound) {
		return nil, fmt.Errorf("load device identity: %w", err)
	}

	// Generate fresh identity
	id, err = wire.GenerateDeviceIdentityFromReader(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate fresh device identity: %w", err)
	}

	if err := m.saveLocked(id); err != nil {
		return nil, fmt.Errorf("save fresh device identity: %w", err)
	}

	m.currIdentity = id
	return id, nil
}

// RotateIdentity generates a new device identity keypair, overwrites the stored key, and returns the new identity.
func (m *IdentityManager) RotateIdentity() (*wire.DeviceIdentity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	newID, err := wire.GenerateDeviceIdentityFromReader(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate rotated device identity: %w", err)
	}

	if err := m.saveLocked(newID); err != nil {
		return nil, fmt.Errorf("save rotated device identity: %w", err)
	}

	m.currIdentity = newID
	return newID, nil
}

// CurrentIdentity returns the cached identity or nil if not yet initialized.
func (m *IdentityManager) CurrentIdentity() *wire.DeviceIdentity {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currIdentity
}

func (m *IdentityManager) loadLocked() (*wire.DeviceIdentity, error) {
	data, err := os.ReadFile(m.keyFilePath)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, ErrIdentityNotFound
	}

	// Seed is stored as raw 32 bytes or 64-character hex
	var seed []byte
	if len(data) == ed25519.SeedSize {
		seed = data
	} else {
		decoded, err := hex.DecodeString(string(data))
		if err == nil && len(decoded) == ed25519.SeedSize {
			seed = decoded
		} else {
			return nil, errors.New("corrupt device identity key file")
		}
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	return wire.NewDeviceIdentity(pub, priv)
}

func (m *IdentityManager) saveLocked(id *wire.DeviceIdentity) error {
	seed := id.PrivateKey.Seed()

	dir := filepath.Dir(m.keyFilePath)
	tmpFile, err := os.CreateTemp(dir, "identity-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp identity file: %w", err)
	}
	tmpName := tmpFile.Name()
	defer os.Remove(tmpName)

	if err := tmpFile.Chmod(0600); err != nil {
		tmpFile.Close()
		return fmt.Errorf("chmod temp identity file: %w", err)
	}

	if _, err := tmpFile.Write(seed); err != nil {
		tmpFile.Close()
		return fmt.Errorf("write temp identity file: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return fmt.Errorf("sync temp identity file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp identity file: %w", err)
	}

	if err := os.Rename(tmpName, m.keyFilePath); err != nil {
		return fmt.Errorf("atomic rename identity file: %w", err)
	}

	return nil
}
