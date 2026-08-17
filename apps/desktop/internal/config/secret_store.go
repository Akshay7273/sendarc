// Package config manages desktop persistent configuration and credentials.
package config

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

var (
	// ErrSecretStoreUnavailable is returned when attempting to persist secrets on a
	// system where OS-protected credential storage is unavailable. Silent downgrade
	// to plaintext persistence is strictly refused.
	ErrSecretStoreUnavailable = errors.New("os protected secret storage is unavailable; saving raw secrets in plaintext is refused")
	// ErrSecretNotFound is returned when the requested secret key does not exist.
	ErrSecretNotFound = errors.New("secret not found")
)

// SecretStore is the interface for OS-protected persistent secret storage.
// Implementations MUST NOT store raw secrets in plaintext JSON, localStorage,
// or diagnostic logs.
type SecretStore interface {
	Get(key string) ([]byte, error)
	Set(key string, secret []byte) error
	Delete(key string) error
	IsAvailable() bool
	BackendName() string
}

// UnavailableSecretStore is used when no reliable OS-protected secret store is
// available. It fails closed and explicitly informs the caller rather than
// silently storing secrets insecurely.
type UnavailableSecretStore struct {
	reason string
}

// NewUnavailableSecretStore creates an UnavailableSecretStore.
func NewUnavailableSecretStore(reason string) *UnavailableSecretStore {
	if reason == "" {
		reason = "no protected credential facility detected"
	}
	return &UnavailableSecretStore{reason: reason}
}

// Get always returns an error indicating secret storage is unavailable.
func (u *UnavailableSecretStore) Get(_ string) ([]byte, error) {
	return nil, fmt.Errorf("%w: %s", ErrSecretStoreUnavailable, u.reason)
}

// Set always returns an error indicating secret storage is unavailable.
func (u *UnavailableSecretStore) Set(_ string, _ []byte) error {
	return fmt.Errorf("%w: %s", ErrSecretStoreUnavailable, u.reason)
}

// Delete is an idempotent no-op on unavailable stores.
func (u *UnavailableSecretStore) Delete(_ string) error {
	return nil
}

// IsAvailable reports false for unavailable stores.
func (u *UnavailableSecretStore) IsAvailable() bool {
	return false
}

// BackendName returns a descriptive unavailable status.
func (u *UnavailableSecretStore) BackendName() string {
	return "unavailable (" + u.reason + ")"
}

// MemorySecretStore is an in-memory thread-safe secret store for tests or ephemeral runs.
type MemorySecretStore struct {
	mu      sync.RWMutex
	secrets map[string][]byte
}

// NewMemorySecretStore creates a new MemorySecretStore.
func NewMemorySecretStore() *MemorySecretStore {
	return &MemorySecretStore{secrets: make(map[string][]byte)}
}

// Get retrieves a stored secret by key.
func (m *MemorySecretStore) Get(key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	val, ok := m.secrets[key]
	if !ok {
		return nil, ErrSecretNotFound
	}
	cpy := make([]byte, len(val))
	copy(cpy, val)
	return cpy, nil
}

// Set stores a secret by key.
func (m *MemorySecretStore) Set(key string, secret []byte) error {
	if key == "" {
		return errors.New("secret key cannot be empty")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cpy := make([]byte, len(secret))
	copy(cpy, secret)
	m.secrets[key] = cpy
	return nil
}

// Delete removes a stored secret by key.
func (m *MemorySecretStore) Delete(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.secrets, key)
	return nil
}

// IsAvailable reports true for in-memory stores.
func (m *MemorySecretStore) IsAvailable() bool {
	return true
}

// BackendName returns "memory".
func (m *MemorySecretStore) BackendName() string {
	return "memory"
}

// DarwinKeychainSecretStore uses the macOS Security CLI (/usr/bin/security)
// to manage secrets in the macOS Keychain.
type DarwinKeychainSecretStore struct {
	serviceName string
}

// NewDarwinKeychainSecretStore creates a Darwin keychain secret store.
func NewDarwinKeychainSecretStore(serviceName string) *DarwinKeychainSecretStore {
	if serviceName == "" {
		serviceName = "SendBeam"
	}
	return &DarwinKeychainSecretStore{serviceName: serviceName}
}

// Get retrieves a generic password from the macOS Keychain.
func (d *DarwinKeychainSecretStore) Get(key string) ([]byte, error) {
	cmd := exec.Command("/usr/bin/security", "find-generic-password", "-s", d.serviceName, "-a", key, "-w")
	out, err := cmd.Output()
	if err != nil {
		return nil, ErrSecretNotFound
	}
	trimmed := strings.TrimRight(string(out), "\r\n")
	return []byte(trimmed), nil
}

// Set saves or updates a generic password in the macOS Keychain.
func (d *DarwinKeychainSecretStore) Set(key string, secret []byte) error {
	if key == "" {
		return errors.New("secret key cannot be empty")
	}
	cmd := exec.Command("/usr/bin/security", "add-generic-password", "-U", "-s", d.serviceName, "-a", key, "-w", string(secret))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("keychain set error: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// Delete removes a generic password from the macOS Keychain.
func (d *DarwinKeychainSecretStore) Delete(key string) error {
	cmd := exec.Command("/usr/bin/security", "delete-generic-password", "-s", d.serviceName, "-a", key)
	_ = cmd.Run()
	return nil
}

// IsAvailable reports true when running on Darwin.
func (d *DarwinKeychainSecretStore) IsAvailable() bool {
	return runtime.GOOS == "darwin"
}

// BackendName returns "macos-keychain".
func (d *DarwinKeychainSecretStore) BackendName() string {
	return "macos-keychain"
}

// DefaultSecretStore resolves the appropriate OS-protected secret store
// for the current platform. If none is available, it returns an UnavailableSecretStore
// to fail closed rather than falling back to plaintext storage.
func DefaultSecretStore() SecretStore {
	switch runtime.GOOS {
	case "darwin":
		return NewDarwinKeychainSecretStore("SendBeam")
	default:
		return NewUnavailableSecretStore("native OS credential helper not configured for " + runtime.GOOS)
	}
}
