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

func (u *UnavailableSecretStore) Get(key string) ([]byte, error) {
	return nil, fmt.Errorf("%w: %s", ErrSecretStoreUnavailable, u.reason)
}

func (u *UnavailableSecretStore) Set(key string, secret []byte) error {
	return fmt.Errorf("%w: %s", ErrSecretStoreUnavailable, u.reason)
}

func (u *UnavailableSecretStore) Delete(key string) error {
	return nil // deleting from an unavailable store is an idempotent no-op
}

func (u *UnavailableSecretStore) IsAvailable() bool {
	return false
}

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

func (m *MemorySecretStore) Delete(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.secrets, key)
	return nil
}

func (m *MemorySecretStore) IsAvailable() bool {
	return true
}

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

func (d *DarwinKeychainSecretStore) Get(key string) ([]byte, error) {
	cmd := exec.Command("/usr/bin/security", "find-generic-password", "-s", d.serviceName, "-a", key, "-w")
	out, err := cmd.Output()
	if err != nil {
		return nil, ErrSecretNotFound
	}
	return []byte(strings.TrimRight(string(out), "\r\n")), nil
}

func (d *DarwinKeychainSecretStore) Set(key string, secret []byte) error {
	cmd := exec.Command("/usr/bin/security", "add-generic-password", "-U", "-s", d.serviceName, "-a", key, "-w", string(secret))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("keychain set error: %w", err)
	}
	return nil
}

func (d *DarwinKeychainSecretStore) Delete(key string) error {
	cmd := exec.Command("/usr/bin/security", "delete-generic-password", "-s", d.serviceName, "-a", key)
	_ = cmd.Run() // idempotent ignore if not found
	return nil
}

func (d *DarwinKeychainSecretStore) IsAvailable() bool {
	_, err := exec.LookPath("/usr/bin/security")
	return err == nil
}

func (d *DarwinKeychainSecretStore) BackendName() string {
	return "darwin-keychain"
}

// DefaultSecretStore returns the best available OS-protected secret store for the
// current platform, or an UnavailableSecretStore with clear degradation rationale.
func DefaultSecretStore() SecretStore {
	switch runtime.GOOS {
	case "darwin":
		store := NewDarwinKeychainSecretStore("SendBeam")
		if store.IsAvailable() {
			return store
		}
		return NewUnavailableSecretStore("macOS security CLI not found")
	case "windows":
		return NewUnavailableSecretStore("Windows DPAPI integration disabled in current build")
	case "linux":
		return NewUnavailableSecretStore("Linux Secret Service daemon not available")
	default:
		return NewUnavailableSecretStore("unsupported operating system for protected credentials: " + runtime.GOOS)
	}
}
