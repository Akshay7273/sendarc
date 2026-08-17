// Package config manages desktop persistent configuration and credentials.
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	if !d.IsAvailable() {
		return nil, ErrSecretStoreUnavailable
	}
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
	if !d.IsAvailable() {
		return ErrSecretStoreUnavailable
	}
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
	if !d.IsAvailable() {
		return nil
	}
	cmd := exec.Command("/usr/bin/security", "delete-generic-password", "-s", d.serviceName, "-a", key)
	_ = cmd.Run()
	return nil
}

// IsAvailable reports true on Darwin when security CLI is in PATH.
func (d *DarwinKeychainSecretStore) IsAvailable() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	_, err := exec.LookPath("security")
	return err == nil
}

// BackendName returns "macos-keychain".
func (d *DarwinKeychainSecretStore) BackendName() string {
	return "macos-keychain"
}

// LinuxSecretServiceStore manages credentials via the FreeDesktop Secret Service
// standard using the `secret-tool` CLI utility.
type LinuxSecretServiceStore struct {
	serviceName string
}

// NewLinuxSecretServiceStore creates a Linux Secret Service store.
func NewLinuxSecretServiceStore(serviceName string) *LinuxSecretServiceStore {
	if serviceName == "" {
		serviceName = "SendBeam"
	}
	return &LinuxSecretServiceStore{serviceName: serviceName}
}

// Get retrieves a secret from Secret Service.
func (l *LinuxSecretServiceStore) Get(key string) ([]byte, error) {
	if !l.IsAvailable() {
		return nil, ErrSecretStoreUnavailable
	}
	cmd := exec.Command("secret-tool", "lookup", "service", l.serviceName, "key", key)
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		return nil, ErrSecretNotFound
	}
	return out, nil
}

// Set saves a secret into Secret Service.
func (l *LinuxSecretServiceStore) Set(key string, secret []byte) error {
	if !l.IsAvailable() {
		return ErrSecretStoreUnavailable
	}
	if key == "" {
		return errors.New("secret key cannot be empty")
	}
	cmd := exec.Command("secret-tool", "store", "--label="+l.serviceName, "service", l.serviceName, "key", key)
	cmd.Stdin = bytes.NewReader(secret)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("secret-tool set error: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// Delete clears a secret from Secret Service.
func (l *LinuxSecretServiceStore) Delete(key string) error {
	if !l.IsAvailable() {
		return nil
	}
	cmd := exec.Command("secret-tool", "clear", "service", l.serviceName, "key", key)
	_ = cmd.Run()
	return nil
}

// IsAvailable reports true if running on Linux and secret-tool is in PATH.
func (l *LinuxSecretServiceStore) IsAvailable() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	_, err := exec.LookPath("secret-tool")
	return err == nil
}

// BackendName returns "linux-secret-service".
func (l *LinuxSecretServiceStore) BackendName() string {
	return "linux-secret-service"
}

// WindowsDPAPIStore uses Windows Data Protection API (DPAPI) to encrypt secrets
// at rest scoped to the current user.
type WindowsDPAPIStore struct {
	storageDir string
}

// NewWindowsDPAPIStore creates a Windows DPAPI store. If storageDir is empty,
// it uses %APPDATA%\sendbeam\secrets.
func NewWindowsDPAPIStore(storageDir string) *WindowsDPAPIStore {
	if storageDir == "" {
		if configDir, err := os.UserConfigDir(); err == nil {
			storageDir = filepath.Join(configDir, AppDirName, "secrets")
		} else {
			storageDir = filepath.Join(os.TempDir(), "sendbeam_secrets")
		}
	}
	return &WindowsDPAPIStore{storageDir: storageDir}
}

func (w *WindowsDPAPIStore) keyPath(key string) string {
	h := sha256.Sum256([]byte(key))
	return filepath.Join(w.storageDir, hex.EncodeToString(h[:])+".dpapi")
}

// EncodeDPAPICiphertextBlob formats DPAPI protected ciphertext into a Base64 string for disk storage.
func EncodeDPAPICiphertextBlob(rawCiphertext []byte) string {
	return base64.StdEncoding.EncodeToString(rawCiphertext)
}

// DecodeDPAPICiphertextBlob parses a Base64 string from disk into raw DPAPI ciphertext bytes.
func DecodeDPAPICiphertextBlob(b64Ciphertext string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.TrimSpace(b64Ciphertext))
}

// Get reads and decrypts a DPAPI-protected secret.
func (w *WindowsDPAPIStore) Get(key string) ([]byte, error) {
	if !w.IsAvailable() {
		return nil, ErrSecretStoreUnavailable
	}
	p := w.keyPath(key)
	encData, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrSecretNotFound
		}
		return nil, fmt.Errorf("read dpapi file: %w", err)
	}

	// Validate ciphertext format
	if _, err := DecodeDPAPICiphertextBlob(string(encData)); err != nil {
		return nil, fmt.Errorf("corrupt dpapi ciphertext file: %w", err)
	}

	// Unprotect via PowerShell ProtectedData reading Base64 ciphertext from stdin
	// and outputting Base64 decrypted plaintext to stdout (no secrets in command line args).
	script := `$in = [Console]::In.ReadToEnd().Trim(); if ([string]::IsNullOrEmpty($in)) { exit 1 }; $enc = [Convert]::FromBase64String($in); $raw = [System.Security.Cryptography.ProtectedData]::Unprotect($enc, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser); [Console]::Out.Write([Convert]::ToBase64String($raw))`
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Stdin = strings.NewReader(strings.TrimSpace(string(encData)))
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("dpapi unprotect error: %w", err)
	}
	dec64 := strings.TrimSpace(string(out))
	return base64.StdEncoding.DecodeString(dec64)
}

// Set encrypts and writes a DPAPI-protected secret.
func (w *WindowsDPAPIStore) Set(key string, secret []byte) error {
	if !w.IsAvailable() {
		return ErrSecretStoreUnavailable
	}
	if key == "" {
		return errors.New("secret key cannot be empty")
	}
	if err := os.MkdirAll(w.storageDir, 0o700); err != nil {
		return fmt.Errorf("create secrets dir: %w", err)
	}

	// Protect via PowerShell ProtectedData reading Base64 plaintext from stdin
	// and outputting Base64 ciphertext to stdout (no secrets in command line args).
	script := `$in = [Console]::In.ReadToEnd().Trim(); if ([string]::IsNullOrEmpty($in)) { exit 1 }; $raw = [Convert]::FromBase64String($in); $enc = [System.Security.Cryptography.ProtectedData]::Protect($raw, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser); [Console]::Out.Write([Convert]::ToBase64String($enc))`
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Stdin = strings.NewReader(base64.StdEncoding.EncodeToString(secret))
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("dpapi protect error: %w", err)
	}

	b64Ciphertext := strings.TrimSpace(string(out))
	if _, err := DecodeDPAPICiphertextBlob(b64Ciphertext); err != nil {
		return fmt.Errorf("invalid dpapi output ciphertext: %w", err)
	}

	p := w.keyPath(key)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(b64Ciphertext), 0o600); err != nil {
		return fmt.Errorf("write dpapi file: %w", err)
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename dpapi file: %w", err)
	}
	return nil
}

// Delete removes a DPAPI-protected secret.
func (w *WindowsDPAPIStore) Delete(key string) error {
	if !w.IsAvailable() {
		return nil
	}
	_ = os.Remove(w.keyPath(key))
	return nil
}

// IsAvailable reports true when running on Windows and PowerShell is in PATH.
func (w *WindowsDPAPIStore) IsAvailable() bool {
	if runtime.GOOS != "windows" {
		return false
	}
	_, err := exec.LookPath("powershell")
	return err == nil
}

// BackendName returns "windows-dpapi".
func (w *WindowsDPAPIStore) BackendName() string {
	return "windows-dpapi"
}

// DefaultSecretStore resolves the appropriate OS-protected secret store
// for the current platform. If none is available, it returns an UnavailableSecretStore
// to fail closed rather than falling back to plaintext storage.
func DefaultSecretStore() SecretStore {
	switch runtime.GOOS {
	case "darwin":
		store := NewDarwinKeychainSecretStore("SendBeam")
		if store.IsAvailable() {
			return store
		}
		return NewUnavailableSecretStore("macOS Keychain unavailable")
	case "windows":
		store := NewWindowsDPAPIStore("")
		if store.IsAvailable() {
			return store
		}
		return NewUnavailableSecretStore("Windows DPAPI unavailable")
	case "linux":
		store := NewLinuxSecretServiceStore("SendBeam")
		if store.IsAvailable() {
			return store
		}
		return NewUnavailableSecretStore("Secret Service / secret-tool not available in Linux desktop session")
	default:
		return NewUnavailableSecretStore("native OS credential helper not configured for " + runtime.GOOS)
	}
}
