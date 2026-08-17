package config

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.ServerURL != DefaultServerURL {
		t.Errorf("ServerURL = %q, want %q", cfg.ServerURL, DefaultServerURL)
	}
	if cfg.AutoAccept != false {
		t.Errorf("AutoAccept must be false by default, got %v", cfg.AutoAccept)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("DefaultConfig failed validation: %v", err)
	}
}

func TestConfigStoreLoadSave(t *testing.T) {
	dir := t.TempDir()
	memSecret := NewMemorySecretStore()
	store, err := NewStore(dir, memSecret)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// 1. Initial load returns default config without error
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("initial Load: %v", err)
	}
	if loaded.ServerURL != DefaultServerURL {
		t.Errorf("loaded.ServerURL = %q, want default %q", loaded.ServerURL, DefaultServerURL)
	}
	if loaded.AutoAccept != false {
		t.Errorf("loaded.AutoAccept = %v, want false", loaded.AutoAccept)
	}

	// 2. Modify and save config
	custom := loaded
	custom.ServerURL = "wss://custom.example.com:9000/ws"
	custom.ICEServers = []string{"stun:stun1.example.com:3478", "turn:turnuser@turn.example.com:3478"}
	custom.DownloadDir = filepath.Join(dir, "downloads")
	custom.CloseToTray = true
	custom.Theme = "dark"

	if err := store.Save(custom); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// 3. Verify file permissions (0600)
	fi, err := os.Stat(store.ConfigPath())
	if err != nil {
		t.Fatalf("Stat config path: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("Config file permissions = %o, want 0600", fi.Mode().Perm())
	}

	// 4. Reload and verify equality
	reloaded, err := store.Load()
	if err != nil {
		t.Fatalf("reload Load: %v", err)
	}
	if reloaded.ServerURL != custom.ServerURL {
		t.Errorf("reloaded ServerURL = %q, want %q", reloaded.ServerURL, custom.ServerURL)
	}
	if len(reloaded.ICEServers) != 2 || reloaded.ICEServers[0] != custom.ICEServers[0] {
		t.Errorf("reloaded ICEServers = %v, want %v", reloaded.ICEServers, custom.ICEServers)
	}
	if reloaded.DownloadDir != custom.DownloadDir {
		t.Errorf("reloaded DownloadDir = %q, want %q", reloaded.DownloadDir, custom.DownloadDir)
	}
	if reloaded.CloseToTray != true {
		t.Errorf("reloaded CloseToTray = %v, want true", reloaded.CloseToTray)
	}
	if reloaded.Theme != "dark" {
		t.Errorf("reloaded Theme = %q, want 'dark'", reloaded.Theme)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*DesktopConfig)
		wantErr bool
	}{
		{
			name: "invalid server scheme ftp",
			mutate: func(c *DesktopConfig) {
				c.ServerURL = "ftp://invalid-url"
			},
			wantErr: true,
		},
		{
			name: "invalid server scheme http",
			mutate: func(c *DesktopConfig) {
				c.ServerURL = "http://localhost:8443/ws"
			},
			wantErr: true,
		},
		{
			name: "invalid server scheme https",
			mutate: func(c *DesktopConfig) {
				c.ServerURL = "https://localhost:8443/ws"
			},
			wantErr: true,
		},
		{
			name: "valid server scheme ws",
			mutate: func(c *DesktopConfig) {
				c.ServerURL = "ws://localhost:8443/ws"
			},
			wantErr: false,
		},
		{
			name: "valid server scheme wss",
			mutate: func(c *DesktopConfig) {
				c.ServerURL = "wss://relay.sendbeam.org/ws"
			},
			wantErr: false,
		},
		{
			name: "invalid ICE url prefix",
			mutate: func(c *DesktopConfig) {
				c.ICEServers = []string{"http://bad-ice-server.com"}
			},
			wantErr: true,
		},
		{
			name: "valid STUN and username-only TURN urls",
			mutate: func(c *DesktopConfig) {
				c.ICEServers = []string{"stun:stun.example.com", "turn:beamuser@turn.example.com:3478", "turns:relay.example.com:5349"}
			},
			wantErr: false,
		},
		{
			name: "embedded TURN password in config is forbidden",
			mutate: func(c *DesktopConfig) {
				c.ICEServers = []string{"turn:beamuser:plaintextpassword@turn.example.com:3478"}
			},
			wantErr: true,
		},
		{
			name: "embedded TURNS password with slashes is forbidden",
			mutate: func(c *DesktopConfig) {
				c.ICEServers = []string{"turns://beamuser:secret123@relay.example.com:5349"}
			},
			wantErr: true,
		},
		{
			name: "invalid theme",
			mutate: func(c *DesktopConfig) {
				c.Theme = "neon-green"
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.mutate(&cfg)
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCorruptConfigFileHandling(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir, NewMemorySecretStore())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// Write invalid JSON into config path
	if err := os.WriteFile(store.ConfigPath(), []byte("{ corrupt json ..."), 0o600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}

	_, err = store.Load()
	if err == nil {
		t.Fatalf("Load on corrupt config should fail, got nil")
	}
}

func TestSecretStoreUnavailableDegradation(t *testing.T) {
	unavail := NewUnavailableSecretStore("test environment has no keychain")
	if unavail.IsAvailable() {
		t.Errorf("IsAvailable() = true, want false")
	}

	err := unavail.Set("turn:secret", []byte("topsecret"))
	if err == nil || !errors.Is(err, ErrSecretStoreUnavailable) {
		t.Fatalf("Set on unavailable secret store returned err = %v, want ErrSecretStoreUnavailable", err)
	}

	_, err = unavail.Get("turn:secret")
	if err == nil || !errors.Is(err, ErrSecretStoreUnavailable) {
		t.Fatalf("Get on unavailable secret store returned err = %v, want ErrSecretStoreUnavailable", err)
	}

	// Delete is an idempotent no-op
	if err := unavail.Delete("turn:secret"); err != nil {
		t.Fatalf("Delete on unavailable store returned error: %v", err)
	}
}

func TestMemorySecretStore(t *testing.T) {
	mem := NewMemorySecretStore()
	if !mem.IsAvailable() {
		t.Errorf("IsAvailable() = false, want true")
	}

	key := "turn:server.com:user1"
	val := []byte("super-secret-password-123")

	// 1. Initial Get returns not found
	_, err := mem.Get(key)
	if !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("Get before Set returned %v, want ErrSecretNotFound", err)
	}

	// 2. Set and Get
	if err := mem.Set(key, val); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := mem.Get(key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(val) {
		t.Fatalf("Get returned %q, want %q", got, val)
	}

	// 3. Delete
	if err := mem.Delete(key); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = mem.Get(key)
	if !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("Get after Delete returned %v, want ErrSecretNotFound", err)
	}
}

func TestStoreTurnCredentials(t *testing.T) {
	dir := t.TempDir()
	memSecret := NewMemorySecretStore()
	store, err := NewStore(dir, memSecret)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	serverURL := "turn:relay.sendbeam.org:3478"
	username := "beam-user"
	secret := []byte("turn-credential-token")

	// Save TURN credential
	if err := store.SaveTurnCredential(serverURL, username, secret); err != nil {
		t.Fatalf("SaveTurnCredential: %v", err)
	}

	// Retrieve TURN credential
	got, err := store.GetTurnCredential(serverURL, username)
	if err != nil {
		t.Fatalf("GetTurnCredential: %v", err)
	}
	if string(got) != string(secret) {
		t.Fatalf("GetTurnCredential = %q, want %q", got, secret)
	}

	// Delete TURN credential
	if err := store.DeleteTurnCredential(serverURL, username); err != nil {
		t.Fatalf("DeleteTurnCredential: %v", err)
	}

	_, err = store.GetTurnCredential(serverURL, username)
	if !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("GetTurnCredential after delete returned %v, want ErrSecretNotFound", err)
	}
}

func TestDefaultSecretStoreSelection(t *testing.T) {
	store := DefaultSecretStore()
	if store == nil {
		t.Fatalf("DefaultSecretStore() returned nil")
	}
	if store.BackendName() == "" {
		t.Fatalf("DefaultSecretStore BackendName is empty")
	}
}

func TestUnavailableSecretStoreRefusesPlaintextPersistence(t *testing.T) {
	dir := t.TempDir()
	unavail := NewUnavailableSecretStore("explicit test unavailability")
	store, err := NewStore(dir, unavail)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	err = store.SaveTurnCredential("turn:example.com", "user", []byte("secret123"))
	if err == nil || !errors.Is(err, ErrSecretStoreUnavailable) {
		t.Fatalf("SaveTurnCredential on unavailable store expected ErrSecretStoreUnavailable, got %v", err)
	}

	// Verify no secrets file or plaintext was created on disk
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != ConfigFileName {
			t.Fatalf("unexpected file %q created on disk when secret store is unavailable", e.Name())
		}
	}
}

func TestDPAPICiphertextBlobRoundTrip(t *testing.T) {
	testPayloads := [][]byte{
		[]byte("simple-ascii-secret"),
		[]byte(""),
		[]byte("\x00\x01\x02\x03\xff\xfe\xfd\x00binary-data"),
		[]byte("unicode-🔑-secret-🔒-token"),
		bytes.Repeat([]byte("A"), 4096),
	}

	for _, payload := range testPayloads {
		encoded := EncodeDPAPICiphertextBlob(payload)
		decoded, err := DecodeDPAPICiphertextBlob(encoded)
		if err != nil {
			t.Fatalf("DecodeDPAPICiphertextBlob error: %v", err)
		}
		if !bytes.Equal(decoded, payload) {
			t.Fatalf("DPAPI round-trip mismatch: got %v, want %v", decoded, payload)
		}
	}

	// Corrupt Base64 decoding fails safely
	if _, err := DecodeDPAPICiphertextBlob("!!!not-valid-base64!!!"); err == nil {
		t.Fatalf("DecodeDPAPICiphertextBlob on corrupt data expected error, got nil")
	}
}

func TestConfigFileContainsNoSecrets(t *testing.T) {
	dir := t.TempDir()
	memSecret := NewMemorySecretStore()
	store, err := NewStore(dir, memSecret)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	serverURL := "turn:relay.sendbeam.org:3478"
	username := "beamuser"
	secretPass := "ultra-confidential-password-xyz"

	// 1. Save TURN password to SecretStore
	if err := store.SaveTurnCredential(serverURL, username, []byte(secretPass)); err != nil {
		t.Fatalf("SaveTurnCredential: %v", err)
	}

	// 2. Save desktop config with non-secret ICE server URL
	cfg := DefaultConfig()
	cfg.ICEServers = []string{"stun:stun1.example.com:3478", "turn:beamuser@relay.sendbeam.org:3478"}
	if err := store.Save(cfg); err != nil {
		t.Fatalf("Save config: %v", err)
	}

	// 3. Inspect raw desktop_config.json on disk
	rawJSON, err := os.ReadFile(store.ConfigPath())
	if err != nil {
		t.Fatalf("ReadFile config: %v", err)
	}
	if strings.Contains(string(rawJSON), secretPass) {
		t.Fatalf("desktop_config.json leaked secret password! content: %s", string(rawJSON))
	}
}
