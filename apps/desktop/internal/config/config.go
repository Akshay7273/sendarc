// Package config manages desktop persistent configuration and credentials.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	// DefaultServerURL matches the CLI and server default signaling URL.
	DefaultServerURL = "wss://localhost:8443/ws"
	// ConfigFileName is the JSON file name for desktop preferences.
	ConfigFileName = "desktop_config.json"
	// AppDirName is the folder created in user config directory.
	AppDirName = "sendbeam"
)

// DesktopConfig holds non-secret persistent desktop preferences.
// SENSITIVE values (passwords, tokens) are NEVER stored in this struct or in
// its serialized JSON on disk; they are stored via SecretStore.
type DesktopConfig struct {
	// ServerURL is the signaling server WebSocket URL.
	ServerURL string `json:"serverUrl"`
	// ICEServers are custom STUN / TURN server URLs.
	ICEServers []string `json:"iceServers"`
	// DownloadDir is the custom default directory to save received files.
	// If empty, the OS standard downloads folder or working directory is used.
	DownloadDir string `json:"downloadDir"`
	// AutoAccept controls whether incoming transfers are accepted automatically.
	// SECURITY INVARIANT: Must strictly default to false.
	AutoAccept bool `json:"autoAccept"`
	// CloseToTray controls if closing the main window minimizes to tray instead of quitting.
	CloseToTray bool `json:"closeToTray"`
	// StartMinimized controls whether the app launches minimized.
	StartMinimized bool `json:"startMinimized"`
	// Theme is the UI theme ("system", "dark", "light").
	Theme string `json:"theme"`
}

// DefaultConfig returns the default safe configuration.
func DefaultConfig() DesktopConfig {
	return DesktopConfig{
		ServerURL:      DefaultServerURL,
		ICEServers:     []string{"stun:stun.l.google.com:19302"},
		DownloadDir:    "",
		AutoAccept:     false, // strictly false by default
		CloseToTray:    false,
		StartMinimized: false,
		Theme:          "system",
	}
}

// Validate validates the configuration values.
func (c *DesktopConfig) Validate() error {
	if c.ServerURL != "" {
		u, err := url.Parse(c.ServerURL)
		if err != nil || (u.Scheme != "ws" && u.Scheme != "wss") || u.Host == "" {
			return fmt.Errorf("invalid server url %q (must be a valid ws:// or wss:// url)", c.ServerURL)
		}
	}
	for _, ice := range c.ICEServers {
		ice = strings.TrimSpace(ice)
		if ice == "" {
			continue
		}
		if !strings.HasPrefix(ice, "stun:") && !strings.HasPrefix(ice, "stuns:") &&
			!strings.HasPrefix(ice, "turn:") && !strings.HasPrefix(ice, "turns:") {
			return fmt.Errorf("invalid ice server url %q (must begin with stun:, stuns:, turn:, or turns)", ice)
		}
		// Embedded passwords in configuration are strictly forbidden to prevent plaintext secret leaks.
		if strings.HasPrefix(ice, "turn:") || strings.HasPrefix(ice, "turns:") {
			rest := strings.TrimPrefix(strings.TrimPrefix(ice, "turns:"), "turn:")
			rest = strings.TrimPrefix(rest, "//")
			if atIdx := strings.LastIndex(rest, "@"); atIdx != -1 {
				userInfo := rest[:atIdx]
				if strings.Contains(userInfo, ":") {
					return fmt.Errorf("invalid ice server %q: embedded passwords are forbidden in configuration; store credentials through the protected credential store", ice)
				}
			}
		}
	}
	if c.Theme != "" && c.Theme != "system" && c.Theme != "dark" && c.Theme != "light" {
		return fmt.Errorf("invalid theme %q (must be system, dark, or light)", c.Theme)
	}
	return nil
}

// Store manages loading, saving, and secret access for desktop configuration.
type Store struct {
	mu          sync.RWMutex
	configDir   string
	configPath  string
	secretStore SecretStore
}

// NewStore creates a config Store targeting the given config directory.
// If configDir is empty, it uses the default OS user config directory.
// If secrets is nil, it uses DefaultSecretStore().
func NewStore(configDir string, secrets SecretStore) (*Store, error) {
	if configDir == "" {
		dir, err := os.UserConfigDir()
		if err != nil {
			home, herr := os.UserHomeDir()
			if herr != nil {
				return nil, fmt.Errorf("resolve user config dir: %w", err)
			}
			dir = filepath.Join(home, ".config")
		}
		configDir = filepath.Join(dir, AppDirName)
	}

	absDir, err := filepath.Abs(configDir)
	if err != nil {
		return nil, fmt.Errorf("resolve absolute config dir: %w", err)
	}

	if secrets == nil {
		secrets = DefaultSecretStore()
	}

	return &Store{
		configDir:   absDir,
		configPath:  filepath.Join(absDir, ConfigFileName),
		secretStore: secrets,
	}, nil
}

// ConfigDir returns the directory containing the desktop configuration.
func (s *Store) ConfigDir() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.configDir
}

// ConfigPath returns the path of the desktop configuration file.
func (s *Store) ConfigPath() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.configPath
}

// Secrets returns the associated SecretStore.
func (s *Store) Secrets() SecretStore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.secretStore
}

// Load reads and parses desktop preferences from disk. If the file does not
// exist, it returns DefaultConfig() without creating the file.
func (s *Store) Load() (DesktopConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(s.configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return DefaultConfig(), nil
		}
		return DefaultConfig(), fmt.Errorf("read desktop config: %w", err)
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, &cfg); err != nil {
		return DefaultConfig(), fmt.Errorf("decode desktop config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return DefaultConfig(), fmt.Errorf("invalid config on disk: %w", err)
	}

	return cfg, nil
}

// Save validates and atomically writes desktop preferences to disk with 0600 permissions.
func (s *Store) Save(cfg DesktopConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(s.configDir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode desktop config: %w", err)
	}
	data = append(data, '\n')

	tmpFile := s.configPath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0o600); err != nil {
		return fmt.Errorf("write temporary config: %w", err)
	}

	if err := os.Rename(tmpFile, s.configPath); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("atomic rename config: %w", err)
	}

	return nil
}

// SaveTurnCredential saves TURN server credentials in OS-protected secret storage.
func (s *Store) SaveTurnCredential(serverURL, username string, credential []byte) error {
	s.mu.RLock()
	secrets := s.secretStore
	s.mu.RUnlock()

	if secrets == nil || !secrets.IsAvailable() {
		return fmt.Errorf("%w: cannot store turn credentials", ErrSecretStoreUnavailable)
	}

	key := fmt.Sprintf("turn:%s:%s", serverURL, username)
	return secrets.Set(key, credential)
}

// GetTurnCredential retrieves TURN credentials from OS-protected secret storage.
func (s *Store) GetTurnCredential(serverURL, username string) ([]byte, error) {
	s.mu.RLock()
	secrets := s.secretStore
	s.mu.RUnlock()

	if secrets == nil || !secrets.IsAvailable() {
		return nil, ErrSecretStoreUnavailable
	}

	key := fmt.Sprintf("turn:%s:%s", serverURL, username)
	return secrets.Get(key)
}

// DeleteTurnCredential removes TURN credentials from OS-protected secret storage.
func (s *Store) DeleteTurnCredential(serverURL, username string) error {
	s.mu.RLock()
	secrets := s.secretStore
	s.mu.RUnlock()

	if secrets == nil || !secrets.IsAvailable() {
		return nil
	}

	key := fmt.Sprintf("turn:%s:%s", serverURL, username)
	return secrets.Delete(key)
}
