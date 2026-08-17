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
		if err != nil || (u.Scheme != "ws" && u.Scheme != "wss" && u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("invalid server URL %q: must be a valid ws:// or wss:// URL", c.ServerURL)
		}
	}
	for _, ice := range c.ICEServers {
		ice = strings.TrimSpace(ice)
		if ice == "" {
			continue
		}
		if !strings.HasPrefix(ice, "stun:") && !strings.HasPrefix(ice, "stuns:") &&
			!strings.HasPrefix(ice, "turn:") && !strings.HasPrefix(ice, "turns:") {
			return fmt.Errorf("invalid ICE server URL %q: must begin with stun:, stuns:, turn:, or turns:", ice)
		}
	}
	if c.Theme != "" && c.Theme != "system" && c.Theme != "dark" && c.Theme != "light" {
		return fmt.Errorf("invalid theme %q: must be system, dark, or light", c.Theme)
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
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return nil, fmt.Errorf("create config directory %s: %w", configDir, err)
	}
	if secrets == nil {
		secrets = DefaultSecretStore()
	}
	return &Store{
		configDir:   configDir,
		configPath:  filepath.Join(configDir, ConfigFileName),
		secretStore: secrets,
	}, nil
}

// ConfigDir returns the configuration directory.
func (s *Store) ConfigDir() string {
	return s.configDir
}

// ConfigPath returns the path to the desktop_config.json file.
func (s *Store) ConfigPath() string {
	return s.configPath
}

// SecretStore returns the underlying secret store.
func (s *Store) SecretStore() SecretStore {
	return s.secretStore
}

// Load reads and validates the configuration from disk. If the file does not exist,
// it returns DefaultConfig() without creating the file.
func (s *Store) Load() (DesktopConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(s.configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return DefaultConfig(), nil
		}
		return DesktopConfig{}, fmt.Errorf("read config: %w", err)
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, &cfg); err != nil {
		return DesktopConfig{}, fmt.Errorf("parse config %s: %w", s.configPath, err)
	}

	if err := cfg.Validate(); err != nil {
		return DesktopConfig{}, fmt.Errorf("validate config: %w", err)
	}

	return cfg, nil
}

// Save writes the configuration to disk atomically with 0600 permissions.
func (s *Store) Save(cfg DesktopConfig) error {
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("validate config: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(s.configDir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	data = append(data, '\n')

	// Atomic write: write to temp file in same directory, sync, and rename
	tmpFile, err := os.CreateTemp(s.configDir, "config-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp config file: %w", err)
	}
	tmpName := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpName) // clean up if rename did not happen
	}()

	if err := tmpFile.Chmod(0o600); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("chmod temp config: %w", err)
	}

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write temp config: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("sync temp config: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp config: %w", err)
	}

	if err := os.Rename(tmpName, s.configPath); err != nil {
		return fmt.Errorf("replace config file: %w", err)
	}

	return nil
}

// SaveTurnCredential securely persists a TURN authentication secret into the OS-protected
// secret store under a key derived from server URL and username.
func (s *Store) SaveTurnCredential(serverURL, username string, secret []byte) error {
	if serverURL == "" || username == "" {
		return errors.New("server URL and username are required")
	}
	if len(secret) == 0 {
		return errors.New("secret cannot be empty")
	}
	key := fmt.Sprintf("turn:%s:%s", serverURL, username)
	return s.secretStore.Set(key, secret)
}

// GetTurnCredential retrieves a TURN credential from OS-protected storage.
func (s *Store) GetTurnCredential(serverURL, username string) ([]byte, error) {
	if serverURL == "" || username == "" {
		return nil, errors.New("server URL and username are required")
	}
	key := fmt.Sprintf("turn:%s:%s", serverURL, username)
	return s.secretStore.Get(key)
}

// DeleteTurnCredential removes a TURN credential from OS-protected storage.
func (s *Store) DeleteTurnCredential(serverURL, username string) error {
	if serverURL == "" || username == "" {
		return errors.New("server URL and username are required")
	}
	key := fmt.Sprintf("turn:%s:%s", serverURL, username)
	return s.secretStore.Delete(key)
}
