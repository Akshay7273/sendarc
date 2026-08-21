package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

const (
	appConfigDirName    = "sendbeam"
	trustFileName       = "trust.json"
	identityKeyFileName = "identity.key"
	secretsFileName     = "secrets.json"
)

// FileSecretResolver manages persistent storage of 32-byte k_pair secrets with 0600 permissions.
type FileSecretResolver struct {
	path string
	mu   sync.RWMutex
	data map[string]string // deviceID -> hex(k_pair)
}

// NewFileSecretResolver initializes the secret resolver from disk.
func NewFileSecretResolver(path string) (*FileSecretResolver, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create secrets dir: %w", err)
	}

	r := &FileSecretResolver{
		path: path,
		data: make(map[string]string),
	}

	content, err := os.ReadFile(path)
	if err == nil && len(content) > 0 {
		_ = json.Unmarshal(content, &r.data)
	}
	return r, nil
}

// SetSecret stores a raw 32-byte secret for a device and flushes atomically to disk.
func (r *FileSecretResolver) SetSecret(deviceID string, secret []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.data[deviceID] = hex.EncodeToString(secret)
	data, err := json.MarshalIndent(r.data, "", "  ")
	if err != nil {
		return err
	}

	tmp := fmt.Sprintf("%s.tmp.%d", r.path, os.Getpid())
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}

// DeleteSecret removes a device secret from storage.
func (r *FileSecretResolver) DeleteSecret(deviceID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.data, deviceID)
	data, err := json.MarshalIndent(r.data, "", "  ")
	if err != nil {
		return err
	}

	tmp := fmt.Sprintf("%s.tmp.%d", r.path, os.Getpid())
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}

// ResolvePairSecret implements trust.SecretResolver.
func (r *FileSecretResolver) ResolvePairSecret(_ context.Context, deviceID, _ string) ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	hexStr, ok := r.data[deviceID]
	if !ok || len(hexStr) == 0 {
		return nil, errors.New("pair secret not found")
	}
	return hex.DecodeString(hexStr)
}

// CLIEnvironment provides shared access to local device identity, trust store, and secret store.
type CLIEnvironment struct {
	ConfigDir   string
	IdentityMgr *trust.IdentityManager
	TrustStore  trust.Store
	Secrets     *FileSecretResolver
}

// InitCLIEnvironment loads or creates the default CLI trust environment.
func InitCLIEnvironment(customDir string) (*CLIEnvironment, error) {
	dir := customDir
	if dir == "" {
		userConfig, err := os.UserConfigDir()
		if err != nil {
			userConfig = "."
		}
		dir = filepath.Join(userConfig, appConfigDirName)
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create config dir: %w", err)
	}

	idPath := filepath.Join(dir, identityKeyFileName)
	idMgr, err := trust.NewIdentityManager(idPath)
	if err != nil {
		return nil, fmt.Errorf("init identity manager: %w", err)
	}

	trustPath := filepath.Join(dir, trustFileName)
	trustStore, err := trust.NewFileTrustStore(trustPath)
	if err != nil {
		return nil, fmt.Errorf("init trust store: %w", err)
	}

	secretsPath := filepath.Join(dir, secretsFileName)
	secrets, err := NewFileSecretResolver(secretsPath)
	if err != nil {
		return nil, fmt.Errorf("init secrets store: %w", err)
	}

	return &CLIEnvironment{
		ConfigDir:   dir,
		IdentityMgr: idMgr,
		TrustStore:  trustStore,
		Secrets:     secrets,
	}, nil
}

// ResolveDevice finds a device in the trust store by device ID, local label, or fingerprint.
func ResolveDevice(ctx context.Context, store trust.Store, query string) (*wire.TrustRecord, error) {
	q := strings.TrimSpace(strings.TrimPrefix(query, "@"))
	if q == "" {
		return nil, errors.New("device query cannot be empty")
	}

	devices, err := store.ListDevices(ctx)
	if err != nil {
		return nil, err
	}

	// 1. Exact match on DeviceID
	for _, dev := range devices {
		if strings.EqualFold(dev.DeviceID, q) {
			return dev, nil
		}
	}

	// 2. Exact match on Fingerprint
	for _, dev := range devices {
		if strings.EqualFold(dev.Fingerprint(), q) {
			return dev, nil
		}
	}

	// 3. Exact match on LocalLabel (case-insensitive)
	for _, dev := range devices {
		if strings.EqualFold(dev.LocalLabel, q) {
			return dev, nil
		}
	}

	// 4. Prefix match on DeviceID or Fingerprint
	var prefixMatches []*wire.TrustRecord
	for _, dev := range devices {
		if strings.HasPrefix(strings.ToLower(dev.DeviceID), strings.ToLower(q)) ||
			strings.HasPrefix(strings.ToLower(dev.Fingerprint()), strings.ToLower(q)) ||
			strings.HasPrefix(strings.ToLower(dev.LocalLabel), strings.ToLower(q)) {
			prefixMatches = append(prefixMatches, dev)
		}
	}

	if len(prefixMatches) == 1 {
		return prefixMatches[0], nil
	}
	if len(prefixMatches) > 1 {
		return nil, fmt.Errorf("ambiguous device identifier %q matches %d devices", query, len(prefixMatches))
	}

	return nil, fmt.Errorf("device %q not found in trust store", query)
}
