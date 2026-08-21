package trust

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sendbeam/wire"
)

var (
	// ErrDeviceNotFound is returned when querying a device ID that is not registered in the trust DB.
	ErrDeviceNotFound = errors.New("device not found in trust database")

	// ErrTrustStoreClosed is returned when operating on a closed store.
	ErrTrustStoreClosed = errors.New("trust store is closed")
)

// TrustStore defines the interface for local trust management, peer policy, and revocation.
type TrustStore interface {
	GetDevice(ctx context.Context, deviceID string) (*wire.TrustRecord, error)
	ListDevices(ctx context.Context) ([]*wire.TrustRecord, error)
	AddOrUpdateDevice(ctx context.Context, record *wire.TrustRecord) error
	RevokeDevice(ctx context.Context, deviceID string) error
	UnpairDevice(ctx context.Context, deviceID string) error
	IsTrusted(ctx context.Context, deviceID string) bool
	UpdateLastSeen(ctx context.Context, deviceID string, seenAt time.Time) error
	UpdatePolicy(ctx context.Context, deviceID string, policy wire.TrustPolicy) error
}

// MemoryTrustStore is an in-memory thread-safe implementation of TrustStore.
type MemoryTrustStore struct {
	mu      sync.RWMutex
	devices map[string]*wire.TrustRecord
}

// NewMemoryTrustStore creates a new MemoryTrustStore.
func NewMemoryTrustStore() *MemoryTrustStore {
	return &MemoryTrustStore{
		devices: make(map[string]*wire.TrustRecord),
	}
}

func (m *MemoryTrustStore) GetDevice(_ context.Context, deviceID string) (*wire.TrustRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.devices[deviceID]
	if !ok {
		return nil, ErrDeviceNotFound
	}
	return cloneRecord(rec), nil
}

func (m *MemoryTrustStore) ListDevices(_ context.Context) ([]*wire.TrustRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*wire.TrustRecord, 0, len(m.devices))
	for _, rec := range m.devices {
		out = append(out, cloneRecord(rec))
	}
	return out, nil
}

func (m *MemoryTrustStore) AddOrUpdateDevice(_ context.Context, record *wire.TrustRecord) error {
	if record == nil {
		return wire.ErrInvalidTrustRecord
	}
	if err := record.Validate(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.devices[record.DeviceID] = cloneRecord(record)
	return nil
}

func (m *MemoryTrustStore) RevokeDevice(_ context.Context, deviceID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.devices[deviceID]
	if !ok {
		return ErrDeviceNotFound
	}
	rec.Revoked = true
	now := time.Now().UTC()
	rec.RevokedAt = &now
	return nil
}

func (m *MemoryTrustStore) UnpairDevice(_ context.Context, deviceID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.devices, deviceID)
	return nil
}

func (m *MemoryTrustStore) IsTrusted(_ context.Context, deviceID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.devices[deviceID]
	return ok && !rec.Revoked
}

func (m *MemoryTrustStore) UpdateLastSeen(_ context.Context, deviceID string, seenAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.devices[deviceID]
	if !ok {
		return ErrDeviceNotFound
	}
	if seenAt.IsZero() {
		seenAt = time.Now().UTC()
	}
	rec.LastSeenAt = seenAt
	return nil
}

func (m *MemoryTrustStore) UpdatePolicy(_ context.Context, deviceID string, policy wire.TrustPolicy) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.devices[deviceID]
	if !ok {
		return ErrDeviceNotFound
	}
	rec.Policy = policy
	return nil
}

// FileTrustStore persists trusted devices in a versioned JSON file with atomic writes and directory confinement.
type FileTrustStore struct {
	mu       sync.RWMutex
	filePath string
	devices  map[string]*wire.TrustRecord
}

type trustFilePayload struct {
	Version   int                 `json:"version"`
	UpdatedAt time.Time           `json:"updated_at"`
	Devices   []*wire.TrustRecord `json:"devices"`
}

const currentTrustFileVersion = 1

// NewFileTrustStore loads or initializes a FileTrustStore at the given path.
func NewFileTrustStore(filePath string) (*FileTrustStore, error) {
	cleanPath := filepath.Clean(filePath)
	dir := filepath.Dir(cleanPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create trust db directory: %w", err)
	}

	store := &FileTrustStore{
		filePath: cleanPath,
		devices:  make(map[string]*wire.TrustRecord),
	}

	if err := store.load(); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Initialize empty file
			if err := store.saveLocked(); err != nil {
				return nil, fmt.Errorf("initialize trust db file: %w", err)
			}
			return store, nil
		}
		return nil, fmt.Errorf("load trust db: %w", err)
	}

	return store, nil
}

func (f *FileTrustStore) load() error {
	data, err := os.ReadFile(f.filePath)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}

	var payload trustFilePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("parse trust db JSON: %w", err)
	}

	f.devices = make(map[string]*wire.TrustRecord)
	for _, rec := range payload.Devices {
		if rec != nil && rec.Validate() == nil {
			f.devices[rec.DeviceID] = rec
		}
	}
	return nil
}

func (f *FileTrustStore) saveLocked() error {
	list := make([]*wire.TrustRecord, 0, len(f.devices))
	for _, rec := range f.devices {
		list = append(list, rec)
	}

	payload := trustFilePayload{
		Version:   currentTrustFileVersion,
		UpdatedAt: time.Now().UTC(),
		Devices:   list,
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal trust db: %w", err)
	}

	dir := filepath.Dir(f.filePath)
	tmpFile, err := os.CreateTemp(dir, "trust-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp trust db file: %w", err)
	}
	tmpName := tmpFile.Name()
	defer os.Remove(tmpName)

	if err := tmpFile.Chmod(0600); err != nil {
		tmpFile.Close()
		return fmt.Errorf("chmod temp trust db file: %w", err)
	}

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return fmt.Errorf("write temp trust db: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return fmt.Errorf("sync temp trust db: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp trust db: %w", err)
	}

	if err := os.Rename(tmpName, f.filePath); err != nil {
		return fmt.Errorf("atomic rename trust db: %w", err)
	}

	return nil
}

func (f *FileTrustStore) GetDevice(_ context.Context, deviceID string) (*wire.TrustRecord, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	rec, ok := f.devices[deviceID]
	if !ok {
		return nil, ErrDeviceNotFound
	}
	return cloneRecord(rec), nil
}

func (f *FileTrustStore) ListDevices(_ context.Context) ([]*wire.TrustRecord, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]*wire.TrustRecord, 0, len(f.devices))
	for _, rec := range f.devices {
		out = append(out, cloneRecord(rec))
	}
	return out, nil
}

func (f *FileTrustStore) AddOrUpdateDevice(_ context.Context, record *wire.TrustRecord) error {
	if record == nil {
		return wire.ErrInvalidTrustRecord
	}
	if err := record.Validate(); err != nil {
		return err
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.devices[record.DeviceID] = cloneRecord(record)
	return f.saveLocked()
}

func (f *FileTrustStore) RevokeDevice(_ context.Context, deviceID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.devices[deviceID]
	if !ok {
		return ErrDeviceNotFound
	}
	rec.Revoked = true
	now := time.Now().UTC()
	rec.RevokedAt = &now
	return f.saveLocked()
}

func (f *FileTrustStore) UnpairDevice(_ context.Context, deviceID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.devices[deviceID]; !ok {
		return nil
	}
	delete(f.devices, deviceID)
	return f.saveLocked()
}

func (f *FileTrustStore) IsTrusted(_ context.Context, deviceID string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	rec, ok := f.devices[deviceID]
	return ok && !rec.Revoked
}

func (f *FileTrustStore) UpdateLastSeen(_ context.Context, deviceID string, seenAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.devices[deviceID]
	if !ok {
		return ErrDeviceNotFound
	}
	if seenAt.IsZero() {
		seenAt = time.Now().UTC()
	}
	rec.LastSeenAt = seenAt
	return f.saveLocked()
}

func (f *FileTrustStore) UpdatePolicy(_ context.Context, deviceID string, policy wire.TrustPolicy) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.devices[deviceID]
	if !ok {
		return ErrDeviceNotFound
	}
	rec.Policy = policy
	return f.saveLocked()
}

func cloneRecord(r *wire.TrustRecord) *wire.TrustRecord {
	if r == nil {
		return nil
	}
	cpy := *r
	if len(r.Capabilities) > 0 {
		cpy.Capabilities = append([]string(nil), r.Capabilities...)
	}
	if len(r.Policy.AllowedMimeTypes) > 0 {
		cpy.Policy.AllowedMimeTypes = append([]string(nil), r.Policy.AllowedMimeTypes...)
	}
	if r.RevokedAt != nil {
		t := *r.RevokedAt
		cpy.RevokedAt = &t
	}
	return &cpy
}
