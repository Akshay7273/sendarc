package engine

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sendbeam/desktop/internal/config"
	"github.com/sendbeam/engine/discovery"
	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/engine/wsclient"
	"github.com/sendbeam/wire"
)

// DeviceEventName is emitted to frontend whenever trusted devices or presence states update.
const DeviceEventName = "sendbeam:devices"

// TrustedDeviceView is the JSON-serializable representation of a paired device for the UI.
type TrustedDeviceView struct {
	DeviceID          string           `json:"deviceId"`
	LocalLabel        string           `json:"localLabel"`
	Fingerprint       string           `json:"fingerprint"`
	PublicKey         string           `json:"publicKey"`
	Status            string           `json:"status"` // "lan_direct" | "online" | "offline" | "revoked"
	Revoked           bool             `json:"revoked"`
	LastSeenAt        string           `json:"lastSeenAt"`
	FirstSeenAt       string           `json:"firstSeenAt"`
	Capabilities      []string         `json:"capabilities"`
	Policy            wire.TrustPolicy `json:"policy"`
	DirectEndpoint    string           `json:"directEndpoint,omitempty"`
}

type discoveredPeerInfo struct {
	ip        net.IP
	port      uint16
	lastSeen  time.Time
}

// DesktopSecretResolver manages encrypted/file-backed persistent pair secrets with 0600 permissions.
type DesktopSecretResolver struct {
	path string
	mu   sync.RWMutex
	data map[string]string // deviceID -> hex(k_pair)
}

func NewDesktopSecretResolver(path string) (*DesktopSecretResolver, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create secrets dir: %w", err)
	}

	r := &DesktopSecretResolver{
		path: path,
		data: make(map[string]string),
	}

	content, err := os.ReadFile(path)
	if err == nil && len(content) > 0 {
		_ = json.Unmarshal(content, &r.data)
	}
	return r, nil
}

func (r *DesktopSecretResolver) SetSecret(deviceID string, secret []byte) error {
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

func (r *DesktopSecretResolver) DeleteSecret(deviceID string) error {
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

func (r *DesktopSecretResolver) ResolvePairSecret(_ context.Context, deviceID, _ string) ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	hexStr, ok := r.data[deviceID]
	if !ok || len(hexStr) == 0 {
		return nil, errors.New("pair secret not found")
	}
	return hex.DecodeString(hexStr)
}

// DeviceService manages trusted device operations and background presence for the desktop UI.
type DeviceService struct {
	mu           sync.RWMutex
	emit         func(name string, data any)
	idMgr        *trust.IdentityManager
	store        trust.Store
	secrets      *DesktopSecretResolver
	coordinator  *trust.PairingCoordinator
	lanDiscovery *discovery.LanDiscoveryService
	activePeers  map[string]discoveredPeerInfo // deviceID -> info
	configDir    string
	cancel       context.CancelFunc
}

// NewDeviceService initializes the desktop device service.
func NewDeviceService(emit func(name string, data any), customConfigDir string) (*DeviceService, error) {
	dir := customConfigDir
	if dir == "" {
		userConfig, err := os.UserConfigDir()
		if err != nil {
			userConfig = "."
		}
		dir = filepath.Join(userConfig, config.AppDirName)
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create config dir: %w", err)
	}

	idPath := filepath.Join(dir, "identity.key")
	idMgr, err := trust.NewIdentityManager(idPath)
	if err != nil {
		return nil, fmt.Errorf("init identity manager: %w", err)
	}

	trustPath := filepath.Join(dir, "trust.json")
	trustStore, err := trust.NewFileTrustStore(trustPath)
	if err != nil {
		return nil, fmt.Errorf("init trust store: %w", err)
	}

	secretsPath := filepath.Join(dir, "secrets.json")
	secrets, err := NewDesktopSecretResolver(secretsPath)
	if err != nil {
		return nil, fmt.Errorf("init secret store: %w", err)
	}

	coordinator := trust.NewPairingCoordinator(idMgr, trustStore)

	ctx, cancel := context.WithCancel(context.Background())

	discCfg := discovery.Config{
		AdvertisePort:  53317,
		BeaconInterval: 3 * time.Second,
	}
	lanDiscovery := discovery.NewLanDiscoveryService(discCfg, trustStore, secrets)

	svc := &DeviceService{
		emit:         emit,
		idMgr:        idMgr,
		store:        trustStore,
		secrets:      secrets,
		coordinator:  coordinator,
		lanDiscovery: lanDiscovery,
		activePeers:  make(map[string]discoveredPeerInfo),
		configDir:    dir,
		cancel:       cancel,
	}

	lanDiscovery.OnPeerDiscovered(func(peer discovery.DiscoveredPeer) {
		svc.mu.Lock()
		svc.activePeers[peer.DeviceID] = discoveredPeerInfo{
			ip:       peer.IP,
			port:     peer.Port,
			lastSeen: time.Now().UTC(),
		}
		svc.mu.Unlock()
		svc.notifyDevicesChanged()
	})

	_ = lanDiscovery.Start(ctx)

	return svc, nil
}

// ListTrustedDevices returns all registered paired devices with honest status.
func (s *DeviceService) ListTrustedDevices() ([]TrustedDeviceView, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	devices, err := s.store.ListDevices(ctx)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now().UTC()
	views := make([]TrustedDeviceView, 0, len(devices))

	for _, dev := range devices {
		status := "offline"
		var directEndpoint string

		if dev.Revoked {
			status = "revoked"
		} else if peer, ok := s.activePeers[dev.DeviceID]; ok && now.Sub(peer.lastSeen) < 30*time.Second {
			status = "lan_direct"
			directEndpoint = fmt.Sprintf("%s:%d", peer.ip.String(), peer.port)
		} else if !dev.LastSeenAt.IsZero() && now.Sub(dev.LastSeenAt) < 15*time.Minute {
			status = "online"
		}

		lastSeen := "never"
		if !dev.LastSeenAt.IsZero() {
			lastSeen = dev.LastSeenAt.UTC().Format(time.RFC3339)
		}

		views = append(views, TrustedDeviceView{
			DeviceID:       dev.DeviceID,
			LocalLabel:     dev.LocalLabel,
			Fingerprint:    dev.Fingerprint(),
			PublicKey:      dev.PublicKey,
			Status:         status,
			Revoked:        dev.Revoked,
			LastSeenAt:     lastSeen,
			FirstSeenAt:    dev.FirstSeenAt.UTC().Format(time.RFC3339),
			Capabilities:   dev.Capabilities,
			Policy:         dev.Policy,
			DirectEndpoint: directEndpoint,
		})
	}
	return views, nil
}

// RenameDevice updates a device's local label in the trust database.
func (s *DeviceService) RenameDevice(deviceID string, newLabel string) error {
	trimmed := strings.TrimSpace(newLabel)
	if trimmed == "" {
		return errors.New("device name cannot be empty")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rec, err := s.store.GetDevice(ctx, deviceID)
	if err != nil {
		return err
	}

	rec.LocalLabel = trimmed
	if err := s.store.AddOrUpdateDevice(ctx, rec); err != nil {
		return err
	}

	s.notifyDevicesChanged()
	return nil
}

// UpdateDevicePolicy updates authorization and auto-accept safety policy.
func (s *DeviceService) UpdateDevicePolicy(deviceID string, policy wire.TrustPolicy) error {
	if policy.AutoAccept {
		if policy.AutoAcceptDestDir == "" {
			return errors.New("destination directory is required when auto-accept is enabled")
		}
		if !filepath.IsAbs(policy.AutoAcceptDestDir) {
			return errors.New("destination directory must be an absolute path")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.store.UpdatePolicy(ctx, deviceID, policy); err != nil {
		return err
	}

	s.notifyDevicesChanged()
	return nil
}

// UnpairDevice revokes or purges trust credentials for a device.
func (s *DeviceService) UnpairDevice(deviceID string, purge bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if purge {
		if err := s.store.UnpairDevice(ctx, deviceID); err != nil {
			return err
		}
		_ = s.secrets.DeleteSecret(deviceID)
	} else {
		if err := s.store.RevokeDevice(ctx, deviceID); err != nil {
			return err
		}
	}

	s.mu.Lock()
	delete(s.activePeers, deviceID)
	s.mu.Unlock()

	s.notifyDevicesChanged()
	return nil
}

// PairDevice joins a pairing room with the given invite code and completes mutual device pairing.
func (s *DeviceService) PairDevice(serverURL, inviteCode, customLabel string, autoAccept bool, destDir string) (*TrustedDeviceView, error) {
	if inviteCode == "" {
		return nil, errors.New("invite code is required")
	}
	server := serverURL
	if server == "" {
		server = DefaultServer
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "Desktop Device"
	}
	if customLabel != "" {
		hostname = customLabel
	}

	opts := rendezvous.Options{
		Role: wire.RoleJoiner,
		Code: inviteCode,
	}

	dopts := wsclient.DialOptions{
		InsecureSkipVerify: true,
	}

	res, err := wsclient.Rendezvous(ctx, server, dopts, opts)
	if err != nil {
		return nil, fmt.Errorf("pairing handshake failed: %w", err)
	}

	a2b := make(chan []byte, 4)
	b2a := make(chan []byte, 4)
	transport := &desktopPairingTransport{in: a2b, out: b2a}

	cfg := trust.PairingSessionConfig{
		DeviceName:   hostname,
		Capabilities: []string{"transfer.v1", "transfer.v2", "lan_direct"},
		MasterKey:    res.Master,
		AutoAccept:   autoAccept,
		DestDir:      destDir,
	}

	pairResult, err := s.coordinator.AcceptPairing(ctx, transport, cfg)
	if err != nil {
		return nil, fmt.Errorf("pairing ceremony failed: %w", err)
	}

	if err := s.secrets.SetSecret(pairResult.PeerRecord.DeviceID, pairResult.KPair); err != nil {
		return nil, fmt.Errorf("persist secret: %w", err)
	}

	s.notifyDevicesChanged()

	pubBytes, _ := hex.DecodeString(pairResult.PeerRecord.PublicKey)
	fp := wire.FormatFingerprint(pubBytes)

	return &TrustedDeviceView{
		DeviceID:     pairResult.PeerRecord.DeviceID,
		LocalLabel:   pairResult.PeerRecord.LocalLabel,
		Fingerprint:  fp,
		PublicKey:    pairResult.PeerRecord.PublicKey,
		Status:       "online",
		Revoked:      false,
		LastSeenAt:   time.Now().UTC().Format(time.RFC3339),
		FirstSeenAt:  pairResult.PeerRecord.FirstSeenAt.UTC().Format(time.RFC3339),
		Capabilities: pairResult.PeerRecord.Capabilities,
		Policy:       pairResult.PeerRecord.Policy,
	}, nil
}

func (s *DeviceService) notifyDevicesChanged() {
	if s.emit == nil {
		return
	}
	devices, err := s.ListTrustedDevices()
	if err == nil {
		s.emit(DeviceEventName, devices)
	}
}

// Close gracefully stops the device service.
func (s *DeviceService) Close() {
	if s.cancel != nil {
		s.cancel()
	}
}

type desktopPairingTransport struct {
	in  <-chan []byte
	out chan<- []byte
}

func (t *desktopPairingTransport) SendMessage(ctx context.Context, data []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case t.out <- data:
		return nil
	}
}

func (t *desktopPairingTransport) ReceiveMessage(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case data, ok := <-t.in:
		if !ok {
			return nil, errors.New("pairing transport closed")
		}
		return data, nil
	}
}
