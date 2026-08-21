// Package discovery implements privacy-preserving local network (LAN) peer discovery using blinded beacons.
package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// DiscoveredPeer represents a trusted paired peer discovered directly over LAN.
type DiscoveredPeer struct {
	DeviceID string
	IP       net.IP
	Port     uint16
	LastSeen time.Time
}

// Config defines options for the LAN discovery service.
type Config struct {
	ListenAddr     string
	BroadcastAddr  string
	AdvertisePort  uint16
	BeaconInterval time.Duration
	EpochWindow    time.Duration
}

// LanDiscoveryService broadcasts blinded beacons and discovers local paired peers.
type LanDiscoveryService struct {
	cfg      Config
	store    trust.Store
	resolver trust.SecretResolver

	mu       sync.RWMutex
	peers    map[string]*DiscoveredPeer
	handlers []func(peer DiscoveredPeer)

	conn   net.PacketConn
	isConnManaged bool
}

// NewLanDiscoveryService creates a new LanDiscoveryService.
func NewLanDiscoveryService(cfg Config, store trust.Store, resolver trust.SecretResolver) *LanDiscoveryService {
	if cfg.BeaconInterval <= 0 {
		cfg.BeaconInterval = 3 * time.Second
	}
	if cfg.EpochWindow <= 0 {
		cfg.EpochWindow = wire.DefaultLanBeaconEpochWindow
	}
	return &LanDiscoveryService{
		cfg:      cfg,
		store:    store,
		resolver: resolver,
		peers:    make(map[string]*DiscoveredPeer),
	}
}

// SetPacketConn overrides the UDP packet connection (useful for unit testing).
func (s *LanDiscoveryService) SetPacketConn(conn net.PacketConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conn = conn
	s.isConnManaged = false
}

// OnPeerDiscovered registers a callback invoked when a paired peer is seen on LAN.
func (s *LanDiscoveryService) OnPeerDiscovered(handler func(peer DiscoveredPeer)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers = append(s.handlers, handler)
}

// GetDiscoveredPeers returns a snapshot of currently discovered LAN peers.
func (s *LanDiscoveryService) GetDiscoveredPeers() []DiscoveredPeer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make([]DiscoveredPeer, 0, len(s.peers))
	for _, p := range s.peers {
		res = append(res, *p)
	}
	return res
}

// Start launches the background advertiser and listener routines.
func (s *LanDiscoveryService) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.conn == nil {
		listenAddr := s.cfg.ListenAddr
		if listenAddr == "" {
			listenAddr = fmt.Sprintf(":%d", wire.DefaultLanBeaconPort)
		}
		c, err := net.ListenPacket("udp4", listenAddr)
		if err != nil {
			s.mu.Unlock()
			return fmt.Errorf("listen udp: %w", err)
		}
		s.conn = c
		s.isConnManaged = true
	}
	conn := s.conn
	s.mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(2)

	// Listener loop
	go func() {
		defer wg.Done()
		s.listenLoop(ctx, conn)
	}()

	// Advertiser loop
	go func() {
		defer wg.Done()
		s.advertiseLoop(ctx, conn)
	}()

	<-ctx.Done()
	if s.isConnManaged && conn != nil {
		_ = conn.Close()
	}
	wg.Wait()
	return nil
}

func (s *LanDiscoveryService) listenLoop(ctx context.Context, conn net.PacketConn) {
	buf := make([]byte, 1024)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			continue
		}

		beacon, err := wire.DecodeLanBeacon(buf[:n])
		if err != nil {
			continue
		}

		var udpIP net.IP
		if udpAddr, ok := addr.(*net.UDPAddr); ok {
			udpIP = udpAddr.IP
		}

		s.processBeacon(ctx, beacon, udpIP)
	}
}

func (s *LanDiscoveryService) processBeacon(ctx context.Context, beacon *wire.LanBeacon, ip net.IP) {
	devices, err := s.store.ListDevices(ctx)
	if err != nil || len(devices) == 0 {
		return
	}

	localPairs := make(map[string][]byte, len(devices))
	for _, dev := range devices {
		if dev.Revoked {
			continue
		}
		kPair, err := s.resolver.ResolvePairSecret(ctx, dev.DeviceID, dev.PairCredentialRef)
		if err == nil && len(kPair) > 0 {
			localPairs[dev.DeviceID] = kPair
		}
	}

	now := time.Now().UTC()
	matched := wire.MatchLanBeacon(beacon, localPairs, now, s.cfg.EpochWindow)
	if len(matched) == 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, devID := range matched {
		peer := &DiscoveredPeer{
			DeviceID: devID,
			IP:       ip,
			Port:     beacon.Port,
			LastSeen: now,
		}
		s.peers[devID] = peer
		for _, h := range s.handlers {
			go h(*peer)
		}
	}
}

func (s *LanDiscoveryService) advertiseLoop(ctx context.Context, conn net.PacketConn) {
	ticker := time.NewTicker(s.cfg.BeaconInterval)
	defer ticker.Stop()

	// Initial send immediately
	s.sendBeacon(ctx, conn)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sendBeacon(ctx, conn)
		}
	}
}

func (s *LanDiscoveryService) sendBeacon(ctx context.Context, conn net.PacketConn) {
	devices, err := s.store.ListDevices(ctx)
	if err != nil || len(devices) == 0 {
		return
	}

	var kPairs [][]byte
	for _, dev := range devices {
		if dev.Revoked {
			continue
		}
		kPair, err := s.resolver.ResolvePairSecret(ctx, dev.DeviceID, dev.PairCredentialRef)
		if err == nil && len(kPair) > 0 {
			kPairs = append(kPairs, kPair)
		}
	}

	if len(kPairs) == 0 {
		return
	}

	now := time.Now().UTC()
	beacon, err := wire.NewLanBeacon(s.cfg.AdvertisePort, kPairs, now, s.cfg.EpochWindow)
	if err != nil {
		return
	}

	data, err := beacon.Encode()
	if err != nil {
		return
	}

	dstAddrStr := s.cfg.BroadcastAddr
	if dstAddrStr == "" {
		dstAddrStr = fmt.Sprintf("255.255.255.255:%d", wire.DefaultLanBeaconPort)
	}

	dst, err := net.ResolveUDPAddr("udp4", dstAddrStr)
	if err != nil {
		return
	}

	_, _ = conn.WriteTo(data, dst)
}
