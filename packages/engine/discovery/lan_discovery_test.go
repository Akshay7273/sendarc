package discovery

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// pipePacketConn is an in-memory bi-directional PacketConn for testing.
type pipePacketConn struct {
	localAddr net.Addr
	peer      *pipePacketConn
	incoming  chan packet
	closed    chan struct{}
	once      sync.Once
}

type packet struct {
	data []byte
	addr net.Addr
}

func newPipePacketPair() (*pipePacketConn, *pipePacketConn) {
	addrA := &net.UDPAddr{IP: net.ParseIP("192.168.1.10"), Port: 53317}
	addrB := &net.UDPAddr{IP: net.ParseIP("192.168.1.20"), Port: 53317}

	a := &pipePacketConn{
		localAddr: addrA,
		incoming:  make(chan packet, 32),
		closed:    make(chan struct{}),
	}
	b := &pipePacketConn{
		localAddr: addrB,
		incoming:  make(chan packet, 32),
		closed:    make(chan struct{}),
	}
	a.peer = b
	b.peer = a
	return a, b
}

func (p *pipePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case <-p.closed:
		return 0, nil, net.ErrClosed
	case pkt, ok := <-p.incoming:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n := copy(b, pkt.data)
		return n, pkt.addr, nil
	}
}

func (p *pipePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
	}
	data := append([]byte(nil), b...)
	if p.peer != nil {
		select {
		case p.peer.incoming <- packet{data: data, addr: p.localAddr}:
		default:
		}
	}
	return len(b), nil
}

func (p *pipePacketConn) Close() error {
	p.once.Do(func() {
		close(p.closed)
	})
	return nil
}

func (p *pipePacketConn) LocalAddr() net.Addr                { return p.localAddr }
func (p *pipePacketConn) SetDeadline(_ time.Time) error      { return nil }
func (p *pipePacketConn) SetReadDeadline(_ time.Time) error  { return nil }
func (p *pipePacketConn) SetWriteDeadline(_ time.Time) error { return nil }

func TestLanDiscoveryEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	tmpDirA := t.TempDir()
	tmpDirB := t.TempDir()

	storeA, _ := trust.NewFileTrustStore(filepath.Join(tmpDirA, "alice-trust.json"))
	storeB, _ := trust.NewFileTrustStore(filepath.Join(tmpDirB, "bob-trust.json"))

	resA := trust.NewMemorySecretResolver()
	resB := trust.NewMemorySecretResolver()

	kPair := sha256.Sum256([]byte("shared-k-pair-lan-discovery-test"))
	hCred := sha256.Sum256(kPair[:])
	credRef := "cred-" + hex.EncodeToString(hCred[:])

	pubA, _, _ := ed25519.GenerateKey(nil)
	pubB, _, _ := ed25519.GenerateKey(nil)

	devAlice := wire.DeriveDeviceID(pubA)
	devBob := wire.DeriveDeviceID(pubB)

	now := time.Now().UTC()
	errA := storeA.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          devBob,
		PublicKey:         hex.EncodeToString(pubB),
		LocalLabel:        "Bob",
		PairCredentialRef: credRef,
		FirstSeenAt:       now,
		LastSeenAt:        now,
		Policy:            wire.DefaultTrustPolicy(),
	})
	if errA != nil {
		t.Fatalf("storeA AddOrUpdateDevice: %v", errA)
	}
	resA.SetSecret(devBob, kPair[:])

	errB := storeB.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          devAlice,
		PublicKey:         hex.EncodeToString(pubA),
		LocalLabel:        "Alice",
		PairCredentialRef: credRef,
		FirstSeenAt:       now,
		LastSeenAt:        now,
		Policy:            wire.DefaultTrustPolicy(),
	})
	if errB != nil {
		t.Fatalf("storeB AddOrUpdateDevice: %v", errB)
	}
	resB.SetSecret(devAlice, kPair[:])

	connA, connB := newPipePacketPair()

	cfgA := Config{
		AdvertisePort:  8081,
		BeaconInterval: 100 * time.Millisecond,
		EpochWindow:    15 * time.Minute,
	}
	cfgB := Config{
		AdvertisePort:  8082,
		BeaconInterval: 100 * time.Millisecond,
		EpochWindow:    15 * time.Minute,
	}

	serviceA := NewLanDiscoveryService(cfgA, storeA, resA)
	serviceA.SetPacketConn(connA)

	serviceB := NewLanDiscoveryService(cfgB, storeB, resB)
	serviceB.SetPacketConn(connB)

	discoveredChA := make(chan DiscoveredPeer, 4)
	serviceA.OnPeerDiscovered(func(p DiscoveredPeer) {
		discoveredChA <- p
	})

	discoveredChB := make(chan DiscoveredPeer, 4)
	serviceB.OnPeerDiscovered(func(p DiscoveredPeer) {
		discoveredChB <- p
	})

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_ = serviceA.Start(ctx)
	}()

	go func() {
		defer wg.Done()
		_ = serviceB.Start(ctx)
	}()

	// Wait for mutual discovery
	select {
	case peer := <-discoveredChA:
		if peer.DeviceID != devBob {
			t.Errorf("Alice discovered wrong peer: %v", peer.DeviceID)
		}
		if peer.Port != 8082 {
			t.Errorf("Alice discovered wrong port: %v", peer.Port)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for Alice to discover Bob")
	}

	select {
	case peer := <-discoveredChB:
		if peer.DeviceID != devAlice {
			t.Errorf("Bob discovered wrong peer: %v", peer.DeviceID)
		}
		if peer.Port != 8081 {
			t.Errorf("Bob discovered wrong port: %v", peer.Port)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for Bob to discover Alice")
	}

	cancel()
	_ = connA.Close()
	_ = connB.Close()
	wg.Wait()
}
