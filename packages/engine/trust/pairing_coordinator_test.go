package trust

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sendbeam/wire"
)

type loopbackTransport struct {
	in  <-chan []byte
	out chan<- []byte
}

func (l *loopbackTransport) SendMessage(ctx context.Context, data []byte) error {
	select {
	case l.out <- data:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *loopbackTransport) ReceiveMessage(ctx context.Context) ([]byte, error) {
	select {
	case data, ok := <-l.in:
		if !ok {
			return nil, errors.New("channel closed")
		}
		return data, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func makeLoopbackPair() (PairingTransport, PairingTransport) {
	a2b := make(chan []byte, 8)
	b2a := make(chan []byte, 8)
	tA := &loopbackTransport{in: b2a, out: a2b}
	tB := &loopbackTransport{in: a2b, out: b2a}
	return tA, tB
}

func TestPairingCoordinatorEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tmpDirA := t.TempDir()
	tmpDirB := t.TempDir()

	idMgrA, err := NewIdentityManager(filepath.Join(tmpDirA, "alice.key"))
	if err != nil {
		t.Fatalf("NewIdentityManager A: %v", err)
	}
	storeA, err := NewFileTrustStore(filepath.Join(tmpDirA, "alice-trust.json"))
	if err != nil {
		t.Fatalf("NewFileTrustStore A: %v", err)
	}

	idMgrB, err := NewIdentityManager(filepath.Join(tmpDirB, "bob.key"))
	if err != nil {
		t.Fatalf("NewIdentityManager B: %v", err)
	}
	storeB, err := NewFileTrustStore(filepath.Join(tmpDirB, "bob-trust.json"))
	if err != nil {
		t.Fatalf("NewFileTrustStore B: %v", err)
	}

	coordA := NewPairingCoordinator(idMgrA, storeA)
	coordB := NewPairingCoordinator(idMgrB, storeB)

	masterKey := sha256.Sum256([]byte("spake2-master-key-shared"))
	transA, transB := makeLoopbackPair()

	cfgA := PairingSessionConfig{
		DeviceName:   "Alice MacBook Pro",
		Capabilities: []string{"transfer.v1", "auto_accept"},
		MasterKey:    masterKey[:],
		AutoAccept:   true,
		DestDir:      "/tmp/sendbeam-alice-downloads",
	}

	cfgB := PairingSessionConfig{
		DeviceName:   "Bob Linux Desktop",
		Capabilities: []string{"transfer.v1", "lan_direct"},
		MasterKey:    masterKey[:],
		AutoAccept:   false,
	}

	resAChan := make(chan *PairingResult, 1)
	errAChan := make(chan error, 1)
	resBChan := make(chan *PairingResult, 1)
	errBChan := make(chan error, 1)

	go func() {
		res, err := coordA.InitiatePairing(ctx, transA, cfgA)
		if err != nil {
			errAChan <- err
			return
		}
		resAChan <- res
	}()

	go func() {
		res, err := coordB.AcceptPairing(ctx, transB, cfgB)
		if err != nil {
			errBChan <- err
			return
		}
		resBChan <- res
	}()

	var resA, resB *PairingResult
	select {
	case err := <-errAChan:
		t.Fatalf("Alice InitiatePairing error: %v", err)
	case resA = <-resAChan:
	}

	select {
	case err := <-errBChan:
		t.Fatalf("Bob AcceptPairing error: %v", err)
	case resB = <-resBChan:
	}

	// Verify derived secret symmetry
	if !bytes.Equal(resA.KPair, resB.KPair) {
		t.Errorf("k_pair mismatch between Alice and Bob")
	}
	if resA.CredRef != resB.CredRef {
		t.Errorf("credRef mismatch: %s vs %s", resA.CredRef, resB.CredRef)
	}

	// Verify Alice's store records Bob
	recInA, err := storeA.GetDevice(ctx, resA.PeerRecord.DeviceID)
	if err != nil {
		t.Fatalf("storeA GetDevice: %v", err)
	}
	if recInA.LocalLabel != "Bob Linux Desktop" {
		t.Errorf("expected Bob's label in Alice's store, got %s", recInA.LocalLabel)
	}
	if !recInA.Policy.AutoAccept {
		t.Errorf("expected auto-accept policy set on Alice")
	}
	if !storeA.IsTrusted(ctx, recInA.DeviceID) {
		t.Errorf("expected Bob to be trusted in storeA")
	}

	// Verify Bob's store records Alice
	recInB, err := storeB.GetDevice(ctx, resB.PeerRecord.DeviceID)
	if err != nil {
		t.Fatalf("storeB GetDevice: %v", err)
	}
	if recInB.LocalLabel != "Alice MacBook Pro" {
		t.Errorf("expected Alice's label in Bob's store, got %s", recInB.LocalLabel)
	}
	if !storeB.IsTrusted(ctx, recInB.DeviceID) {
		t.Errorf("expected Alice to be trusted in storeB")
	}

	// Re-pairing with updated label succeeds and updates store
	cfgA2 := cfgA
	cfgA2.DeviceName = "Alice M3 Max"
	transA2, transB2 := makeLoopbackPair()

	var wg sync.WaitGroup
	wg.Add(2)
	var resB2 *PairingResult
	var errB2 error

	go func() {
		defer wg.Done()
		_, _ = coordA.InitiatePairing(ctx, transA2, cfgA2)
	}()
	go func() {
		defer wg.Done()
		resB2, errB2 = coordB.AcceptPairing(ctx, transB2, cfgB)
	}()
	wg.Wait()

	if errB2 != nil {
		t.Fatalf("re-pairing failed: %v", errB2)
	}
	if resB2.PeerRecord.LocalLabel != "Alice M3 Max" {
		t.Errorf("re-pairing did not update label: %s", resB2.PeerRecord.LocalLabel)
	}
}

func TestPairingCoordinatorLabelConflictRefusal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tmpDirA := t.TempDir()
	tmpDirB := t.TempDir()

	idMgrA, _ := NewIdentityManager(filepath.Join(tmpDirA, "alice.key"))
	storeA, _ := NewFileTrustStore(filepath.Join(tmpDirA, "alice-trust.json"))

	// Prepopulate storeB with an existing trusted device named "Alice Laptop" with a different key
	roguePub, _, _ := ed25519.GenerateKey(nil)
	rogueID := wire.DeriveDeviceID(roguePub)
	storeB, _ := NewFileTrustStore(filepath.Join(tmpDirB, "bob-trust.json"))
	_ = storeB.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          rogueID,
		PublicKey:         hex.EncodeToString(roguePub),
		LocalLabel:        "Alice Laptop",
		PairCredentialRef: "cred-rogue",
		Capabilities:      []string{"transfer.v1"},
		FirstSeenAt:       time.Now().UTC(),
		LastSeenAt:        time.Now().UTC(),
		Policy:            wire.DefaultTrustPolicy(),
	})

	idMgrB, _ := NewIdentityManager(filepath.Join(tmpDirB, "bob.key"))
	coordA := NewPairingCoordinator(idMgrA, storeA)
	coordB := NewPairingCoordinator(idMgrB, storeB)

	masterKey := sha256.Sum256([]byte("spake2-master-key-shared"))
	transA, transB := makeLoopbackPair()

	errChanB := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = coordA.InitiatePairing(ctx, transA, PairingSessionConfig{
			DeviceName:   "Alice Laptop",
			Capabilities: []string{"transfer.v1"},
			MasterKey:    masterKey[:],
		})
	}()

	go func() {
		defer wg.Done()
		_, err := coordB.AcceptPairing(ctx, transB, PairingSessionConfig{
			DeviceName:   "Bob",
			Capabilities: []string{"transfer.v1"},
			MasterKey:    masterKey[:],
		})
		errChanB <- err
	}()

	select {
	case err := <-errChanB:
		if !errors.Is(err, ErrLabelConflict) {
			t.Fatalf("expected ErrLabelConflict, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for conflict rejection")
	}

	wg.Wait()

	// Verify Bob's store retained the original device
	stored, err := storeB.GetDevice(ctx, rogueID)
	if err != nil {
		t.Fatalf("storeB GetDevice: %v", err)
	}
	if stored.LocalLabel != "Alice Laptop" {
		t.Errorf("store was corrupted after rejected pairing")
	}
}
