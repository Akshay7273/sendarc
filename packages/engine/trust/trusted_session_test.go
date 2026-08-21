package trust

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sendbeam/wire"
)

func TestTrustedSessionCoordinatorEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tmpDirA := t.TempDir()
	tmpDirB := t.TempDir()

	idMgrA, _ := NewIdentityManager(filepath.Join(tmpDirA, "alice.key"))
	idMgrB, _ := NewIdentityManager(filepath.Join(tmpDirB, "bob.key"))

	idA, _ := idMgrA.GetOrCreateIdentity()
	idB, _ := idMgrB.GetOrCreateIdentity()

	storeA, _ := NewFileTrustStore(filepath.Join(tmpDirA, "alice-trust.json"))
	storeB, _ := NewFileTrustStore(filepath.Join(tmpDirB, "bob-trust.json"))

	kPair := sha256.Sum256([]byte("shared-k-pair-secret-for-session-test"))
	hCred := sha256.Sum256(kPair[:])
	credRef := "cred-" + hex.EncodeToString(hCred[:])

	resA := NewMemorySecretResolver()
	resA.SetSecret(idB.DeviceID, kPair[:])

	resB := NewMemorySecretResolver()
	resB.SetSecret(idA.DeviceID, kPair[:])

	now := time.Now().UTC().Add(-1 * time.Hour)

	_ = storeA.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          idB.DeviceID,
		PublicKey:         hex.EncodeToString(idB.PublicKey),
		LocalLabel:        "Bob Desktop",
		PairCredentialRef: credRef,
		Capabilities:      []string{"transfer.v1", "transfer.v2", "lan_direct"},
		FirstSeenAt:       now,
		LastSeenAt:        now,
		Policy:            wire.DefaultTrustPolicy(),
	})

	_ = storeB.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          idA.DeviceID,
		PublicKey:         hex.EncodeToString(idA.PublicKey),
		LocalLabel:        "Alice Laptop",
		PairCredentialRef: credRef,
		Capabilities:      []string{"transfer.v1", "transfer.v2", "auto_accept"},
		FirstSeenAt:       now,
		LastSeenAt:        now,
		Policy:            wire.DefaultTrustPolicy(),
	})

	coordA := NewTrustedSessionCoordinator(idMgrA, storeA, resA)
	coordB := NewTrustedSessionCoordinator(idMgrB, storeB, resB)

	transA, transB := makeLoopbackPair()

	var wg sync.WaitGroup
	wg.Add(2)

	var resInit *TrustedSessionResult
	var errInit error
	var resResp *TrustedSessionResult
	var errResp error

	go func() {
		defer wg.Done()
		resInit, errInit = coordA.InitiateTrustedSession(ctx, transA, TrustedSessionConfig{
			PeerDeviceID: idB.DeviceID,
			Capabilities: []string{"transfer.v1", "transfer.v2", "auto_accept"},
		})
	}()

	go func() {
		defer wg.Done()
		resResp, errResp = coordB.AcceptTrustedSession(ctx, transB, []string{"transfer.v1", "transfer.v2", "lan_direct"})
	}()

	wg.Wait()

	if errInit != nil {
		t.Fatalf("Alice InitiateTrustedSession error: %v", errInit)
	}
	if errResp != nil {
		t.Fatalf("Bob AcceptTrustedSession error: %v", errResp)
	}

	// Verify key schedule symmetry
	if !bytes.Equal(resInit.Keys.SessionMaster, resResp.Keys.SessionMaster) {
		t.Errorf("SessionMaster mismatch")
	}
	if !bytes.Equal(resInit.Keys.InitiatorToResponderKey, resResp.Keys.InitiatorToResponderKey) {
		t.Errorf("I2RKey mismatch")
	}
	if !bytes.Equal(resInit.Keys.ResponderToInitiatorKey, resResp.Keys.ResponderToInitiatorKey) {
		t.Errorf("R2IKey mismatch")
	}

	// Verify LastSeenAt updated in stores
	recA, _ := storeA.GetDevice(ctx, idB.DeviceID)
	if !recA.LastSeenAt.After(now) {
		t.Errorf("storeA LastSeenAt was not refreshed")
	}

	recB, _ := storeB.GetDevice(ctx, idA.DeviceID)
	if !recB.LastSeenAt.After(now) {
		t.Errorf("storeB LastSeenAt was not refreshed")
	}
}

func TestTrustedSessionRevocationRejection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tmpDirA := t.TempDir()
	tmpDirB := t.TempDir()

	idMgrA, _ := NewIdentityManager(filepath.Join(tmpDirA, "alice.key"))
	idMgrB, _ := NewIdentityManager(filepath.Join(tmpDirB, "bob.key"))

	idA, _ := idMgrA.GetOrCreateIdentity()
	idB, _ := idMgrB.GetOrCreateIdentity()

	storeA, _ := NewFileTrustStore(filepath.Join(tmpDirA, "alice-trust.json"))
	storeB, _ := NewFileTrustStore(filepath.Join(tmpDirB, "bob-trust.json"))

	kPair := sha256.Sum256([]byte("shared-k-pair-revocation-test"))
	hCred := sha256.Sum256(kPair[:])
	credRef := "cred-" + hex.EncodeToString(hCred[:])

	resA := NewMemorySecretResolver()
	resA.SetSecret(idB.DeviceID, kPair[:])
	resB := NewMemorySecretResolver()
	resB.SetSecret(idA.DeviceID, kPair[:])

	now := time.Now().UTC()

	_ = storeA.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          idB.DeviceID,
		PublicKey:         hex.EncodeToString(idB.PublicKey),
		LocalLabel:        "Bob Desktop",
		PairCredentialRef: credRef,
		Capabilities:      []string{"transfer.v1"},
		FirstSeenAt:       now,
		LastSeenAt:        now,
		Policy:            wire.DefaultTrustPolicy(),
	})

	// Bob has REVOKED Alice
	_ = storeB.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          idA.DeviceID,
		PublicKey:         hex.EncodeToString(idA.PublicKey),
		LocalLabel:        "Alice Laptop",
		PairCredentialRef: credRef,
		Capabilities:      []string{"transfer.v1"},
		FirstSeenAt:       now,
		LastSeenAt:        now,
		Revoked:           true,
		RevokedAt:         &now,
		Policy:            wire.DefaultTrustPolicy(),
	})

	coordA := NewTrustedSessionCoordinator(idMgrA, storeA, resA)
	coordB := NewTrustedSessionCoordinator(idMgrB, storeB, resB)

	transA, transB := makeLoopbackPair()

	var wg sync.WaitGroup
	wg.Add(2)

	var errInit, errResp error

	go func() {
		defer wg.Done()
		_, errInit = coordA.InitiateTrustedSession(ctx, transA, TrustedSessionConfig{
			PeerDeviceID: idB.DeviceID,
			Capabilities: []string{"transfer.v1"},
		})
	}()

	go func() {
		defer wg.Done()
		_, errResp = coordB.AcceptTrustedSession(ctx, transB, []string{"transfer.v1"})
	}()

	wg.Wait()

	if !errors.Is(errResp, wire.ErrTrustedPeerRevoked) {
		t.Errorf("expected Bob to return ErrTrustedPeerRevoked, got %v", errResp)
	}
	if !errors.Is(errInit, wire.ErrTrustedPeerRevoked) {
		t.Errorf("expected Alice to receive ErrTrustedPeerRevoked, got %v", errInit)
	}
}

func TestTrustedSessionUnknownPeerRejection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tmpDirA := t.TempDir()
	tmpDirB := t.TempDir()

	idMgrA, _ := NewIdentityManager(filepath.Join(tmpDirA, "alice.key"))
	idMgrB, _ := NewIdentityManager(filepath.Join(tmpDirB, "bob.key"))

	idB, _ := idMgrB.GetOrCreateIdentity()

	storeA, _ := NewFileTrustStore(filepath.Join(tmpDirA, "alice-trust.json"))
	storeB, _ := NewFileTrustStore(filepath.Join(tmpDirB, "bob-trust.json"))

	kPair := sha256.Sum256([]byte("shared-k-pair-unknown-test"))
	hCred := sha256.Sum256(kPair[:])
	credRef := "cred-" + hex.EncodeToString(hCred[:])

	resA := NewMemorySecretResolver()
	resA.SetSecret(idB.DeviceID, kPair[:])
	resB := NewMemorySecretResolver()

	now := time.Now().UTC()

	// Alice has Bob in store, but Bob DOES NOT have Alice in store
	_ = storeA.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          idB.DeviceID,
		PublicKey:         hex.EncodeToString(idB.PublicKey),
		LocalLabel:        "Bob Desktop",
		PairCredentialRef: credRef,
		Capabilities:      []string{"transfer.v1"},
		FirstSeenAt:       now,
		LastSeenAt:        now,
		Policy:            wire.DefaultTrustPolicy(),
	})

	coordA := NewTrustedSessionCoordinator(idMgrA, storeA, resA)
	coordB := NewTrustedSessionCoordinator(idMgrB, storeB, resB)

	transA, transB := makeLoopbackPair()

	var wg sync.WaitGroup
	wg.Add(2)

	var errInit, errResp error

	go func() {
		defer wg.Done()
		_, errInit = coordA.InitiateTrustedSession(ctx, transA, TrustedSessionConfig{
			PeerDeviceID: idB.DeviceID,
			Capabilities: []string{"transfer.v1"},
		})
	}()

	go func() {
		defer wg.Done()
		_, errResp = coordB.AcceptTrustedSession(ctx, transB, []string{"transfer.v1"})
	}()

	wg.Wait()

	if errResp == nil {
		t.Errorf("expected Bob to reject unknown peer")
	}
	if errInit == nil {
		t.Errorf("expected Alice to fail on rejected session")
	}
}
