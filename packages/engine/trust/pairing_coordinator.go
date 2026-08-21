// Package trust manages local device cryptographic identity and paired device trust records.
package trust

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sendbeam/wire"
)

var (
	// ErrKeyConflict indicates that a pairing peer presents a conflicting public key for an existing device ID.
	ErrKeyConflict = errors.New("pairing key conflict: device ID matches an existing record with a different public key")

	// ErrLabelConflict indicates that a different active device already uses the requested local display name.
	ErrLabelConflict = errors.New("pairing conflict: a different trusted device already uses this name")
)

// PairingTransport abstracts sending and receiving pairing message payloads over an authenticated channel.
type PairingTransport interface {
	SendMessage(ctx context.Context, data []byte) error
	ReceiveMessage(ctx context.Context) ([]byte, error)
}

// PairingSessionConfig specifies options for a pairing ceremony.
type PairingSessionConfig struct {
	DeviceName   string
	Capabilities []string
	MasterKey    []byte
	AutoAccept   bool
	DestDir      string
}

// PairingResult contains the established trust record and secret pairwise credential.
type PairingResult struct {
	PeerRecord *wire.TrustRecord
	KPair      []byte
	CredRef    string
}

// PairingCoordinator drives the multi-step pairing ceremony on both initiator and responder sides.
type PairingCoordinator struct {
	idMgr *IdentityManager
	store Store
}

// NewPairingCoordinator creates a new PairingCoordinator.
func NewPairingCoordinator(idMgr *IdentityManager, store Store) *PairingCoordinator {
	return &PairingCoordinator{
		idMgr: idMgr,
		store: store,
	}
}

// InitiatePairing executes the initiator role of the pairing ceremony.
func (p *PairingCoordinator) InitiatePairing(ctx context.Context, transport PairingTransport, cfg PairingSessionConfig) (*PairingResult, error) {
	if transport == nil {
		return nil, errors.New("pairing transport required")
	}
	if len(cfg.MasterKey) == 0 {
		return nil, errors.New("master key required")
	}

	id, err := p.idMgr.GetOrCreateIdentity()
	if err != nil {
		return nil, fmt.Errorf("get local identity: %w", err)
	}

	// 1. Create and send PairingRequest
	req, err := wire.NewPairingRequest(id, cfg.DeviceName, cfg.Capabilities, cfg.MasterKey, nil)
	if err != nil {
		return nil, fmt.Errorf("create pairing request: %w", err)
	}

	reqData, err := wire.EncodePairingMessage(req)
	if err != nil {
		return nil, fmt.Errorf("encode pairing request: %w", err)
	}

	if err := transport.SendMessage(ctx, reqData); err != nil {
		return nil, fmt.Errorf("send pairing request: %w", err)
	}

	// 2. Receive and verify PairingResponse
	respData, err := transport.ReceiveMessage(ctx)
	if err != nil {
		return nil, fmt.Errorf("receive pairing response: %w", err)
	}

	respMsg, err := wire.DecodePairingMessage(respData)
	if err != nil {
		return nil, fmt.Errorf("decode pairing response: %w", err)
	}

	resp, ok := respMsg.(*wire.PairingResponse)
	if !ok {
		return nil, errors.New("expected pairing response message")
	}

	reqNonce, _ := hex.DecodeString(req.Nonce)
	peerPub, respNonce, err := wire.VerifyPairingResponse(resp, reqNonce, cfg.MasterKey)
	if err != nil {
		return nil, fmt.Errorf("verify pairing response: %w", err)
	}

	// 3. Derive pairwise credential
	kPair, credRef, err := wire.DerivePairCredential(cfg.MasterKey, reqNonce, respNonce, id.PublicKey, peerPub)
	if err != nil {
		return nil, fmt.Errorf("derive pair credential: %w", err)
	}

	// 4. Verify no key or label conflict in trust store
	if err := p.checkConflict(ctx, resp.DeviceID, resp.DeviceName, peerPub); err != nil {
		_ = p.sendRejection(ctx, transport)
		return nil, err
	}

	// 5. Send and receive PairingConfirm
	confirm := wire.NewPairingConfirm(kPair, resp.DeviceID, true)
	confData, err := wire.EncodePairingMessage(confirm)
	if err != nil {
		return nil, fmt.Errorf("encode pairing confirm: %w", err)
	}

	if err := transport.SendMessage(ctx, confData); err != nil {
		return nil, fmt.Errorf("send pairing confirm: %w", err)
	}

	peerConfData, err := transport.ReceiveMessage(ctx)
	if err != nil {
		return nil, fmt.Errorf("receive peer pairing confirm: %w", err)
	}

	peerConfMsg, err := wire.DecodePairingMessage(peerConfData)
	if err != nil {
		return nil, fmt.Errorf("decode peer pairing confirm: %w", err)
	}

	peerConf, ok := peerConfMsg.(*wire.PairingConfirm)
	if !ok {
		return nil, errors.New("expected pairing confirm message")
	}

	if err := wire.VerifyPairingConfirm(peerConf, kPair, id.DeviceID); err != nil {
		return nil, fmt.Errorf("verify peer pairing confirm: %w", err)
	}

	// 6. Record peer in local trust store
	now := time.Now().UTC()
	policy := wire.DefaultTrustPolicy()
	if cfg.AutoAccept && cfg.DestDir != "" {
		policy.AutoAccept = true
		policy.AutoAcceptDestDir = cfg.DestDir
	}

	record := &wire.TrustRecord{
		DeviceID:          resp.DeviceID,
		PublicKey:         hex.EncodeToString(peerPub),
		LocalLabel:        resp.DeviceName,
		PairCredentialRef: credRef,
		Capabilities:      resp.Capabilities,
		FirstSeenAt:       now,
		LastSeenAt:        now,
		Revoked:           false,
		RevokedAt:         nil,
		Policy:            policy,
	}

	if err := p.store.AddOrUpdateDevice(ctx, record); err != nil {
		return nil, fmt.Errorf("save trusted device: %w", err)
	}

	return &PairingResult{
		PeerRecord: record,
		KPair:      kPair,
		CredRef:    credRef,
	}, nil
}

// AcceptPairing executes the responder role of the pairing ceremony.
func (p *PairingCoordinator) AcceptPairing(ctx context.Context, transport PairingTransport, cfg PairingSessionConfig) (*PairingResult, error) {
	if transport == nil {
		return nil, errors.New("pairing transport required")
	}
	if len(cfg.MasterKey) == 0 {
		return nil, errors.New("master key required")
	}

	id, err := p.idMgr.GetOrCreateIdentity()
	if err != nil {
		return nil, fmt.Errorf("get local identity: %w", err)
	}

	// 1. Receive and verify PairingRequest
	reqData, err := transport.ReceiveMessage(ctx)
	if err != nil {
		return nil, fmt.Errorf("receive pairing request: %w", err)
	}

	reqMsg, err := wire.DecodePairingMessage(reqData)
	if err != nil {
		return nil, fmt.Errorf("decode pairing request: %w", err)
	}

	req, ok := reqMsg.(*wire.PairingRequest)
	if !ok {
		return nil, errors.New("expected pairing request message")
	}

	peerPub, reqNonce, err := wire.VerifyPairingRequest(req, cfg.MasterKey)
	if err != nil {
		return nil, fmt.Errorf("verify pairing request: %w", err)
	}

	// 2. Check no key or label conflict in trust store
	if err := p.checkConflict(ctx, req.DeviceID, req.DeviceName, peerPub); err != nil {
		_ = p.sendRejection(ctx, transport)
		return nil, err
	}

	// 3. Create and send PairingResponse
	resp, err := wire.NewPairingResponse(id, cfg.DeviceName, cfg.Capabilities, cfg.MasterKey, reqNonce, nil)
	if err != nil {
		return nil, fmt.Errorf("create pairing response: %w", err)
	}

	respData, err := wire.EncodePairingMessage(resp)
	if err != nil {
		return nil, fmt.Errorf("encode pairing response: %w", err)
	}

	if err := transport.SendMessage(ctx, respData); err != nil {
		return nil, fmt.Errorf("send pairing response: %w", err)
	}

	// 4. Derive pairwise credential
	respNonce, _ := hex.DecodeString(resp.Nonce)
	kPair, credRef, err := wire.DerivePairCredential(cfg.MasterKey, reqNonce, respNonce, peerPub, id.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("derive pair credential: %w", err)
	}

	// 5. Receive peer's PairingConfirm, then send ours
	peerConfData, err := transport.ReceiveMessage(ctx)
	if err != nil {
		return nil, fmt.Errorf("receive peer pairing confirm: %w", err)
	}

	peerConfMsg, err := wire.DecodePairingMessage(peerConfData)
	if err != nil {
		return nil, fmt.Errorf("decode peer pairing confirm: %w", err)
	}

	peerConf, ok := peerConfMsg.(*wire.PairingConfirm)
	if !ok {
		return nil, errors.New("expected pairing confirm message")
	}

	if err := wire.VerifyPairingConfirm(peerConf, kPair, id.DeviceID); err != nil {
		return nil, fmt.Errorf("verify peer pairing confirm: %w", err)
	}

	confirm := wire.NewPairingConfirm(kPair, req.DeviceID, true)
	confData, err := wire.EncodePairingMessage(confirm)
	if err != nil {
		return nil, fmt.Errorf("encode pairing confirm: %w", err)
	}

	if err := transport.SendMessage(ctx, confData); err != nil {
		return nil, fmt.Errorf("send pairing confirm: %w", err)
	}

	// 6. Record peer in local trust store
	now := time.Now().UTC()
	policy := wire.DefaultTrustPolicy()
	if cfg.AutoAccept && cfg.DestDir != "" {
		policy.AutoAccept = true
		policy.AutoAcceptDestDir = cfg.DestDir
	}

	record := &wire.TrustRecord{
		DeviceID:          req.DeviceID,
		PublicKey:         hex.EncodeToString(peerPub),
		LocalLabel:        req.DeviceName,
		PairCredentialRef: credRef,
		Capabilities:      req.Capabilities,
		FirstSeenAt:       now,
		LastSeenAt:        now,
		Revoked:           false,
		RevokedAt:         nil,
		Policy:            policy,
	}

	if err := p.store.AddOrUpdateDevice(ctx, record); err != nil {
		return nil, fmt.Errorf("save trusted device: %w", err)
	}

	return &PairingResult{
		PeerRecord: record,
		KPair:      kPair,
		CredRef:    credRef,
	}, nil
}

func (p *PairingCoordinator) checkConflict(ctx context.Context, deviceID, deviceName string, pubKey ed25519.PublicKey) error {
	existing, err := p.store.GetDevice(ctx, deviceID)
	if err == nil && existing != nil {
		existingPub, err := hex.DecodeString(existing.PublicKey)
		if err == nil && !bytes.Equal(existingPub, pubKey) {
			return ErrKeyConflict
		}
	} else if err != nil && !errors.Is(err, ErrDeviceNotFound) {
		return err
	}

	// Check for active trusted devices with the same label but different device ID
	list, err := p.store.ListDevices(ctx)
	if err != nil {
		return err
	}
	for _, rec := range list {
		if rec.DeviceID != deviceID && strings.EqualFold(rec.LocalLabel, deviceName) && !rec.Revoked {
			return ErrLabelConflict
		}
	}

	return nil
}

func (p *PairingCoordinator) sendRejection(ctx context.Context, transport PairingTransport) error {
	rej := &wire.PairingConfirm{
		Type:   wire.MsgPairingConfirm,
		Status: "rejected",
	}
	data, _ := wire.EncodePairingMessage(rej)
	return transport.SendMessage(ctx, data)
}
