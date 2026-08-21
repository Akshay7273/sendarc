package wire

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type TrustedSessionTestVector struct {
	Name             string   `json:"name"`
	KPairHex         string   `json:"k_pair_hex"`
	PairCredRef      string   `json:"pair_cred_ref"`
	InitSeedHex      string   `json:"init_seed_hex"`
	InitDeviceID     string   `json:"init_device_id"`
	InitPubKeyHex    string   `json:"init_pub_key_hex"`
	InitEphemPubHex  string   `json:"init_ephem_pub_hex"`
	InitNonceHex     string   `json:"init_nonce_hex"`
	InitCaps         []string `json:"init_caps"`
	InitTimestamp    string   `json:"init_timestamp"`
	InitSigHex       string   `json:"init_sig_hex"`
	InitAuthTagHex   string   `json:"init_auth_tag_hex"`
	RespSeedHex      string   `json:"resp_seed_hex"`
	RespDeviceID     string   `json:"resp_device_id"`
	RespPubKeyHex    string   `json:"resp_pub_key_hex"`
	RespEphemPubHex  string   `json:"resp_ephem_pub_hex"`
	RespNonceHex     string   `json:"resp_nonce_hex"`
	RespCaps         []string `json:"resp_caps"`
	RespSigHex       string   `json:"resp_sig_hex"`
	RespAuthTagHex   string   `json:"resp_auth_tag_hex"`
	SessionMasterHex string   `json:"session_master_hex"`
	I2RKeyHex        string   `json:"i2r_key_hex"`
	R2IKeyHex        string   `json:"r2i_key_hex"`
	InitConfirmTag   string   `json:"init_confirm_tag"`
	RespConfirmTag   string   `json:"resp_confirm_tag"`
}

func TestTrustedAuthEndToEnd(t *testing.T) {
	seedA := sha256.Sum256([]byte("seed-device-alice-trusted-v15"))
	seedB := sha256.Sum256([]byte("seed-device-bob-trusted-v15"))
	kPair := sha256.Sum256([]byte("shared-k-pair-secret-alice-bob"))
	hCred := sha256.Sum256(kPair[:])
	credRef := "cred-" + hex.EncodeToString(hCred[:])

	privA := ed25519.NewKeyFromSeed(seedA[:])
	pubA := privA.Public().(ed25519.PublicKey)
	idA, err := NewDeviceIdentity(pubA, privA)
	if err != nil {
		t.Fatalf("NewDeviceIdentity A: %v", err)
	}

	privB := ed25519.NewKeyFromSeed(seedB[:])
	pubB := privB.Public().(ed25519.PublicKey)
	idB, err := NewDeviceIdentity(pubB, privB)
	if err != nil {
		t.Fatalf("NewDeviceIdentity B: %v", err)
	}

	fixedTime, _ := time.Parse(time.RFC3339, "2026-08-21T12:00:00Z")

	ephemPubA := sha256.Sum256([]byte("ephem-alice-fixed-1"))
	nonceA := sha256.Sum256([]byte("nonce-alice-fixed-1"))

	ephemPubB := sha256.Sum256([]byte("ephem-bob-fixed-2"))
	nonceB := sha256.Sum256([]byte("nonce-bob-fixed-2"))

	capsA := []string{"transfer.v1", "transfer.v2", "auto_accept"}
	capsB := []string{"transfer.v1", "transfer.v2", "lan_direct"}

	// Alice creates TrustedAuthInit
	initMsg, err := NewTrustedAuthInit(idA, idB.DeviceID, credRef, kPair[:], capsA, ephemPubA[:], nonceA[:], fixedTime)
	if err != nil {
		t.Fatalf("NewTrustedAuthInit: %v", err)
	}

	// Bob verifies TrustedAuthInit
	ephemAVerified, nonceAVerified, err := VerifyTrustedAuthInit(initMsg, kPair[:], idA.PublicKey, idB.DeviceID, fixedTime)
	if err != nil {
		t.Fatalf("VerifyTrustedAuthInit: %v", err)
	}
	if hex.EncodeToString(ephemAVerified) != hex.EncodeToString(ephemPubA[:]) {
		t.Errorf("ephem A mismatch")
	}

	// Bob creates TrustedAuthResponse
	respMsg, err := NewTrustedAuthResponse(idB, initMsg, kPair[:], capsB, ephemPubB[:], nonceB[:])
	if err != nil {
		t.Fatalf("NewTrustedAuthResponse: %v", err)
	}

	// Alice verifies TrustedAuthResponse
	ephemBVerified, nonceBVerified, err := VerifyTrustedAuthResponse(respMsg, initMsg, kPair[:], idB.PublicKey, idA.DeviceID)
	if err != nil {
		t.Fatalf("VerifyTrustedAuthResponse: %v", err)
	}
	if hex.EncodeToString(ephemBVerified) != hex.EncodeToString(ephemPubB[:]) {
		t.Errorf("ephem B mismatch")
	}

	// Both derive directional session keys
	keysAlice, err := DeriveTrustedSessionKeys(kPair[:], ephemPubA[:], ephemBVerified, nonceA[:], nonceBVerified, idA.DeviceID, idB.DeviceID, capsA, respMsg.Capabilities)
	if err != nil {
		t.Fatalf("DeriveTrustedSessionKeys Alice: %v", err)
	}

	keysBob, err := DeriveTrustedSessionKeys(kPair[:], ephemAVerified, ephemPubB[:], nonceAVerified, nonceB[:], initMsg.InitiatorDeviceID, idB.DeviceID, initMsg.Capabilities, capsB)
	if err != nil {
		t.Fatalf("DeriveTrustedSessionKeys Bob: %v", err)
	}

	if hex.EncodeToString(keysAlice.SessionMaster) != hex.EncodeToString(keysBob.SessionMaster) {
		t.Errorf("SessionMaster mismatch")
	}
	if hex.EncodeToString(keysAlice.InitiatorToResponderKey) != hex.EncodeToString(keysBob.InitiatorToResponderKey) {
		t.Errorf("I2RKey mismatch")
	}
	if hex.EncodeToString(keysAlice.ResponderToInitiatorKey) != hex.EncodeToString(keysBob.ResponderToInitiatorKey) {
		t.Errorf("R2IKey mismatch")
	}

	// Confirmation handshake
	confirmAlice := NewTrustedAuthConfirm(keysAlice.SessionMaster, DomainTrustedConfirmInit, idA.DeviceID, true)
	if err := VerifyTrustedAuthConfirm(confirmAlice, keysBob.SessionMaster, DomainTrustedConfirmInit, idA.DeviceID); err != nil {
		t.Errorf("Bob failed to verify Alice confirm: %v", err)
	}

	confirmBob := NewTrustedAuthConfirm(keysBob.SessionMaster, DomainTrustedConfirmResp, idB.DeviceID, true)
	if err := VerifyTrustedAuthConfirm(confirmBob, keysAlice.SessionMaster, DomainTrustedConfirmResp, idB.DeviceID); err != nil {
		t.Errorf("Alice failed to verify Bob confirm: %v", err)
	}

	// Generate deterministic test vector
	vector := TrustedSessionTestVector{
		Name:             "alice_bob_trusted_session",
		KPairHex:         hex.EncodeToString(kPair[:]),
		PairCredRef:      credRef,
		InitSeedHex:      hex.EncodeToString(seedA[:]),
		InitDeviceID:     idA.DeviceID,
		InitPubKeyHex:    hex.EncodeToString(idA.PublicKey),
		InitEphemPubHex:  hex.EncodeToString(ephemPubA[:]),
		InitNonceHex:     hex.EncodeToString(nonceA[:]),
		InitCaps:         capsA,
		InitTimestamp:    initMsg.Timestamp,
		InitSigHex:       initMsg.Signature,
		InitAuthTagHex:   initMsg.AuthTag,
		RespSeedHex:      hex.EncodeToString(seedB[:]),
		RespDeviceID:     idB.DeviceID,
		RespPubKeyHex:    hex.EncodeToString(idB.PublicKey),
		RespEphemPubHex:  hex.EncodeToString(ephemPubB[:]),
		RespNonceHex:     hex.EncodeToString(nonceB[:]),
		RespCaps:         capsB,
		RespSigHex:       respMsg.Signature,
		RespAuthTagHex:   respMsg.AuthTag,
		SessionMasterHex: hex.EncodeToString(keysAlice.SessionMaster),
		I2RKeyHex:        hex.EncodeToString(keysAlice.InitiatorToResponderKey),
		R2IKeyHex:        hex.EncodeToString(keysAlice.ResponderToInitiatorKey),
		InitConfirmTag:   confirmAlice.AuthTag,
		RespConfirmTag:   confirmBob.AuthTag,
	}

	vecData, err := json.MarshalIndent([]TrustedSessionTestVector{vector}, "", "  ")
	if err != nil {
		t.Fatalf("marshal test vector: %v", err)
	}

	targetPath := filepath.Join("testdata", "trusted-session-vectors.json")
	if err := os.WriteFile(targetPath, vecData, 0644); err != nil {
		t.Fatalf("write trusted-session-vectors.json: %v", err)
	}
}

func TestTrustedAuthAdversarialRejections(t *testing.T) {
	seedA := sha256.Sum256([]byte("seed-device-alice-adv-t"))
	seedB := sha256.Sum256([]byte("seed-device-bob-adv-t"))
	kPair := sha256.Sum256([]byte("k-pair-adv-shared"))
	privA := ed25519.NewKeyFromSeed(seedA[:])
	privB := ed25519.NewKeyFromSeed(seedB[:])
	idA, _ := NewDeviceIdentity(privA.Public().(ed25519.PublicKey), privA)
	idB, _ := NewDeviceIdentity(privB.Public().(ed25519.PublicKey), privB)

	now := time.Now().UTC()
	initMsg, _ := NewTrustedAuthInit(idA, idB.DeviceID, "cred-ref", kPair[:], []string{"transfer.v1"}, nil, nil, now)

	// 1. Clock skew > 5 minutes
	expiredTime := now.Add(-10 * time.Minute)
	if _, _, err := VerifyTrustedAuthInit(initMsg, kPair[:], idA.PublicKey, idB.DeviceID, expiredTime); !errors.Is(err, ErrTrustedTimestampSkew) {
		t.Errorf("expected ErrTrustedTimestampSkew, got %v", err)
	}

	// 2. Peer mismatch
	if _, _, err := VerifyTrustedAuthInit(initMsg, kPair[:], idA.PublicKey, "sb-dev-wrong", now); !errors.Is(err, ErrTrustedPeerMismatch) {
		t.Errorf("expected ErrTrustedPeerMismatch on wrong responder, got %v", err)
	}

	// 3. Forged signature
	tamperedSig := *initMsg
	tamperedSig.Signature = hex.EncodeToString(make([]byte, 64))
	if _, _, err := VerifyTrustedAuthInit(&tamperedSig, kPair[:], idA.PublicKey, idB.DeviceID, now); !errors.Is(err, ErrTrustedSignatureFailed) {
		t.Errorf("expected ErrTrustedSignatureFailed, got %v", err)
	}

	// 4. Wrong k_pair fails signature challenge binding
	wrongKPair := sha256.Sum256([]byte("rogue-k-pair"))
	if _, _, err := VerifyTrustedAuthInit(initMsg, wrongKPair[:], idA.PublicKey, idB.DeviceID, now); !errors.Is(err, ErrTrustedSignatureFailed) {
		t.Errorf("expected ErrTrustedSignatureFailed on wrong k_pair, got %v", err)
	}

	// 5. Tampered AuthTag
	tamperedMAC := *initMsg
	tamperedMAC.AuthTag = hex.EncodeToString(make([]byte, 32))
	if _, _, err := VerifyTrustedAuthInit(&tamperedMAC, kPair[:], idA.PublicKey, idB.DeviceID, now); !errors.Is(err, ErrTrustedMACTagFailed) {
		t.Errorf("expected ErrTrustedMACTagFailed, got %v", err)
	}

	// 6. Revoked status in response
	respRevoked := &TrustedAuthResponse{
		Type:              MsgTrustedAuthResponse,
		ProtocolVersion:   TrustedAuthProtocolVersion,
		Status:            "revoked",
		ResponderDeviceID: idB.DeviceID,
	}
	if _, _, err := VerifyTrustedAuthResponse(respRevoked, initMsg, kPair[:], idB.PublicKey, idA.DeviceID); !errors.Is(err, ErrTrustedPeerRevoked) {
		t.Errorf("expected ErrTrustedPeerRevoked, got %v", err)
	}
}

func TestTrustedAuthCodec(t *testing.T) {
	init := &TrustedAuthInit{
		Type:              MsgTrustedAuthInit,
		ProtocolVersion:   TrustedAuthProtocolVersion,
		InitiatorDeviceID: "sb-dev-1111",
		ResponderDeviceID: "sb-dev-2222",
		PairCredentialRef: "cred-1234",
		EphemeralPub:      hex.EncodeToString(make([]byte, 32)),
		Nonce:             hex.EncodeToString(make([]byte, 32)),
		Capabilities:      []string{"transfer.v1"},
		Timestamp:         "2026-08-21T12:00:00Z",
		Signature:         hex.EncodeToString(make([]byte, 64)),
		AuthTag:           hex.EncodeToString(make([]byte, 32)),
	}

	data, err := EncodeTrustedAuthMessage(init)
	if err != nil {
		t.Fatalf("EncodeTrustedAuthMessage: %v", err)
	}

	decoded, err := DecodeTrustedAuthMessage(data)
	if err != nil {
		t.Fatalf("DecodeTrustedAuthMessage: %v", err)
	}

	initDecoded, ok := decoded.(*TrustedAuthInit)
	if !ok {
		t.Fatalf("expected *TrustedAuthInit, got %T", decoded)
	}
	if initDecoded.InitiatorDeviceID != init.InitiatorDeviceID {
		t.Errorf("initiator device id mismatch")
	}
}
