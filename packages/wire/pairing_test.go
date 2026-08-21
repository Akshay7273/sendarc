package wire

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type PairingTestVector struct {
	Name             string   `json:"name"`
	MasterKeyHex     string   `json:"master_key_hex"`
	ReqSeedHex       string   `json:"req_seed_hex"`
	ReqDeviceID      string   `json:"req_device_id"`
	ReqPubKeyHex     string   `json:"req_pub_key_hex"`
	ReqName          string   `json:"req_name"`
	ReqCaps          []string `json:"req_caps"`
	ReqNonceHex      string   `json:"req_nonce_hex"`
	ReqSigHex        string   `json:"req_sig_hex"`
	RespSeedHex      string   `json:"resp_seed_hex"`
	RespDeviceID     string   `json:"resp_device_id"`
	RespPubKeyHex    string   `json:"resp_pub_key_hex"`
	RespName         string   `json:"resp_name"`
	RespCaps         []string `json:"resp_caps"`
	RespNonceHex     string   `json:"resp_nonce_hex"`
	RespSigHex       string   `json:"resp_sig_hex"`
	KPairHex         string   `json:"k_pair_hex"`
	PairCredRef      string   `json:"pair_cred_ref"`
	ReqConfirmTag    string   `json:"req_confirm_tag"`
	RespConfirmTag   string   `json:"resp_confirm_tag"`
}

func TestPairingCeremonyEndToEnd(t *testing.T) {
	// Deterministic seeds for test vectors
	seedA := sha256.Sum256([]byte("seed-device-alice-v15"))
	seedB := sha256.Sum256([]byte("seed-device-bob-v15"))
	masterKey := sha256.Sum256([]byte("session-master-key-spake2"))

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

	nonceA := sha256.Sum256([]byte("nonce-alice-fixed-1"))
	nonceB := sha256.Sum256([]byte("nonce-bob-fixed-2"))

	// Alice creates request
	req, err := NewPairingRequest(idA, "Alice Laptop", []string{"transfer.v1", "auto_accept"}, masterKey[:], nonceA[:])
	if err != nil {
		t.Fatalf("NewPairingRequest: %v", err)
	}

	// Bob verifies Alice's request
	pubAVerified, nonceAVerified, err := VerifyPairingRequest(req, masterKey[:])
	if err != nil {
		t.Fatalf("VerifyPairingRequest: %v", err)
	}
	if hex.EncodeToString(pubAVerified) != hex.EncodeToString(idA.PublicKey) {
		t.Errorf("verified pubkey mismatch")
	}

	// Bob creates response
	resp, err := NewPairingResponse(idB, "Bob Phone", []string{"transfer.v1", "lan_direct"}, masterKey[:], nonceAVerified, nonceB[:])
	if err != nil {
		t.Fatalf("NewPairingResponse: %v", err)
	}

	// Alice verifies Bob's response
	pubBVerified, nonceBVerified, err := VerifyPairingResponse(resp, nonceA[:], masterKey[:])
	if err != nil {
		t.Fatalf("VerifyPairingResponse: %v", err)
	}
	if hex.EncodeToString(pubBVerified) != hex.EncodeToString(idB.PublicKey) {
		t.Errorf("verified pubkey mismatch")
	}

	// Both derive k_pair
	kPairAlice, credRefAlice, err := DerivePairCredential(masterKey[:], nonceA[:], nonceBVerified, idA.PublicKey, pubBVerified)
	if err != nil {
		t.Fatalf("DerivePairCredential Alice: %v", err)
	}

	kPairBob, credRefBob, err := DerivePairCredential(masterKey[:], nonceAVerified, nonceB[:], pubAVerified, idB.PublicKey)
	if err != nil {
		t.Fatalf("DerivePairCredential Bob: %v", err)
	}

	if hex.EncodeToString(kPairAlice) != hex.EncodeToString(kPairBob) {
		t.Errorf("k_pair mismatch between Alice and Bob")
	}
	if credRefAlice != credRefBob {
		t.Errorf("credRef mismatch between Alice and Bob: %s vs %s", credRefAlice, credRefBob)
	}

	// Confirmation exchange
	confirmAlice := NewPairingConfirm(kPairAlice, idB.DeviceID, true)
	if err := VerifyPairingConfirm(confirmAlice, kPairBob, idB.DeviceID); err != nil {
		t.Errorf("Bob failed to verify Alice's confirm: %v", err)
	}

	confirmBob := NewPairingConfirm(kPairBob, idA.DeviceID, true)
	if err := VerifyPairingConfirm(confirmBob, kPairAlice, idA.DeviceID); err != nil {
		t.Errorf("Alice failed to verify Bob's confirm: %v", err)
	}

	// Generate pairing test vector file
	vector := PairingTestVector{
		Name:           "alice_bob_standard_pairing",
		MasterKeyHex:   hex.EncodeToString(masterKey[:]),
		ReqSeedHex:     hex.EncodeToString(seedA[:]),
		ReqDeviceID:    idA.DeviceID,
		ReqPubKeyHex:   hex.EncodeToString(idA.PublicKey),
		ReqName:        "Alice Laptop",
		ReqCaps:        []string{"transfer.v1", "auto_accept"},
		ReqNonceHex:    hex.EncodeToString(nonceA[:]),
		ReqSigHex:      req.Signature,
		RespSeedHex:    hex.EncodeToString(seedB[:]),
		RespDeviceID:   idB.DeviceID,
		RespPubKeyHex:  hex.EncodeToString(idB.PublicKey),
		RespName:       "Bob Phone",
		RespCaps:       []string{"transfer.v1", "lan_direct"},
		RespNonceHex:   hex.EncodeToString(nonceB[:]),
		RespSigHex:     resp.Signature,
		KPairHex:       hex.EncodeToString(kPairAlice),
		PairCredRef:    credRefAlice,
		ReqConfirmTag:  confirmAlice.AuthTag,
		RespConfirmTag: confirmBob.AuthTag,
	}

	vecData, err := json.MarshalIndent([]PairingTestVector{vector}, "", "  ")
	if err != nil {
		t.Fatalf("marshal test vector: %v", err)
	}

	targetPath := filepath.Join("testdata", "pairing-vectors.json")
	if err := os.WriteFile(targetPath, vecData, 0644); err != nil {
		t.Fatalf("write pairing-vectors.json: %v", err)
	}
}

func TestPairingAdversarialFailures(t *testing.T) {
	seedA := sha256.Sum256([]byte("seed-device-alice-adv"))
	seedB := sha256.Sum256([]byte("seed-device-bob-adv"))
	privA := ed25519.NewKeyFromSeed(seedA[:])
	privB := ed25519.NewKeyFromSeed(seedB[:])
	idA, _ := NewDeviceIdentity(privA.Public().(ed25519.PublicKey), privA)
	idB, _ := NewDeviceIdentity(privB.Public().(ed25519.PublicKey), privB)

	masterKey := sha256.Sum256([]byte("session-master-key-adv"))
	nonceA := sha256.Sum256([]byte("nonce-alice-adv"))
	nonceB := sha256.Sum256([]byte("nonce-bob-adv"))

	req, _ := NewPairingRequest(idA, "Alice", []string{"transfer.v1"}, masterKey[:], nonceA[:])

	// 1. Malicious server modifies DeviceID in request
	tamperedReq := *req
	tamperedReq.DeviceID = idB.DeviceID
	if _, _, err := VerifyPairingRequest(&tamperedReq, masterKey[:]); err == nil {
		t.Errorf("expected error on tampered DeviceID")
	}

	// 2. Tampered signature in request
	tamperedReq2 := *req
	tamperedReq2.Signature = hex.EncodeToString(make([]byte, 64))
	if _, _, err := VerifyPairingRequest(&tamperedReq2, masterKey[:]); err == nil {
		t.Errorf("expected error on tampered signature")
	}

	// 3. Different master key (MITM attempt)
	rogueMaster := sha256.Sum256([]byte("rogue-master-key"))
	if _, _, err := VerifyPairingRequest(req, rogueMaster[:]); err == nil {
		t.Errorf("expected error on wrong master key in request")
	}

	// 4. Response verified against wrong request nonce
	resp, _ := NewPairingResponse(idB, "Bob", []string{"transfer.v1"}, masterKey[:], nonceA[:], nonceB[:])
	wrongNonceA := sha256.Sum256([]byte("different-req-nonce"))
	if _, _, err := VerifyPairingResponse(resp, wrongNonceA[:], masterKey[:]); err == nil {
		t.Errorf("expected error on wrong request nonce in response")
	}

	// 5. Rejection confirm
	kPair, _, _ := DerivePairCredential(masterKey[:], nonceA[:], nonceB[:], idA.PublicKey, idB.PublicKey)
	rejectedConfirm := NewPairingConfirm(kPair, idB.DeviceID, false)
	if err := VerifyPairingConfirm(rejectedConfirm, kPair, idB.DeviceID); err != ErrPairingRejected {
		t.Errorf("expected ErrPairingRejected, got %v", err)
	}

	// 6. Bad auth tag on confirm
	badTagConfirm := &PairingConfirm{Type: MsgPairingConfirm, Status: "accepted", AuthTag: hex.EncodeToString(make([]byte, 32))}
	if err := VerifyPairingConfirm(badTagConfirm, kPair, idB.DeviceID); err != ErrPairingConfirmFailed {
		t.Errorf("expected ErrPairingConfirmFailed, got %v", err)
	}
}

func TestPairingCodec(t *testing.T) {
	req := &PairingRequest{
		Type:            MsgPairingRequest,
		ProtocolVersion: "sendbeam/1",
		DeviceID:        "sb-dev-1234",
		PublicKey:       "abcd",
		DeviceName:      "Test",
		Capabilities:    []string{"cap1"},
		Nonce:           "1122",
		Signature:       "3344",
	}

	data, err := EncodePairingMessage(req)
	if err != nil {
		t.Fatalf("EncodePairingMessage: %v", err)
	}

	decoded, err := DecodePairingMessage(data)
	if err != nil {
		t.Fatalf("DecodePairingMessage: %v", err)
	}

	reqDecoded, ok := decoded.(*PairingRequest)
	if !ok {
		t.Fatalf("expected *PairingRequest, got %T", decoded)
	}
	if reqDecoded.DeviceID != req.DeviceID {
		t.Errorf("device ID mismatch: got %s, want %s", reqDecoded.DeviceID, req.DeviceID)
	}
}
