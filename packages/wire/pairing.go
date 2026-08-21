package wire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// Pairing message types and domain separation constants.
const (
	MsgPairingRequest  = "pairing_request"
	MsgPairingResponse = "pairing_response"
	MsgPairingConfirm  = "pairing_confirm"

	DomainPairingRequest  = "sendbeam/1 pairing-request:"
	DomainPairingResponse = "sendbeam/1 pairing-response:"
	DomainPairingConfirm  = "sendbeam/1 pairing-confirm:"
	InfoPairCredential    = "sendbeam/1 pair-credential"

	PairingNonceSize = 32
)

var (
	// ErrInvalidPairingMessage is returned when a pairing message cannot be decoded or is malformed.
	ErrInvalidPairingMessage = errors.New("invalid pairing message")

	// ErrPairingSignatureFailed is returned when an Ed25519 device signature verification fails.
	ErrPairingSignatureFailed = errors.New("pairing signature verification failed")

	// ErrPairingDeviceIDMismatch is returned when the claimed device ID does not match the public key.
	ErrPairingDeviceIDMismatch = errors.New("pairing device ID does not match public key")

	// ErrPairingConfirmFailed is returned when the pairing confirmation authentication tag is invalid.
	ErrPairingConfirmFailed = errors.New("pairing confirmation authentication tag verification failed")

	// ErrPairingRejected is returned when a peer rejects the pairing ceremony.
	ErrPairingRejected = errors.New("pairing ceremony was rejected by peer")
)

// PairingRequest is sent by the initiating device in the pairing ceremony.
type PairingRequest struct {
	Type            string   `json:"type"`
	ProtocolVersion string   `json:"protocol_version"`
	DeviceID        string   `json:"device_id"`
	PublicKey       string   `json:"public_key"`
	DeviceName      string   `json:"device_name"`
	Capabilities    []string `json:"capabilities"`
	Nonce           string   `json:"nonce"`
	Signature       string   `json:"signature"`
}

// PairingResponse is sent by the receiving device upon verifying the PairingRequest.
type PairingResponse struct {
	Type            string   `json:"type"`
	ProtocolVersion string   `json:"protocol_version"`
	DeviceID        string   `json:"device_id"`
	PublicKey       string   `json:"public_key"`
	DeviceName      string   `json:"device_name"`
	Capabilities    []string `json:"capabilities"`
	Nonce           string   `json:"nonce"`
	Signature       string   `json:"signature"`
}

// PairingConfirm commits and finalizes the pairing ceremony after both sides agree to trust.
type PairingConfirm struct {
	Type    string `json:"type"`
	Status  string `json:"status"` // "accepted" or "rejected"
	AuthTag string `json:"auth_tag,omitempty"`
}

// BuildPairingRequestChallenge constructs the domain-separated message signed by the pairing initiator.
func BuildPairingRequestChallenge(masterKey, reqNonce []byte, deviceID string) []byte {
	h := sha256.Sum256(masterKey)
	buf := make([]byte, 0, len(DomainPairingRequest)+len(h)+len(reqNonce)+len(deviceID))
	buf = append(buf, DomainPairingRequest...)
	buf = append(buf, h[:]...)
	buf = append(buf, reqNonce...)
	buf = append(buf, deviceID...)
	return buf
}

// BuildPairingResponseChallenge constructs the domain-separated message signed by the pairing responder.
func BuildPairingResponseChallenge(masterKey, reqNonce, respNonce []byte, deviceID string) []byte {
	h := sha256.Sum256(masterKey)
	buf := make([]byte, 0, len(DomainPairingResponse)+len(h)+len(reqNonce)+len(respNonce)+len(deviceID))
	buf = append(buf, DomainPairingResponse...)
	buf = append(buf, h[:]...)
	buf = append(buf, reqNonce...)
	buf = append(buf, respNonce...)
	buf = append(buf, deviceID...)
	return buf
}

// DerivePairCredential derives the persistent pairwise credential (k_pair) and its reference ID.
// Public keys are sorted lexicographically to guarantee deterministic derivation regardless of role.
func DerivePairCredential(masterKey, reqNonce, respNonce, pubA, pubB []byte) ([]byte, string, error) {
	if len(masterKey) == 0 {
		return nil, "", errors.New("master key required")
	}
	if len(reqNonce) != PairingNonceSize || len(respNonce) != PairingNonceSize {
		return nil, "", errors.New("invalid pairing nonce length")
	}
	if len(pubA) != ed25519.PublicKeySize || len(pubB) != ed25519.PublicKeySize {
		return nil, "", errors.New("invalid public key size")
	}

	salt := make([]byte, 0, len(reqNonce)+len(respNonce))
	salt = append(salt, reqNonce...)
	salt = append(salt, respNonce...)

	var infoPubs []byte
	if bytes.Compare(pubA, pubB) < 0 {
		infoPubs = append(append([]byte(nil), pubA...), pubB...)
	} else {
		infoPubs = append(append([]byte(nil), pubB...), pubA...)
	}

	info := append([]byte(InfoPairCredential), infoPubs...)
	kPair, err := hkdfSHA256(masterKey, salt, info, 32)
	if err != nil {
		return nil, "", fmt.Errorf("derive k_pair: %w", err)
	}

	h := sha256.Sum256(kPair)
	credRef := "cred-" + hex.EncodeToString(h[:])

	return kPair, credRef, nil
}

// ComputePairingConfirmTag computes the HMAC-SHA256 confirmation tag over the peer's device ID.
func ComputePairingConfirmTag(kPair []byte, peerDeviceID string) string {
	mac := hmac.New(sha256.New, kPair)
	mac.Write([]byte(DomainPairingConfirm))
	mac.Write([]byte(peerDeviceID))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyPairingConfirmTag verifies the confirmation authentication tag using constant-time comparison.
func VerifyPairingConfirmTag(kPair []byte, peerDeviceID, tagHex string) bool {
	tagBytes, err := hex.DecodeString(tagHex)
	if err != nil || len(tagBytes) != sha256.Size {
		return false
	}
	expectedHex := ComputePairingConfirmTag(kPair, peerDeviceID)
	expectedBytes, _ := hex.DecodeString(expectedHex)
	return subtle.ConstantTimeCompare(tagBytes, expectedBytes) == 1
}

// NewPairingRequest creates a signed PairingRequest message.
func NewPairingRequest(id *DeviceIdentity, deviceName string, caps []string, masterKey []byte, nonce []byte) (*PairingRequest, error) {
	if id == nil {
		return nil, ErrInvalidIdentity
	}
	if len(nonce) != PairingNonceSize {
		nonce = make([]byte, PairingNonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
	}

	challenge := BuildPairingRequestChallenge(masterKey, nonce, id.DeviceID)
	sig, err := id.Sign(challenge)
	if err != nil {
		return nil, fmt.Errorf("sign pairing request: %w", err)
	}

	return &PairingRequest{
		Type:            MsgPairingRequest,
		ProtocolVersion: "sendbeam/1",
		DeviceID:        id.DeviceID,
		PublicKey:       hex.EncodeToString(id.PublicKey),
		DeviceName:      deviceName,
		Capabilities:    caps,
		Nonce:           hex.EncodeToString(nonce),
		Signature:       hex.EncodeToString(sig),
	}, nil
}

// VerifyPairingRequest validates the format, DeviceID binding, and Ed25519 signature of a PairingRequest.
func VerifyPairingRequest(req *PairingRequest, masterKey []byte) (ed25519.PublicKey, []byte, error) {
	if req == nil || req.Type != MsgPairingRequest {
		return nil, nil, ErrInvalidPairingMessage
	}
	if !ValidateDeviceID(req.DeviceID) {
		return nil, nil, ErrInvalidDeviceID
	}

	pubBytes, err := hex.DecodeString(req.PublicKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return nil, nil, ErrInvalidPublicKey
	}

	expectedID := DeriveDeviceID(pubBytes)
	if expectedID != req.DeviceID {
		return nil, nil, ErrPairingDeviceIDMismatch
	}

	nonceBytes, err := hex.DecodeString(req.Nonce)
	if err != nil || len(nonceBytes) != PairingNonceSize {
		return nil, nil, ErrInvalidPairingMessage
	}

	sigBytes, err := hex.DecodeString(req.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return nil, nil, ErrPairingSignatureFailed
	}

	challenge := BuildPairingRequestChallenge(masterKey, nonceBytes, req.DeviceID)
	if !VerifyDeviceSignature(pubBytes, challenge, sigBytes) {
		return nil, nil, ErrPairingSignatureFailed
	}

	return pubBytes, nonceBytes, nil
}

// NewPairingResponse creates a signed PairingResponse message responding to a verified request.
func NewPairingResponse(id *DeviceIdentity, deviceName string, caps []string, masterKey []byte, reqNonce, respNonce []byte) (*PairingResponse, error) {
	if id == nil {
		return nil, ErrInvalidIdentity
	}
	if len(reqNonce) != PairingNonceSize {
		return nil, errors.New("invalid request nonce length")
	}
	if len(respNonce) != PairingNonceSize {
		respNonce = make([]byte, PairingNonceSize)
		if _, err := rand.Read(respNonce); err != nil {
			return nil, err
		}
	}

	challenge := BuildPairingResponseChallenge(masterKey, reqNonce, respNonce, id.DeviceID)
	sig, err := id.Sign(challenge)
	if err != nil {
		return nil, fmt.Errorf("sign pairing response: %w", err)
	}

	return &PairingResponse{
		Type:            MsgPairingResponse,
		ProtocolVersion: "sendbeam/1",
		DeviceID:        id.DeviceID,
		PublicKey:       hex.EncodeToString(id.PublicKey),
		DeviceName:      deviceName,
		Capabilities:    caps,
		Nonce:           hex.EncodeToString(respNonce),
		Signature:       hex.EncodeToString(sig),
	}, nil
}

// VerifyPairingResponse validates the format, DeviceID binding, and Ed25519 signature of a PairingResponse.
func VerifyPairingResponse(resp *PairingResponse, reqNonce []byte, masterKey []byte) (ed25519.PublicKey, []byte, error) {
	if resp == nil || resp.Type != MsgPairingResponse {
		return nil, nil, ErrInvalidPairingMessage
	}
	if !ValidateDeviceID(resp.DeviceID) {
		return nil, nil, ErrInvalidDeviceID
	}

	pubBytes, err := hex.DecodeString(resp.PublicKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return nil, nil, ErrInvalidPublicKey
	}

	expectedID := DeriveDeviceID(pubBytes)
	if expectedID != resp.DeviceID {
		return nil, nil, ErrPairingDeviceIDMismatch
	}

	respNonceBytes, err := hex.DecodeString(resp.Nonce)
	if err != nil || len(respNonceBytes) != PairingNonceSize {
		return nil, nil, ErrInvalidPairingMessage
	}

	sigBytes, err := hex.DecodeString(resp.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return nil, nil, ErrPairingSignatureFailed
	}

	challenge := BuildPairingResponseChallenge(masterKey, reqNonce, respNonceBytes, resp.DeviceID)
	if !VerifyDeviceSignature(pubBytes, challenge, sigBytes) {
		return nil, nil, ErrPairingSignatureFailed
	}

	return pubBytes, respNonceBytes, nil
}

// NewPairingConfirm creates a PairingConfirm commit message.
func NewPairingConfirm(kPair []byte, peerDeviceID string, accepted bool) *PairingConfirm {
	if !accepted {
		return &PairingConfirm{
			Type:   MsgPairingConfirm,
			Status: "rejected",
		}
	}
	tag := ComputePairingConfirmTag(kPair, peerDeviceID)
	return &PairingConfirm{
		Type:    MsgPairingConfirm,
		Status:  "accepted",
		AuthTag: tag,
	}
}

// VerifyPairingConfirm verifies an incoming PairingConfirm message.
func VerifyPairingConfirm(confirm *PairingConfirm, kPair []byte, peerDeviceID string) error {
	if confirm == nil || confirm.Type != MsgPairingConfirm {
		return ErrInvalidPairingMessage
	}
	if confirm.Status != "accepted" {
		return ErrPairingRejected
	}
	if !VerifyPairingConfirmTag(kPair, peerDeviceID, confirm.AuthTag) {
		return ErrPairingConfirmFailed
	}
	return nil
}

// EncodePairingMessage marshals any pairing message into compact JSON bytes.
func EncodePairingMessage(msg any) ([]byte, error) {
	return json.Marshal(msg)
}

// DecodePairingMessage unmarshals a pairing message into its concrete type.
func DecodePairingMessage(data []byte) (any, error) {
	var peek struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &peek); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPairingMessage, err)
	}

	switch peek.Type {
	case MsgPairingRequest:
		var req PairingRequest
		if err := json.Unmarshal(data, &req); err != nil {
			return nil, err
		}
		return &req, nil
	case MsgPairingResponse:
		var resp PairingResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			return nil, err
		}
		return &resp, nil
	case MsgPairingConfirm:
		var conf PairingConfirm
		if err := json.Unmarshal(data, &conf); err != nil {
			return nil, err
		}
		return &conf, nil
	default:
		return nil, fmt.Errorf("%w: unknown type %q", ErrInvalidPairingMessage, peek.Type)
	}
}
