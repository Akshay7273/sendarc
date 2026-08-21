package wire

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Trusted-session message types, protocol version, and domain separation constants (V15-PR03).
const (
	MsgTrustedAuthInit     = "trusted_auth_init"
	MsgTrustedAuthResponse = "trusted_auth_response"
	MsgTrustedAuthConfirm  = "trusted_auth_confirm"

	TrustedAuthProtocolVersion = "sendbeam/2"

	DomainTrustedInit          = "sendbeam/2 trusted-init:"
	DomainTrustedInitMAC       = "sendbeam/2 trusted-init-mac:"
	DomainTrustedResp          = "sendbeam/2 trusted-resp:"
	DomainTrustedRespMAC       = "sendbeam/2 trusted-resp-mac:"
	DomainTrustedMaster        = "sendbeam/2 session-master:"
	DomainTrustedInitToRespKey = "sendbeam/2 initiator-to-responder key"
	DomainTrustedRespToInitKey = "sendbeam/2 responder-to-initiator key"
	DomainTrustedConfirmInit   = "sendbeam/2 confirm-init:"
	DomainTrustedConfirmResp   = "sendbeam/2 confirm-resp:"

	TrustedAuthNonceSize     = 32
	TrustedAuthEphemeralSize = 32
	MaxTrustedTimestampSkew  = 5 * time.Minute
)

var (
	// ErrInvalidTrustedMessage indicates a malformed or unrecognizable trusted-session message.
	ErrInvalidTrustedMessage = errors.New("invalid trusted-session message")

	// ErrTrustedTimestampSkew indicates that the message timestamp is outside acceptable clock bounds.
	ErrTrustedTimestampSkew = errors.New("trusted-session timestamp outside acceptable skew window")

	// ErrTrustedSignatureFailed indicates that the Ed25519 signature in trusted authentication failed.
	ErrTrustedSignatureFailed = errors.New("trusted-session signature verification failed")

	// ErrTrustedMACTagFailed indicates that the HMAC-SHA256 authentication tag failed verification.
	ErrTrustedMACTagFailed = errors.New("trusted-session MAC tag verification failed")

	// ErrTrustedPeerMismatch indicates that the claimed peer device ID does not match expected identity.
	ErrTrustedPeerMismatch = errors.New("trusted-session peer device ID mismatch")

	// ErrTrustedPeerRevoked indicates that the peer device has been revoked in local trust store.
	ErrTrustedPeerRevoked = errors.New("trusted peer device is revoked")

	// ErrTrustedRejected indicates that the peer explicitly rejected the trusted session.
	ErrTrustedRejected = errors.New("trusted session was rejected by peer")
)

// TrustedAuthInit is sent by the initiating device to authenticate a trusted connection.
type TrustedAuthInit struct {
	Type               string   `json:"type"`
	ProtocolVersion    string   `json:"protocol_version"`
	InitiatorDeviceID  string   `json:"initiator_device_id"`
	ResponderDeviceID  string   `json:"responder_device_id"`
	PairCredentialRef  string   `json:"pair_credential_ref"`
	EphemeralPub       string   `json:"ephemeral_pub"`
	Nonce              string   `json:"nonce"`
	Capabilities       []string `json:"capabilities"`
	Timestamp          string   `json:"timestamp"`
	Signature          string   `json:"signature"`
	AuthTag            string   `json:"auth_tag"`
}

// TrustedAuthResponse is sent by the responder upon verifying the TrustedAuthInit.
type TrustedAuthResponse struct {
	Type              string   `json:"type"`
	ProtocolVersion   string   `json:"protocol_version"`
	Status            string   `json:"status"` // "accepted", "rejected", or "revoked"
	ResponderDeviceID string   `json:"responder_device_id"`
	EphemeralPub      string   `json:"ephemeral_pub,omitempty"`
	Nonce             string   `json:"nonce,omitempty"`
	Capabilities      []string `json:"capabilities,omitempty"`
	Signature         string   `json:"signature,omitempty"`
	AuthTag           string   `json:"auth_tag,omitempty"`
}

// TrustedAuthConfirm finalizes mutual session establishment.
type TrustedAuthConfirm struct {
	Type    string `json:"type"`
	Status  string `json:"status"` // "ready" or "rejected"
	AuthTag string `json:"auth_tag,omitempty"`
}

// TrustedSessionKeys contains forward-secret directional session keys and negotiated features.
type TrustedSessionKeys struct {
	SessionMaster           []byte
	InitiatorToResponderKey []byte
	ResponderToInitiatorKey []byte
	NegotiatedCapabilities  []string
}

// HashCapabilities produces a deterministic canonical SHA-256 digest of capability strings.
func HashCapabilities(caps []string) []byte {
	sorted := make([]string, len(caps))
	copy(sorted, caps)
	sort.Strings(sorted)
	joined := strings.Join(sorted, ",")
	h := sha256.Sum256([]byte(joined))
	return h[:]
}

// IntersectCapabilities returns the alphabetically sorted set of capabilities supported by both peers.
func IntersectCapabilities(a, b []string) []string {
	set := make(map[string]bool, len(a))
	for _, item := range a {
		set[item] = true
	}
	var res []string
	for _, item := range b {
		if set[item] {
			res = append(res, item)
		}
	}
	sort.Strings(res)
	return res
}

// BuildTrustedInitChallenge constructs the binary payload signed by the initiator.
func BuildTrustedInitChallenge(kPairHash, ephemPub, nonce []byte, initID, respID string, capsHash []byte, timestamp string) []byte {
	buf := make([]byte, 0, len(DomainTrustedInit)+len(kPairHash)+len(ephemPub)+len(nonce)+len(initID)+len(respID)+len(capsHash)+len(timestamp))
	buf = append(buf, DomainTrustedInit...)
	buf = append(buf, kPairHash...)
	buf = append(buf, ephemPub...)
	buf = append(buf, nonce...)
	buf = append(buf, initID...)
	buf = append(buf, respID...)
	buf = append(buf, capsHash...)
	buf = append(buf, timestamp...)
	return buf
}

// BuildTrustedRespChallenge constructs the binary payload signed by the responder.
func BuildTrustedRespChallenge(kPairHash, ephemPubInit, ephemPubResp, nonceInit, nonceResp []byte, initID, respID string, capsHash []byte) []byte {
	buf := make([]byte, 0, len(DomainTrustedResp)+len(kPairHash)+len(ephemPubInit)+len(ephemPubResp)+len(nonceInit)+len(nonceResp)+len(initID)+len(respID)+len(capsHash))
	buf = append(buf, DomainTrustedResp...)
	buf = append(buf, kPairHash...)
	buf = append(buf, ephemPubInit...)
	buf = append(buf, ephemPubResp...)
	buf = append(buf, nonceInit...)
	buf = append(buf, nonceResp...)
	buf = append(buf, initID...)
	buf = append(buf, respID...)
	buf = append(buf, capsHash...)
	return buf
}

// ComputeTrustedMACTag computes the HMAC-SHA256 authentication tag over a challenge using k_pair.
func ComputeTrustedMACTag(kPair []byte, domain string, challenge []byte) string {
	mac := hmac.New(sha256.New, kPair)
	mac.Write([]byte(domain))
	mac.Write(challenge)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyTrustedMACTag checks a MAC tag in constant time.
func VerifyTrustedMACTag(kPair []byte, domain string, challenge []byte, tagHex string) bool {
	tagBytes, err := hex.DecodeString(tagHex)
	if err != nil || len(tagBytes) != sha256.Size {
		return false
	}
	expectedHex := ComputeTrustedMACTag(kPair, domain, challenge)
	expectedBytes, _ := hex.DecodeString(expectedHex)
	return subtle.ConstantTimeCompare(tagBytes, expectedBytes) == 1
}

// DeriveTrustedSessionKeys derives forward-secret directional traffic keys from ephemeral material and k_pair.
func DeriveTrustedSessionKeys(kPair, ephemPubInit, ephemPubResp, nonceInit, nonceResp []byte, initID, respID string, capsInit, capsResp []string) (*TrustedSessionKeys, error) {
	if len(kPair) == 0 {
		return nil, errors.New("k_pair required")
	}
	if len(ephemPubInit) != TrustedAuthEphemeralSize || len(ephemPubResp) != TrustedAuthEphemeralSize {
		return nil, errors.New("invalid ephemeral public key size")
	}
	if len(nonceInit) != TrustedAuthNonceSize || len(nonceResp) != TrustedAuthNonceSize {
		return nil, errors.New("invalid nonce size")
	}

	negotiated := IntersectCapabilities(capsInit, capsResp)
	capsHash := HashCapabilities(negotiated)

	// Mix ephemeral material and k_pair into IKM
	ephemMix := make([]byte, 0, len(ephemPubInit)+len(ephemPubResp)+len(nonceInit)+len(nonceResp))
	ephemMix = append(ephemMix, ephemPubInit...)
	ephemMix = append(ephemMix, ephemPubResp...)
	ephemMix = append(ephemMix, nonceInit...)
	ephemMix = append(ephemMix, nonceResp...)

	mac := hmac.New(sha256.New, kPair)
	mac.Write(ephemMix)
	ikm := mac.Sum(nil)

	salt := make([]byte, 0, len(nonceInit)+len(nonceResp))
	salt = append(salt, nonceInit...)
	salt = append(salt, nonceResp...)

	kPairHash := sha256.Sum256(kPair)
	transcript := BuildTrustedRespChallenge(kPairHash[:], ephemPubInit, ephemPubResp, nonceInit, nonceResp, initID, respID, capsHash)

	infoMaster := append([]byte(DomainTrustedMaster), transcript...)
	sessionMaster, err := hkdfSHA256(ikm, salt, infoMaster, 32)
	if err != nil {
		return nil, fmt.Errorf("derive session master: %w", err)
	}

	kI2R, err := hkdfSHA256(sessionMaster, nil, []byte(DomainTrustedInitToRespKey), 32)
	if err != nil {
		return nil, fmt.Errorf("derive i2r key: %w", err)
	}

	kR2I, err := hkdfSHA256(sessionMaster, nil, []byte(DomainTrustedRespToInitKey), 32)
	if err != nil {
		return nil, fmt.Errorf("derive r2i key: %w", err)
	}

	return &TrustedSessionKeys{
		SessionMaster:           sessionMaster,
		InitiatorToResponderKey: kI2R,
		ResponderToInitiatorKey: kR2I,
		NegotiatedCapabilities:  negotiated,
	}, nil
}

// ComputeTrustedConfirmTag computes the confirmation tag for the session master.
func ComputeTrustedConfirmTag(sessionMaster []byte, domain string, deviceID string) string {
	mac := hmac.New(sha256.New, sessionMaster)
	mac.Write([]byte(domain))
	mac.Write([]byte(deviceID))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyTrustedConfirmTag verifies the confirmation tag in constant time.
func VerifyTrustedConfirmTag(sessionMaster []byte, domain string, deviceID, tagHex string) bool {
	tagBytes, err := hex.DecodeString(tagHex)
	if err != nil || len(tagBytes) != sha256.Size {
		return false
	}
	expectedHex := ComputeTrustedConfirmTag(sessionMaster, domain, deviceID)
	expectedBytes, _ := hex.DecodeString(expectedHex)
	return subtle.ConstantTimeCompare(tagBytes, expectedBytes) == 1
}

// NewTrustedAuthInit creates a signed and MAC-authenticated TrustedAuthInit message.
func NewTrustedAuthInit(id *DeviceIdentity, respDeviceID, credRef string, kPair []byte, caps []string, ephemPub, nonce []byte, now time.Time) (*TrustedAuthInit, error) {
	if id == nil {
		return nil, ErrInvalidIdentity
	}
	if len(kPair) == 0 {
		return nil, errors.New("k_pair required")
	}
	if len(ephemPub) != TrustedAuthEphemeralSize {
		ephemPub = make([]byte, TrustedAuthEphemeralSize)
		if _, err := rand.Read(ephemPub); err != nil {
			return nil, err
		}
	}
	if len(nonce) != TrustedAuthNonceSize {
		nonce = make([]byte, TrustedAuthNonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
	}

	tsStr := now.UTC().Format(time.RFC3339)
	capsHash := HashCapabilities(caps)
	kPairHash := sha256.Sum256(kPair)

	challenge := BuildTrustedInitChallenge(kPairHash[:], ephemPub, nonce, id.DeviceID, respDeviceID, capsHash, tsStr)
	sig, err := id.Sign(challenge)
	if err != nil {
		return nil, fmt.Errorf("sign trusted init: %w", err)
	}

	tag := ComputeTrustedMACTag(kPair, DomainTrustedInitMAC, challenge)

	return &TrustedAuthInit{
		Type:              MsgTrustedAuthInit,
		ProtocolVersion:   TrustedAuthProtocolVersion,
		InitiatorDeviceID: id.DeviceID,
		ResponderDeviceID: respDeviceID,
		PairCredentialRef: credRef,
		EphemeralPub:      hex.EncodeToString(ephemPub),
		Nonce:             hex.EncodeToString(nonce),
		Capabilities:      caps,
		Timestamp:         tsStr,
		Signature:         hex.EncodeToString(sig),
		AuthTag:           tag,
	}, nil
}

// VerifyTrustedAuthInit validates format, clock skew, Ed25519 signature, and HMAC tag of a TrustedAuthInit.
func VerifyTrustedAuthInit(init *TrustedAuthInit, kPair []byte, initPubKey ed25519.PublicKey, localDeviceID string, now time.Time) ([]byte, []byte, error) {
	if init == nil || init.Type != MsgTrustedAuthInit || init.ProtocolVersion != TrustedAuthProtocolVersion {
		return nil, nil, ErrInvalidTrustedMessage
	}
	if init.ResponderDeviceID != localDeviceID {
		return nil, nil, ErrTrustedPeerMismatch
	}
	if !ValidateDeviceID(init.InitiatorDeviceID) {
		return nil, nil, ErrInvalidDeviceID
	}

	expectedInitID := DeriveDeviceID(initPubKey)
	if expectedInitID != init.InitiatorDeviceID {
		return nil, nil, ErrTrustedPeerMismatch
	}

	ts, err := time.Parse(time.RFC3339, init.Timestamp)
	if err != nil {
		return nil, nil, ErrInvalidTrustedMessage
	}
	skew := now.Sub(ts)
	if skew < 0 {
		skew = -skew
	}
	if skew > MaxTrustedTimestampSkew {
		return nil, nil, ErrTrustedTimestampSkew
	}

	ephemPub, err := hex.DecodeString(init.EphemeralPub)
	if err != nil || len(ephemPub) != TrustedAuthEphemeralSize {
		return nil, nil, ErrInvalidTrustedMessage
	}

	nonce, err := hex.DecodeString(init.Nonce)
	if err != nil || len(nonce) != TrustedAuthNonceSize {
		return nil, nil, ErrInvalidTrustedMessage
	}

	sigBytes, err := hex.DecodeString(init.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return nil, nil, ErrTrustedSignatureFailed
	}

	capsHash := HashCapabilities(init.Capabilities)
	kPairHash := sha256.Sum256(kPair)
	challenge := BuildTrustedInitChallenge(kPairHash[:], ephemPub, nonce, init.InitiatorDeviceID, init.ResponderDeviceID, capsHash, init.Timestamp)

	if !VerifyDeviceSignature(initPubKey, challenge, sigBytes) {
		return nil, nil, ErrTrustedSignatureFailed
	}

	if !VerifyTrustedMACTag(kPair, DomainTrustedInitMAC, challenge, init.AuthTag) {
		return nil, nil, ErrTrustedMACTagFailed
	}

	return ephemPub, nonce, nil
}

// NewTrustedAuthResponse creates a signed and MAC-authenticated TrustedAuthResponse message.
func NewTrustedAuthResponse(id *DeviceIdentity, init *TrustedAuthInit, kPair []byte, caps []string, ephemPub, nonce []byte) (*TrustedAuthResponse, error) {
	if id == nil {
		return nil, ErrInvalidIdentity
	}
	if len(kPair) == 0 {
		return nil, errors.New("k_pair required")
	}
	if len(ephemPub) != TrustedAuthEphemeralSize {
		ephemPub = make([]byte, TrustedAuthEphemeralSize)
		if _, err := rand.Read(ephemPub); err != nil {
			return nil, err
		}
	}
	if len(nonce) != TrustedAuthNonceSize {
		nonce = make([]byte, TrustedAuthNonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
	}

	ephemInit, _ := hex.DecodeString(init.EphemeralPub)
	nonceInit, _ := hex.DecodeString(init.Nonce)

	negotiated := IntersectCapabilities(init.Capabilities, caps)
	capsHash := HashCapabilities(negotiated)
	kPairHash := sha256.Sum256(kPair)

	challenge := BuildTrustedRespChallenge(kPairHash[:], ephemInit, ephemPub, nonceInit, nonce, init.InitiatorDeviceID, id.DeviceID, capsHash)
	sig, err := id.Sign(challenge)
	if err != nil {
		return nil, fmt.Errorf("sign trusted response: %w", err)
	}

	tag := ComputeTrustedMACTag(kPair, DomainTrustedRespMAC, challenge)

	return &TrustedAuthResponse{
		Type:              MsgTrustedAuthResponse,
		ProtocolVersion:   TrustedAuthProtocolVersion,
		Status:            "accepted",
		ResponderDeviceID: id.DeviceID,
		EphemeralPub:      hex.EncodeToString(ephemPub),
		Nonce:             hex.EncodeToString(nonce),
		Capabilities:      caps,
		Signature:         hex.EncodeToString(sig),
		AuthTag:           tag,
	}, nil
}

// VerifyTrustedAuthResponse validates the format, Ed25519 signature, and HMAC tag of a TrustedAuthResponse.
func VerifyTrustedAuthResponse(resp *TrustedAuthResponse, init *TrustedAuthInit, kPair []byte, respPubKey ed25519.PublicKey, localDeviceID string) ([]byte, []byte, error) {
	if resp == nil || resp.Type != MsgTrustedAuthResponse || resp.ProtocolVersion != TrustedAuthProtocolVersion {
		return nil, nil, ErrInvalidTrustedMessage
	}
	if localDeviceID != "" && init.InitiatorDeviceID != localDeviceID {
		return nil, nil, ErrTrustedPeerMismatch
	}
	if resp.Status != "accepted" {
		if resp.Status == "revoked" {
			return nil, nil, ErrTrustedPeerRevoked
		}
		return nil, nil, ErrTrustedRejected
	}
	if resp.ResponderDeviceID != init.ResponderDeviceID {
		return nil, nil, ErrTrustedPeerMismatch
	}

	expectedRespID := DeriveDeviceID(respPubKey)
	if expectedRespID != resp.ResponderDeviceID {
		return nil, nil, ErrTrustedPeerMismatch
	}

	ephemInit, _ := hex.DecodeString(init.EphemeralPub)
	nonceInit, _ := hex.DecodeString(init.Nonce)

	ephemResp, err := hex.DecodeString(resp.EphemeralPub)
	if err != nil || len(ephemResp) != TrustedAuthEphemeralSize {
		return nil, nil, ErrInvalidTrustedMessage
	}

	nonceResp, err := hex.DecodeString(resp.Nonce)
	if err != nil || len(nonceResp) != TrustedAuthNonceSize {
		return nil, nil, ErrInvalidTrustedMessage
	}

	sigBytes, err := hex.DecodeString(resp.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return nil, nil, ErrTrustedSignatureFailed
	}

	negotiated := IntersectCapabilities(init.Capabilities, resp.Capabilities)
	capsHash := HashCapabilities(negotiated)
	kPairHash := sha256.Sum256(kPair)
	challenge := BuildTrustedRespChallenge(kPairHash[:], ephemInit, ephemResp, nonceInit, nonceResp, init.InitiatorDeviceID, resp.ResponderDeviceID, capsHash)

	if !VerifyDeviceSignature(respPubKey, challenge, sigBytes) {
		return nil, nil, ErrTrustedSignatureFailed
	}

	if !VerifyTrustedMACTag(kPair, DomainTrustedRespMAC, challenge, resp.AuthTag) {
		return nil, nil, ErrTrustedMACTagFailed
	}

	return ephemResp, nonceResp, nil
}

// NewTrustedAuthConfirm creates a TrustedAuthConfirm message.
func NewTrustedAuthConfirm(sessionMaster []byte, domain, localDeviceID string, ready bool) *TrustedAuthConfirm {
	if !ready {
		return &TrustedAuthConfirm{
			Type:   MsgTrustedAuthConfirm,
			Status: "rejected",
		}
	}
	tag := ComputeTrustedConfirmTag(sessionMaster, domain, localDeviceID)
	return &TrustedAuthConfirm{
		Type:    MsgTrustedAuthConfirm,
		Status:  "ready",
		AuthTag: tag,
	}
}

// VerifyTrustedAuthConfirm verifies a peer's confirmation tag.
func VerifyTrustedAuthConfirm(confirm *TrustedAuthConfirm, sessionMaster []byte, domain, peerDeviceID string) error {
	if confirm == nil || confirm.Type != MsgTrustedAuthConfirm {
		return ErrInvalidTrustedMessage
	}
	if confirm.Status != "ready" {
		return ErrTrustedRejected
	}
	if !VerifyTrustedConfirmTag(sessionMaster, domain, peerDeviceID, confirm.AuthTag) {
		return ErrTrustedMACTagFailed
	}
	return nil
}

// EncodeTrustedAuthMessage marshals any trusted authentication message into compact JSON bytes.
func EncodeTrustedAuthMessage(msg any) ([]byte, error) {
	return json.Marshal(msg)
}

// DecodeTrustedAuthMessage unmarshals a trusted authentication message into its concrete type.
func DecodeTrustedAuthMessage(data []byte) (any, error) {
	var peek struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &peek); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidTrustedMessage, err)
	}

	switch peek.Type {
	case MsgTrustedAuthInit:
		var init TrustedAuthInit
		if err := json.Unmarshal(data, &init); err != nil {
			return nil, err
		}
		return &init, nil
	case MsgTrustedAuthResponse:
		var resp TrustedAuthResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			return nil, err
		}
		return &resp, nil
	case MsgTrustedAuthConfirm:
		var conf TrustedAuthConfirm
		if err := json.Unmarshal(data, &conf); err != nil {
			return nil, err
		}
		return &conf, nil
	default:
		return nil, fmt.Errorf("%w: unknown type %q", ErrInvalidTrustedMessage, peek.Type)
	}
}
