package wire

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// Standard capability flags for trusted devices.
const (
	CapTransferV1   = "transfer.v1"
	CapTransferV2   = "transfer.v2"
	CapAutoAccept   = "auto_accept"
	CapLANDirect    = "lan_direct"
	CapRelayFall    = "relay_fallback"
)

var (
	// ErrInvalidTrustRecord indicates a trust record with invalid fields.
	ErrInvalidTrustRecord = errors.New("invalid trust record")

	// ErrDeviceRevoked indicates an operation was attempted on a revoked device.
	ErrDeviceRevoked = errors.New("device is revoked")

	// ErrInvalidPolicy indicates invalid trust policy settings.
	ErrInvalidPolicy = errors.New("invalid trust policy")
)

// TrustPolicy defines automated transfer handling and local destination restrictions for a paired peer.
type TrustPolicy struct {
	// AutoAccept indicates if incoming transfers from this device should proceed without manual confirmation.
	AutoAccept bool `json:"auto_accept"`

	// AutoAcceptDestDir is the designated root directory where auto-accepted transfers are saved.
	// Must be an absolute path when AutoAccept is true.
	AutoAcceptDestDir string `json:"auto_accept_dest_dir,omitempty"`

	// MaxFileSizeBytes is the maximum single file size allowed for automated acceptance (0 = default 10GB cap).
	MaxFileSizeBytes int64 `json:"max_file_size_bytes,omitempty"`

	// AllowedMimeTypes is an optional whitelist of permitted MIME types/prefixes.
	AllowedMimeTypes []string `json:"allowed_mime_types,omitempty"`
}

// DefaultTrustPolicy returns the default safe trust policy (auto-accept disabled).
func DefaultTrustPolicy() TrustPolicy {
	return TrustPolicy{
		AutoAccept:        false,
		AutoAcceptDestDir: "",
		MaxFileSizeBytes:  10 * 1024 * 1024 * 1024, // 10 GB default cap
		AllowedMimeTypes:  nil,
	}
}

// TrustRecord represents a persisted trusted device entry in the local trust database.
type TrustRecord struct {
	DeviceID          string      `json:"device_id"`
	PublicKey         string      `json:"public_key"` // hex-encoded 32-byte Ed25519 public key
	LocalLabel        string      `json:"local_label"`
	PairCredentialRef string      `json:"pair_credential_ref"`
	Capabilities      []string    `json:"capabilities"`
	FirstSeenAt       time.Time   `json:"first_seen_at"`
	LastSeenAt        time.Time   `json:"last_seen_at"`
	Revoked           bool        `json:"revoked"`
	RevokedAt         *time.Time  `json:"revoked_at,omitempty"`
	Policy            TrustPolicy `json:"policy"`
}

// Validate checks the structural integrity and security constraints of the trust record.
func (r *TrustRecord) Validate() error {
	if r == nil {
		return ErrInvalidTrustRecord
	}
	if !ValidateDeviceID(r.DeviceID) {
		return fmt.Errorf("%w: invalid device id %q", ErrInvalidTrustRecord, r.DeviceID)
	}
	pub, err := ParsePublicKeyHex(r.PublicKey)
	if err != nil {
		return fmt.Errorf("%w: invalid public key: %w", ErrInvalidTrustRecord, err)
	}
	derivedID := DeriveDeviceID(pub)
	if derivedID != r.DeviceID {
		return fmt.Errorf("%w: device id %q does not match public key derived id %q", ErrInvalidTrustRecord, r.DeviceID, derivedID)
	}
	if strings.TrimSpace(r.LocalLabel) == "" {
		return fmt.Errorf("%w: local label cannot be empty", ErrInvalidTrustRecord)
	}
	if r.FirstSeenAt.IsZero() {
		return fmt.Errorf("%w: first_seen_at must be set", ErrInvalidTrustRecord)
	}
	if r.LastSeenAt.IsZero() {
		r.LastSeenAt = r.FirstSeenAt
	}
	if r.Revoked && r.RevokedAt == nil {
		now := time.Now().UTC()
		r.RevokedAt = &now
	}
	if err := r.Policy.Validate(); err != nil {
		return err
	}
	return nil
}

// Validate checks trust policy safety rules.
func (p *TrustPolicy) Validate() error {
	if p.AutoAccept {
		if p.AutoAcceptDestDir == "" {
			return fmt.Errorf("%w: auto_accept_dest_dir must be configured when auto_accept is enabled", ErrInvalidPolicy)
		}
		if !filepath.IsAbs(p.AutoAcceptDestDir) {
			return fmt.Errorf("%w: auto_accept_dest_dir must be an absolute path: %q", ErrInvalidPolicy, p.AutoAcceptDestDir)
		}
		// Clean and verify it does not contain relative escapes
		clean := filepath.Clean(p.AutoAcceptDestDir)
		if clean == "." || clean == "/" || clean == `\` {
			return fmt.Errorf("%w: auto_accept_dest_dir cannot be filesystem root: %q", ErrInvalidPolicy, p.AutoAcceptDestDir)
		}
	}
	if p.MaxFileSizeBytes < 0 {
		return fmt.Errorf("%w: max_file_size_bytes cannot be negative", ErrInvalidPolicy)
	}
	return nil
}

// HasCapability checks if a specific capability is granted.
func (r *TrustRecord) HasCapability(capName string) bool {
	for _, c := range r.Capabilities {
		if strings.EqualFold(c, capName) {
			return true
		}
	}
	return false
}

// Fingerprint returns the formatted human-verifiable fingerprint for the record's public key.
func (r *TrustRecord) Fingerprint() string {
	pub, err := hex.DecodeString(r.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return ""
	}
	return DeriveFingerprint(ed25519.PublicKey(pub))
}
