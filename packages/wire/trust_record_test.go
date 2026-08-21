package wire

import (
	"encoding/json"
	"testing"
	"time"
)

func TestTrustRecordValidation(t *testing.T) {
	id, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatalf("GenerateDeviceIdentity: %v", err)
	}

	validRecord := &TrustRecord{
		DeviceID:          id.DeviceID,
		PublicKey:         id.PublicKeyHex(),
		LocalLabel:        "Pixel 9 Pro",
		PairCredentialRef: "cred-12345",
		Capabilities:      []string{CapTransferV1, CapTransferV2, CapLANDirect},
		FirstSeenAt:       time.Now().UTC().Add(-24 * time.Hour),
		LastSeenAt:        time.Now().UTC(),
		Revoked:           false,
		Policy: TrustPolicy{
			AutoAccept:        true,
			AutoAcceptDestDir: "/home/user/Downloads/SendBeam",
			MaxFileSizeBytes:  10 * 1024 * 1024 * 1024,
		},
	}

	if err := validRecord.Validate(); err != nil {
		t.Fatalf("validRecord.Validate() failed: %v", err)
	}

	if !validRecord.HasCapability(CapTransferV1) {
		t.Errorf("expected CapTransferV1 capability")
	}
	if validRecord.HasCapability("non_existent") {
		t.Errorf("unexpected capability")
	}

	if fp := validRecord.Fingerprint(); fp != id.Fingerprint {
		t.Errorf("Fingerprint mismatch: got %s, want %s", fp, id.Fingerprint)
	}

	// JSON Round-trip
	data, err := json.Marshal(validRecord)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded TrustRecord
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatalf("decoded.Validate() failed: %v", err)
	}
	if decoded.DeviceID != validRecord.DeviceID {
		t.Errorf("DeviceID mismatch after unmarshal")
	}

	// Mismatched PublicKey and DeviceID should fail validation
	otherID, _ := GenerateDeviceIdentity()
	corruptedRecord := *validRecord
	corruptedRecord.PublicKey = otherID.PublicKeyHex()
	if err := corruptedRecord.Validate(); err == nil {
		t.Errorf("expected validation failure for mismatched public key")
	}

	// Empty LocalLabel should fail
	invalidLabelRecord := *validRecord
	invalidLabelRecord.LocalLabel = ""
	if err := invalidLabelRecord.Validate(); err == nil {
		t.Errorf("expected validation failure for empty local label")
	}

	// AutoAccept without absolute destination should fail
	badPolicyRecord := *validRecord
	badPolicyRecord.Policy = TrustPolicy{
		AutoAccept:        true,
		AutoAcceptDestDir: "relative/path",
	}
	if err := badPolicyRecord.Validate(); err == nil {
		t.Errorf("expected validation failure for relative auto accept dir")
	}

	// AutoAccept with root directory should fail
	rootPolicyRecord := *validRecord
	rootPolicyRecord.Policy = TrustPolicy{
		AutoAccept:        true,
		AutoAcceptDestDir: "/",
	}
	if err := rootPolicyRecord.Validate(); err == nil {
		t.Errorf("expected validation failure for root auto accept dir")
	}
}
