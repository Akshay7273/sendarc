package wire

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// resumeAuthVectorDoc is the committed shape of docs/test-vectors/resume-auth.json: the
// fixed inputs (original master, transferId, manifest fingerprint, both nonces) and the
// full derived chain — resume root, transfer-scoped resume secret, canonical transcript,
// the three proofs, the resumed session master, and the fresh directional keys/salts.
// Both the Go and TypeScript implementations must reproduce every value byte-for-byte.
type resumeAuthVectorDoc struct {
	Description string `json:"description"`
	Version     int    `json:"version"`
	Master      string `json:"master"`
	TransferID  string `json:"transferId"`
	// ManifestFingerprint is the canonical manifest fingerprint (64 lowercase hex).
	ManifestFingerprint string `json:"manifestFingerprint"`
	ResumeRoot          string `json:"resumeRoot"`
	ResumeSecret        string `json:"resumeSecret"`
	OffererNonce        string `json:"offererNonce"`
	JoinerNonce         string `json:"joinerNonce"`
	Transcript          string `json:"transcript"`
	JoinerProof         string `json:"joinerProof"`
	OffererProof        string `json:"offererProof"`
	ReadyProof          string `json:"readyProof"`
	ResumeMaster        string `json:"resumeMaster"`
	O2JKey              string `json:"o2jKey"`
	O2JSalt             string `json:"o2jSalt"`
	J2OKey              string `json:"j2oKey"`
	J2OSalt             string `json:"j2oSalt"`
}

// Fixed vector inputs (public KAT values, never real credentials).
var (
	resumeVectorMaster   = bytesRange(0x00, 0x20) // 0x00..0x1f
	resumeVectorTransfer = "0123456789abcdef0123456789abcdef"
	resumeVectorFinger   = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	resumeVectorOfferer  = bytesRange(0x10, 0x30) // 0x10..0x2f
	resumeVectorJoiner   = bytesRange(0x30, 0x50) // 0x30..0x4f
)

// bytesRange returns [start, end) as bytes.
func bytesRange(start, end byte) []byte {
	out := make([]byte, 0, end-start)
	for b := start; b < end; b++ {
		out = append(out, b)
	}
	return out
}

// buildResumeAuthVectorDoc derives the full committed chain from the fixed inputs.
func buildResumeAuthVectorDoc() (resumeAuthVectorDoc, error) {
	root, err := ResumeRoot(resumeVectorMaster)
	if err != nil {
		return resumeAuthVectorDoc{}, err
	}
	secret, err := ResumeSecret(root, ResumeAuthVersion, resumeVectorTransfer, resumeVectorFinger)
	if err != nil {
		return resumeAuthVectorDoc{}, err
	}
	transcript, err := ResumeTranscript(ResumeAuthVersion, resumeVectorTransfer, resumeVectorFinger,
		resumeVectorOfferer, resumeVectorJoiner)
	if err != nil {
		return resumeAuthVectorDoc{}, err
	}
	joinerProof, err := ResumeJoinerProof(secret, transcript)
	if err != nil {
		return resumeAuthVectorDoc{}, err
	}
	offererProof, err := ResumeOffererProof(secret, transcript)
	if err != nil {
		return resumeAuthVectorDoc{}, err
	}
	readyProof, err := ResumeReadyProof(secret, transcript)
	if err != nil {
		return resumeAuthVectorDoc{}, err
	}
	master, err := ResumeSessionMaster(secret, transcript)
	if err != nil {
		return resumeAuthVectorDoc{}, err
	}
	keys, err := DeriveTransferKeys(master)
	if err != nil {
		return resumeAuthVectorDoc{}, err
	}
	return resumeAuthVectorDoc{
		Description: "Cross-session authenticated resume (V13-PR07) derivation chain, produced by " +
			"the Go implementation (packages/wire/resumeauth.go). Both Go and TypeScript must " +
			"reproduce every value byte-for-byte from the fixed inputs; a mismatch is a " +
			"crypto/codec violation. See docs/adr/0005-cross-session-resume.md.",
		Version:             ResumeAuthVersion,
		Master:              hex.EncodeToString(resumeVectorMaster),
		TransferID:          resumeVectorTransfer,
		ManifestFingerprint: resumeVectorFinger,
		ResumeRoot:          hex.EncodeToString(root),
		ResumeSecret:        hex.EncodeToString(secret),
		OffererNonce:        hex.EncodeToString(resumeVectorOfferer),
		JoinerNonce:         hex.EncodeToString(resumeVectorJoiner),
		Transcript:          hex.EncodeToString(transcript),
		JoinerProof:         hex.EncodeToString(joinerProof),
		OffererProof:        hex.EncodeToString(offererProof),
		ReadyProof:          hex.EncodeToString(readyProof),
		ResumeMaster:        hex.EncodeToString(master),
		O2JKey:              hex.EncodeToString(keys.O2J.Key),
		O2JSalt:             hex.EncodeToString(keys.O2J.Salt),
		J2OKey:              hex.EncodeToString(keys.J2O.Key),
		J2OSalt:             hex.EncodeToString(keys.J2O.Salt),
	}, nil
}

// TestGenerateResumeAuthVector rewrites docs/test-vectors/resume-auth.json from the Go
// implementation. Run with GENERATE_VECTORS=1 (see docs/test-vectors/README.md):
//
//	cd packages/wire && GENERATE_VECTORS=1 go test -run TestGenerateResumeAuthVector ./...
func TestGenerateResumeAuthVector(t *testing.T) {
	if os.Getenv("GENERATE_VECTORS") != "1" {
		t.Skip("set GENERATE_VECTORS=1 to regenerate docs/test-vectors/resume-auth.json")
	}
	doc, err := buildResumeAuthVectorDoc()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "docs", "test-vectors", "resume-auth.json")
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s", path)
}

// TestResumeAuthVector asserts the committed cross-language vector reproduces from the
// fixed inputs (both Go and TypeScript assert this file, so any drift fails one of them).
func TestResumeAuthVector(t *testing.T) {
	var doc resumeAuthVectorDoc
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "test-vectors", "resume-auth.json"))
	if err != nil {
		t.Fatalf("read vector: %v (regenerate with GENERATE_VECTORS=1)", err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	got, err := buildResumeAuthVectorDoc()
	if err != nil {
		t.Fatal(err)
	}
	assertVectorField(t, "master", got.Master, doc.Master)
	assertVectorField(t, "transferId", got.TransferID, doc.TransferID)
	assertVectorField(t, "manifestFingerprint", got.ManifestFingerprint, doc.ManifestFingerprint)
	assertVectorField(t, "resumeRoot", got.ResumeRoot, doc.ResumeRoot)
	assertVectorField(t, "resumeSecret", got.ResumeSecret, doc.ResumeSecret)
	assertVectorField(t, "offererNonce", got.OffererNonce, doc.OffererNonce)
	assertVectorField(t, "joinerNonce", got.JoinerNonce, doc.JoinerNonce)
	assertVectorField(t, "transcript", got.Transcript, doc.Transcript)
	assertVectorField(t, "joinerProof", got.JoinerProof, doc.JoinerProof)
	assertVectorField(t, "offererProof", got.OffererProof, doc.OffererProof)
	assertVectorField(t, "readyProof", got.ReadyProof, doc.ReadyProof)
	assertVectorField(t, "resumeMaster", got.ResumeMaster, doc.ResumeMaster)
	assertVectorField(t, "o2jKey", got.O2JKey, doc.O2JKey)
	assertVectorField(t, "o2jSalt", got.O2JSalt, doc.O2JSalt)
	assertVectorField(t, "j2oKey", got.J2OKey, doc.J2OKey)
	assertVectorField(t, "j2oSalt", got.J2OSalt, doc.J2OSalt)
}

func assertVectorField(t *testing.T, name, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("vector %s mismatch:\n got %s\nwant %s", name, got, want)
	}
}
