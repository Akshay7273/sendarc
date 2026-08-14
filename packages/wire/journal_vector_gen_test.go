package wire

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// resumeSecretVectorCase is one resume-secret envelope validation case: the envelope JSON
// (or nil for the absence case) and whether the v1 validation must accept it. Both the Go
// and TypeScript journal suites assert the same cases, pinning the exact credential format
// (version 1 = 64 lowercase hex) introduced by V13-PR07.
type resumeSecretVectorCase struct {
	Name     string               `json:"name"`
	Envelope *JournalResumeSecret `json:"envelope"`
	Valid    bool                 `json:"valid"`
}

// journalVectorDoc is the committed shape of docs/test-vectors/durable-journal.json: the
// fixed inputs a reader needs to rebuild the sample journals, plus the expected fingerprint
// and the byte-exact canonical journal JSON (including its checksum). Both the Go and the
// TypeScript suites must reproduce `journal` and `journalWithSecret` byte-for-byte, pinning
// the schema's key order, the fingerprint definition, the checksum definition, and the
// resume-secret serialization across languages.
type journalVectorDoc struct {
	Description         string                     `json:"description"`
	TransferID          string                     `json:"transferId"`
	Manifest            string                     `json:"manifest"` // canonical wire JSON of the validated manifest
	SourceIdentity      JournalIdentity            `json:"sourceIdentity"`
	DestinationIdentity JournalIdentity            `json:"destinationIdentity"`
	CreatedAt           int64                      `json:"createdAt"`
	UpdatedAt           int64                      `json:"updatedAt"`
	CommittedBlocks     []int                      `json:"committedBlocks"`
	DigestCheckpoints   []*JournalDigestCheckpoint `json:"digestCheckpoints"` // per-file, null when absent
	Fingerprint         string                     `json:"fingerprint"`
	Journal             string                     `json:"journal"` // canonical encoded journal incl. checksum (no resume secret)
	// JournalWithSecret is the same canonical journal carrying a valid version-1 resume
	// secret, so the resumeSecret serialization is pinned byte-for-byte too.
	JournalWithSecret string `json:"journalWithSecret"`
	// ResumeSecretCases pins the v1 credential format: valid and invalid envelopes.
	ResumeSecretCases []resumeSecretVectorCase `json:"resumeSecretCases"`
}

// journalVectorSecretValue is the fixed 64-hex version-1 resume secret used by the vector
// sample. It is a public fixed test value (a KAT), never a real credential.
const journalVectorSecretValue = "f1f2f3f4f5f6f7f8f9fafbfcfdfeff00f1f2f3f4f5f6f7f8f9fafbfcfdfeff00"

// TestGenerateJournalVector rewrites docs/test-vectors/durable-journal.json from the Go
// implementation. Run with GENERATE_VECTORS=1 (see docs/test-vectors/README.md):
//
//	cd packages/wire && GENERATE_VECTORS=1 go test -run TestGenerateJournalVector ./...
func TestGenerateJournalVector(t *testing.T) {
	if os.Getenv("GENERATE_VECTORS") != "1" {
		t.Skip("set GENERATE_VECTORS=1 to regenerate docs/test-vectors/durable-journal.json")
	}
	j := journalVectorSample(t)
	doc, err := buildJournalVectorDoc(j)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "docs", "test-vectors", "durable-journal.json")
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s", path)
}

// buildJournalVectorDoc derives the committed vector document from a journal.
func buildJournalVectorDoc(j DurableJournal) (journalVectorDoc, error) {
	encoded, err := EncodeJournal(j)
	if err != nil {
		return journalVectorDoc{}, err
	}
	withSecret := j
	withSecret.ResumeSecret = &JournalResumeSecret{Version: 1, Value: journalVectorSecretValue}
	encodedWithSecret, err := EncodeJournal(withSecret)
	if err != nil {
		return journalVectorDoc{}, err
	}
	manifest := journalTestManifest()
	validated, err := ValidateManifest(manifest)
	if err != nil {
		return journalVectorDoc{}, err
	}
	manifestJSON, err := EncodeControl(&validated)
	if err != nil {
		return journalVectorDoc{}, err
	}
	committed := make([]int, len(j.Files))
	checkpoints := make([]*JournalDigestCheckpoint, len(j.Files))
	for i, f := range j.Files {
		committed[i] = f.CommittedBlocks
		checkpoints[i] = f.DigestCheckpoint
	}
	validSecret := &JournalResumeSecret{Version: 1, Value: journalVectorSecretValue}
	return journalVectorDoc{
		Description: "Canonical schema-v1 durable journal, produced by the Go implementation " +
			"(packages/wire/journal.go). Both Go and TypeScript must reproduce `fingerprint`, " +
			"the `journal` JSON, and the `journalWithSecret` JSON byte-for-byte; a mismatch is " +
			"a schema/codec violation. `resumeSecretCases` pins the version-1 credential format " +
			"(exactly 64 lowercase hex characters) introduced by V13-PR07.",
		TransferID:          j.TransferID,
		Manifest:            string(manifestJSON),
		SourceIdentity:      j.SourceIdentity,
		DestinationIdentity: j.DestinationIdentity,
		CreatedAt:           j.CreatedAt,
		UpdatedAt:           j.UpdatedAt,
		CommittedBlocks:     committed,
		DigestCheckpoints:   checkpoints,
		Fingerprint:         j.ManifestFingerprint,
		Journal:             string(encoded),
		JournalWithSecret:   string(encodedWithSecret),
		ResumeSecretCases: []resumeSecretVectorCase{
			{Name: "valid v1 secret", Envelope: validSecret, Valid: true},
			{Name: "wrong version", Envelope: &JournalResumeSecret{Version: 2, Value: journalVectorSecretValue}, Valid: false},
			{Name: "wrong length (short)", Envelope: &JournalResumeSecret{Version: 1, Value: "00"}, Valid: false},
			{Name: "wrong length (long)", Envelope: &JournalResumeSecret{Version: 1, Value: strings.Repeat("ab", 33)}, Valid: false},
			{Name: "uppercase hex", Envelope: &JournalResumeSecret{Version: 1, Value: strings.ToUpper(journalVectorSecretValue)}, Valid: false},
			{Name: "invalid encoding", Envelope: &JournalResumeSecret{Version: 1, Value: "not hex or b64!!"}, Valid: false},
			{Name: "empty value", Envelope: &JournalResumeSecret{Version: 1, Value: ""}, Valid: false},
		},
	}, nil
}
