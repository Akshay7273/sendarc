package wire

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// journalVectorDoc is the committed shape of docs/test-vectors/durable-journal.json: the
// fixed inputs a reader needs to rebuild the sample journal, plus the expected fingerprint
// and the byte-exact canonical journal JSON (including its checksum). Both the Go and the
// TypeScript suites must reproduce `journal` byte-for-byte, pinning the schema's key order,
// the fingerprint definition, and the checksum definition across languages.
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
	Journal             string                     `json:"journal"` // canonical encoded journal incl. checksum
}

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
	return journalVectorDoc{
		Description: "Canonical schema-v1 durable journal, produced by the Go implementation " +
			"(packages/wire/journal.go). Both Go and TypeScript must reproduce `fingerprint` " +
			"and the `journal` JSON byte-for-byte; a mismatch is a schema/codec violation.",
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
	}, nil
}
