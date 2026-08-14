package wire

// Durable transfer journal — the versioned local persistence contract for resumable
// transfers (docs/adr/0004-durable-journal.md).
//
// The journal is LOCAL on-device state, NOT part of the sendbeam/1 wire protocol: it is
// never transmitted between peers and carries no wire-version implication. It lives in
// this package because the Go CLI and the browser must consume the same contract; it is
// the Go twin of packages/protocol/src/journal.ts, and the two must serialize, validate,
// fingerprint, and checksum byte-identically (pinned by docs/test-vectors/durable-journal.json).
//
// Durability ordering (the contract). A checkpoint may be advertised as resumable only
// after the full ordering below; a crash at any earlier step leaves the previous
// checkpoint authoritative:
//
//	receive/authenticate block
//	        ↓
//	verify block
//	        ↓
//	write block data
//	        ↓
//	required durability operation (flush/fsync of the data)
//	        ↓
//	atomically advance the journal checkpoint   ← CommitBlocks is the only advancement API
//	        ↓
//	ONLY NOW may that checkpoint be advertised as resumable
//
// The journal schema cannot observe the data-durability barrier (whether bytes reached
// stable storage); enforcing the ordering is the storage layer's job (PR02 CLI, PR03
// browser). What the schema DOES enforce, and what this file proves with tests, is that
// the journal can never represent more than it is given: checkpoints are whole committed
// blocks bounded by the manifest, they can only advance through CommitBlocks (never
// regress, never exceed the file), and any journal that fails structural validation,
// fingerprint self-consistency, version dispatch, or checksum verification is rejected
// closed — it is never "probably read".

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// JournalSchemaVersion is the current durable-journal schema version. Journals are written
// with exactly this value; DecodeJournal accepts exactly it. A new schema bumps it and
// adds a decode/migration path in decodeJournalVersion. There is deliberately no
// fabricated earlier public format: version 1 is the first.
const JournalSchemaVersion = 1

// JournalResumeVersion is the version of the durability resume protocol whose checkpoint
// semantics the journal was written for. It is independent of both JournalSchemaVersion
// (on-disk layout) and the wire ProtocolVersion (sendbeam/1): a future resume protocol may
// change what committedBlocks means without changing the layout, or vice versa. Only
// version 1 exists today; the cross-session authenticated resume protocol (PR07) must
// either reuse it or define the next value and its migration here.
const JournalResumeVersion = 1

// JournalIdentity is an opaque, versioned identity envelope. The value is deliberately
// opaque to the journal: its content and derivation are defined by the durability
// implementation that writes it (destination-location identity in PR02/PR03) or by the
// resume-authentication protocol (peer identity binding in PR07). Journal validation only
// checks the envelope shape; the value is a claim, never a trust anchor — resume-time
// validation binds it against authenticated transfer state.
type JournalIdentity struct {
	Version int    `json:"version"`
	Value   string `json:"value"`
}

// Digest checkpoint format identifiers (V13-PR05). The identifier tags the serialized
// digest state so only a compatible runtime restores it: the bytes are opaque,
// implementation-specific state, never decoded by another implementation. A journal whose
// checkpoint format this runtime cannot restore falls back to re-hashing the persisted
// prefix — the checkpoint is an optimization, never a source of truth.
const (
	// DigestCheckpointFormatGoStdlib tags serialized state produced by the Go standard
	// library's sha256 hash (encoding.BinaryMarshaler/UnmarshalBinary format v1).
	DigestCheckpointFormatGoStdlib = "sha256-go-v1"
	// DigestCheckpointFormatHashWasm tags serialized state produced by hash-wasm's sha256
	// IHasher.save() (state format v1; load() rejects state from incompatible builds).
	DigestCheckpointFormatHashWasm = "sha256-wasm-v1"
)

// journalDigestCheckpointFormatPattern bounds the format identifier shape: lowercase
// alphanumeric start, then lowercase alphanumeric, '.', '_' or '-' (e.g. "sha256-go-v1").
var journalDigestCheckpointFormatPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// maxDigestCheckpointStateHex bounds the serialized digest state (lowercase hex) a journal
// may carry. Go's sha256 state is 108 bytes (216 hex chars); hash-wasm's is 116 bytes (232
// hex chars). The generous-but-bounded ceiling keeps decode/restore allocations tiny for
// any attacker-controlled or corrupted state length.
const maxDigestCheckpointStateHex = 4096

// JournalDigestCheckpoint is the optional serialized whole-file digest state that exactly
// matches one file's committed checkpoint (V13-PR05). It lets a resuming runtime restore
// the SHA-256 state instead of re-hashing the persisted prefix — an optimization only.
//
// The checkpoint describes EXACTLY the bytes the journal's committed checkpoint claims:
// CommittedBlocks must equal the file's committedBlocks and CommittedBytes must equal the
// committed byte count, or the journal is structurally corrupt and fails closed. The
// serialized state bytes are opaque and implementation-specific; Format identifies which
// runtime produced them so only a compatible implementation may restore them. A valid
// journal carrying an unusable optional checkpoint (unknown format, undecodable or
// unrestorable state) still resumes through correctness-first prefix re-hash.
//
// Never a source of truth: final whole-file digest verification remains mandatory, and a
// checkpoint can never advance the journal — CommitBlocks is still the only progress API.
type JournalDigestCheckpoint struct {
	// Format identifies the digest algorithm + implementation + state-format version
	// (see the DigestCheckpointFormat* constants). Journal validation checks the shape
	// only; whether this runtime can restore the state is a resume-time decision.
	Format string `json:"format"`
	// CommittedBlocks is the exact committed block count the state covers; must equal the
	// file's committedBlocks or the journal fails closed as structurally corrupt.
	CommittedBlocks int `json:"committedBlocks"`
	// CommittedBytes is the exact committed byte count the state covers; must equal
	// min(committedBlocks*blockSize, size) or the journal fails closed.
	CommittedBytes int64 `json:"committedBytes"`
	// State is the serialized digest state, lowercase hex, size-bounded.
	State string `json:"state"`
}

// JournalFileState is one file's durable checkpoint within a journal. The wire FileEntry
// geometry (idx, name, size, mime, lastModified, blockSize, blocks, fileDigest) is stored
// so the journal alone can re-validate the resumed transfer and reproduce the canonical
// manifest fingerprint. CommittedBlocks is the per-file durable high-water mark.
type JournalFileState struct {
	Idx          int    `json:"idx"`
	Name         string `json:"name"`
	Size         int64  `json:"size"`
	Mime         string `json:"mime"`
	LastModified int64  `json:"lastModified"`
	BlockSize    int    `json:"blockSize"`
	Blocks       int    `json:"blocks"`
	FileDigest   string `json:"fileDigest"`
	// CommittedBlocks is the count of leading blocks of this file that are verified,
	// durably persisted, AND checkpointed. It is the only progress representation:
	// checkpoints are whole-block granularity, never byte offsets. Invariant:
	// 0 <= CommittedBlocks <= Blocks.
	CommittedBlocks int `json:"committedBlocks"`
	// DigestCheckpoint is the optional serialized digest state covering exactly this
	// file's committed checkpoint (V13-PR05). Omitted when the digest state is not
	// serializable or the transfer predates digest checkpointing; resume then re-hashes
	// the persisted prefix.
	DigestCheckpoint *JournalDigestCheckpoint `json:"digestCheckpoint,omitempty"`
}

// JournalResumeSecret is the opaque, versioned envelope for the minimum resume-secret
// material the durability model requires. PR01 deliberately does not define its content:
// the cross-session authenticated resume derivation is PR07. The field exists so the
// schema is complete and versioned from day one. Lifecycle rules: created only by the
// resume protocol; NEVER carries the raw SPAKE2/session master key, directional traffic
// keys, live AEAD counters, or unrelated credentials; invalidated when the transfer
// completes or the journal is deleted.
type JournalResumeSecret struct {
	Version int    `json:"version"`
	Value   string `json:"value"`
}

// DurableJournal is the versioned durable-transfer journal (schema version 1). Field
// declaration order is the canonical JSON key order and must match the TypeScript twin
// exactly. Every field is a claim loaded from local, user-editable state: nothing here is
// trusted merely because it was loaded from a journal.
type DurableJournal struct {
	// SchemaVersion identifies the on-disk schema (JournalSchemaVersion).
	SchemaVersion int `json:"schemaVersion"`
	// TransferID is the stable 128-bit hex id carried by the authenticated manifest that
	// this journal's checkpoints belong to.
	TransferID string `json:"transferId"`
	// ManifestFingerprint is the canonical SHA-256 (hex) of the validated manifest (see
	// ManifestFingerprint). It binds every checkpoint to the exact file set.
	ManifestFingerprint string `json:"manifestFingerprint"`
	// ProtocolVersion is the wire-protocol version the transfer ran under. It is recorded,
	// never implied: the journal is not wire state.
	ProtocolVersion string `json:"protocolVersion"`
	// ResumeVersion is the durability resume protocol version (JournalResumeVersion).
	ResumeVersion int `json:"resumeVersion"`
	// BlockSize is the transfer's negotiated logical block size; every file entry's
	// BlockSize must equal it, so a checkpoint's byte meaning is unambiguous.
	BlockSize int `json:"blockSize"`
	// CreatedAt is the journal creation time, unix milliseconds.
	CreatedAt int64 `json:"createdAt"`
	// UpdatedAt is the last checkpoint-advance time, unix milliseconds. Always >= CreatedAt.
	UpdatedAt int64 `json:"updatedAt"`
	// SourceIdentity is an opaque claim about the sender, bound by the resume protocol.
	SourceIdentity JournalIdentity `json:"sourceIdentity"`
	// DestinationIdentity is an opaque claim about the local destination, bound by the
	// durability implementation.
	DestinationIdentity JournalIdentity `json:"destinationIdentity"`
	// Files holds the per-file durable checkpoints, in manifest index order.
	Files []JournalFileState `json:"files"`
	// ResumeSecret is the optional opaque resume-secret envelope (PR07). Omitted when the
	// transfer has no cross-session resume material yet.
	ResumeSecret *JournalResumeSecret `json:"resumeSecret,omitempty"`
	// Checksum is SHA-256 over the canonical JSON of every other field. It is a
	// write-time derivation: EncodeJournal recomputes it, DecodeJournal verifies it, and
	// callers never set it by hand. It detects corruption and tampering; it is not a
	// trust anchor against a local attacker who can recompute it (see ADR 0004 §3).
	Checksum string `json:"checksum,omitempty"`
}

var (
	journalOpaqueHex = regexp.MustCompile(`^[0-9a-f]+$`)
	journalOpaqueB64 = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// isLowerHex reports whether s is exactly n lowercase hex characters.
func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ManifestFingerprint returns the canonical SHA-256 (hex) of a validated manifest. The
// fingerprint is computed over the exact canonical wire serialization of the manifest (the
// same bytes EncodeControl produces), so it is byte-identical across Go and TypeScript and
// pins the file set a journal's checkpoints refer to. It is a binding claim, not a trust
// anchor: resume validation (PR06/PR07) binds it against authenticated transfer state.
func ManifestFingerprint(manifest Manifest) (string, error) {
	validated, err := ValidateManifest(manifest)
	if err != nil {
		return "", err
	}
	encoded, err := EncodeControl(&validated)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// NewJournal builds a fresh schema-v1 journal for one transfer with zero committed
// checkpoints. transferID must be the stable 128-bit hex id carried by the authenticated
// manifest, and manifest must carry that same id (a manifest without one never opted into
// resumption, so it has no durable journal); manifest must describe the exact file set the
// transfer will deliver; source and destination are the identity envelopes the durability
// implementation binds; now seeds both timestamps.
func NewJournal(transferID string, manifest Manifest, source, destination JournalIdentity, now time.Time) (DurableJournal, error) {
	if !isLowerHex(transferID, 32) {
		return DurableJournal{}, Errorf(CodeStorage, "journal: transferId must be 32 lowercase hex characters")
	}
	if manifest.TransferID != transferID {
		return DurableJournal{}, Errorf(CodeStorage, "journal: transferId must match the authenticated manifest")
	}
	fingerprint, err := ManifestFingerprint(manifest)
	if err != nil {
		return DurableJournal{}, Errorf(CodeStorage, "journal: %v", err)
	}
	files := make([]JournalFileState, len(manifest.Files))
	for i, file := range manifest.Files {
		files[i] = JournalFileState{
			Idx: file.Idx, Name: file.Name, Size: file.Size, Mime: file.Mime,
			LastModified: file.LastModified, BlockSize: file.BlockSize, Blocks: file.Blocks,
			FileDigest: file.FileDigest,
		}
	}
	created := now.UnixMilli()
	j := DurableJournal{
		SchemaVersion:       JournalSchemaVersion,
		TransferID:          transferID,
		ManifestFingerprint: fingerprint,
		ProtocolVersion:     ProtocolVersion,
		ResumeVersion:       JournalResumeVersion,
		BlockSize:           manifest.Files[0].BlockSize,
		CreatedAt:           created,
		UpdatedAt:           created,
		SourceIdentity:      source,
		DestinationIdentity: destination,
		Files:               files,
	}
	if err := ValidateJournal(j); err != nil {
		return DurableJournal{}, err
	}
	return j, nil
}

// ValidateJournal checks a journal's structural validity and self-consistency. It does NOT
// verify the checksum (that is a serialization property checked by DecodeJournal), and it
// does NOT treat any field as a trust anchor. Classification: version incompatibilities
// are COMPAT; everything else is STORAGE (local durable state unusable).
func ValidateJournal(j DurableJournal) error {
	if j.SchemaVersion != JournalSchemaVersion {
		return Errorf(CodeCompat, "journal: unsupported schema version %d", j.SchemaVersion)
	}
	if j.ResumeVersion != JournalResumeVersion {
		return Errorf(CodeCompat, "journal: unsupported resume version %d", j.ResumeVersion)
	}
	if j.ProtocolVersion != ProtocolVersion {
		return Errorf(CodeCompat, "journal: unsupported protocol version %q", j.ProtocolVersion)
	}
	if !isLowerHex(j.TransferID, 32) {
		return Errorf(CodeStorage, "journal: transferId must be 32 lowercase hex characters")
	}
	if !isLowerHex(j.ManifestFingerprint, 64) {
		return Errorf(CodeStorage, "journal: manifestFingerprint must be 64 lowercase hex characters")
	}
	if j.CreatedAt <= 0 || j.UpdatedAt <= 0 || j.UpdatedAt < j.CreatedAt {
		return Errorf(CodeStorage, "journal: invalid timestamps")
	}
	if j.BlockSize <= 0 || j.BlockSize > MaxManifestBlockBytes {
		return Errorf(CodeStorage, "journal: invalid block size %d", j.BlockSize)
	}
	if err := validateIdentity(j.SourceIdentity, "sourceIdentity"); err != nil {
		return err
	}
	if err := validateIdentity(j.DestinationIdentity, "destinationIdentity"); err != nil {
		return err
	}
	if j.ResumeSecret != nil {
		if err := validateEnvelope(j.ResumeSecret, "resumeSecret"); err != nil {
			return err
		}
	}
	if len(j.Files) == 0 || len(j.Files) > MaxTransferFiles {
		return Errorf(CodeStorage, "journal: invalid file count %d", len(j.Files))
	}
	// Fingerprint self-consistency: the stored fingerprint must equal one recomputed from
	// the journal's own transferId + file entries, so a journal cannot drift from the file
	// set its checkpoints claim.
	recomputed, err := fingerprintFromFiles(j.TransferID, j.Files)
	if err != nil {
		return Errorf(CodeStorage, "journal: %v", err)
	}
	if recomputed != j.ManifestFingerprint {
		return Errorf(CodeStorage, "journal: manifest fingerprint mismatch")
	}
	seen := make(map[string]struct{}, len(j.Files))
	for i, f := range j.Files {
		if f.Idx != i {
			return Errorf(CodeStorage, "journal: file indexes must be contiguous")
		}
		if f.Size < 0 || f.LastModified < 0 || f.BlockSize <= 0 || f.Blocks < 0 {
			return Errorf(CodeStorage, "journal: file %d has invalid geometry", f.Idx)
		}
		if f.BlockSize > MaxManifestBlockBytes {
			return Errorf(CodeStorage, "journal: file %d block size %d exceeds the %d-byte ceiling",
				f.Idx, f.BlockSize, MaxManifestBlockBytes)
		}
		wantBlocks := 0
		if f.Size > 0 {
			wantBlocks = int((f.Size-1)/int64(f.BlockSize) + 1)
		}
		if f.Blocks != wantBlocks {
			return Errorf(CodeStorage, "journal: file %d has invalid block geometry", f.Idx)
		}
		if f.BlockSize != j.BlockSize {
			return Errorf(CodeStorage, "journal: file %d block size %d differs from journal block size %d",
				f.Idx, f.BlockSize, j.BlockSize)
		}
		if !isLowerHex(f.FileDigest, 64) {
			return Errorf(CodeStorage, "journal: file %d fileDigest must be 64 lowercase hex characters", f.Idx)
		}
		if f.CommittedBlocks < 0 || f.CommittedBlocks > f.Blocks {
			return Errorf(CodeStorage, "journal: committedBlocks %d out of range for file %d (blocks %d)",
				f.CommittedBlocks, f.Idx, f.Blocks)
		}
		if err := validateDigestCheckpoint(f); err != nil {
			return err
		}
		name, err := NormalizeTransferPath(f.Name)
		if err != nil {
			return Errorf(CodeStorage, "journal: %v", err)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return Errorf(CodeStorage, "journal: duplicate file path")
		}
		seen[key] = struct{}{}
	}
	return nil
}

// validateDigestCheckpoint enforces the structural claims of an optional digest
// checkpoint. Any violation is a corrupt journal and fails closed — an impossible
// checkpoint claim must never be trusted. The format identifier and state bytes are
// opaque claims (an unsupported format or unrestorable state falls back to re-hash at
// resume time, which is a different, safe case).
func validateDigestCheckpoint(f JournalFileState) error {
	cp := f.DigestCheckpoint
	if cp == nil {
		return nil
	}
	if !journalDigestCheckpointFormatPattern.MatchString(cp.Format) {
		return Errorf(CodeStorage, "journal: file %d digestCheckpoint has an invalid format identifier", f.Idx)
	}
	if cp.CommittedBlocks != f.CommittedBlocks {
		return Errorf(CodeStorage,
			"journal: file %d digestCheckpoint block count %d does not match committedBlocks %d",
			f.Idx, cp.CommittedBlocks, f.CommittedBlocks)
	}
	wantBytes := int64(cp.CommittedBlocks) * int64(f.BlockSize)
	if wantBytes > f.Size {
		wantBytes = f.Size
	}
	if cp.CommittedBytes != wantBytes {
		return Errorf(CodeStorage,
			"journal: file %d digestCheckpoint byte count %d does not match its committed blocks (%d)",
			f.Idx, cp.CommittedBytes, wantBytes)
	}
	if len(cp.State)%2 != 0 || !isLowerHex(cp.State, len(cp.State)) {
		return Errorf(CodeStorage, "journal: file %d digestCheckpoint state must be lowercase hex", f.Idx)
	}
	if len(cp.State) == 0 || len(cp.State) > maxDigestCheckpointStateHex {
		return Errorf(CodeStorage, "journal: file %d digestCheckpoint state is out of bounds", f.Idx)
	}
	return nil
}

// SetDigestCheckpoint attaches (or, with a nil cp, clears) one file's optional digest
// checkpoint. It runs after CommitBlocks for the same file, so it can enforce the
// checkpoint's block count against the just-committed high-water mark; the storage layer
// must then persist the journal atomically, exactly as it does for CommitBlocks. The
// checkpoint is validated structurally on every encode/decode.
func (j *DurableJournal) SetDigestCheckpoint(fileIdx int, cp *JournalDigestCheckpoint) error {
	if fileIdx < 0 || fileIdx >= len(j.Files) {
		return Errorf(CodeStorage, "journal: no file %d in journal", fileIdx)
	}
	f := &j.Files[fileIdx]
	if cp != nil && cp.CommittedBlocks != f.CommittedBlocks {
		return Errorf(CodeStorage,
			"journal: digestCheckpoint block count %d does not match file %d committedBlocks %d",
			cp.CommittedBlocks, fileIdx, f.CommittedBlocks)
	}
	f.DigestCheckpoint = cp
	return nil
}

func validateIdentity(id JournalIdentity, label string) error {
	if id.Version != 1 {
		return Errorf(CodeCompat, "journal: unsupported %s version %d", label, id.Version)
	}
	if err := validateOpaqueValue(id.Value, label); err != nil {
		return err
	}
	return nil
}

func validateEnvelope(e *JournalResumeSecret, label string) error {
	if e.Version != 1 {
		return Errorf(CodeCompat, "journal: unsupported %s version %d", label, e.Version)
	}
	// V13-PR07: resume secret version 1 is the exact 256-bit transfer-scoped credential
	// envelope — 64 lowercase hex characters (32 bytes). An arbitrary old opaque value is
	// never reinterpreted as a valid key: any other length or encoding fails closed.
	if !isLowerHex(e.Value, 64) {
		return Errorf(CodeStorage, "journal: %s must be 64 lowercase hex characters", label)
	}
	return nil
}

func validateOpaqueValue(v, label string) error {
	if v == "" {
		return Errorf(CodeStorage, "journal: %s value must not be empty", label)
	}
	if len(v) > 2048 {
		return Errorf(CodeStorage, "journal: %s value is too long", label)
	}
	if !journalOpaqueHex.MatchString(v) && !journalOpaqueB64.MatchString(v) {
		return Errorf(CodeStorage, "journal: %s value must be hex or base64url", label)
	}
	return nil
}

// fingerprintFromFiles recomputes the canonical manifest fingerprint from a journal's own
// transferId and file entries, so ValidateJournal can prove self-consistency.
func fingerprintFromFiles(transferID string, files []JournalFileState) (string, error) {
	entries := make([]FileEntry, len(files))
	var total int64
	for i, f := range files {
		entries[i] = FileEntry{
			Idx: f.Idx, Name: f.Name, Size: f.Size, Mime: f.Mime,
			LastModified: f.LastModified, BlockSize: f.BlockSize, Blocks: f.Blocks,
			FileDigest: f.FileDigest,
		}
		total += f.Size
	}
	return ManifestFingerprint(Manifest{TransferID: transferID, Files: entries, TotalSize: total})
}

// EncodeJournal serializes a journal to its canonical JSON, appending the checksum. The
// checksum is SHA-256 over the canonical JSON of every field except the checksum itself
// and is recomputed on every encode, so re-encoding a loaded journal yields a fresh,
// correct checksum. Output is byte-identical to the TypeScript twin (pinned by
// docs/test-vectors/durable-journal.json).
func EncodeJournal(j DurableJournal) ([]byte, error) {
	if err := ValidateJournal(j); err != nil {
		return nil, err
	}
	j.Checksum = ""
	body, err := marshalJournalJSON(j)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	j.Checksum = hex.EncodeToString(sum[:])
	return marshalJournalJSON(j)
}

// marshalJournalJSON is the canonical JSON encoder used for journals: no HTML escaping and
// no trailing newline, byte-identical to JavaScript's JSON.stringify (same rules as the
// wire control codec).
func marshalJournalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// DecodeJournal parses, version-dispatches, validates, and checksum-verifies a journal,
// failing closed on ANY deviation: malformed JSON, unknown fields, trailing data, an
// unsupported or corrupt schema version, invalid content, or a checksum mismatch.
//
// Version policy (ADR 0004 §6):
//   - schemaVersion == JournalSchemaVersion (1): decoded and validated as v1.
//   - schemaVersion > JournalSchemaVersion: rejected as unsupported-future (COMPAT). When
//     a new schema lands, the migration entry point is the case added to
//     decodeJournalVersion; downgrading a newer journal to an older reader is not
//     supported.
//   - anything else (missing, zero, negative, non-integer): rejected as corrupt (STORAGE).
func DecodeJournal(data []byte) (DurableJournal, error) {
	var head struct {
		SchemaVersion *int `json:"schemaVersion"`
	}
	// Lenient first pass: only the version is needed for dispatch; the full document is
	// re-parsed strictly after the schema is known.
	if err := json.Unmarshal(data, &head); err != nil {
		return DurableJournal{}, Errorf(CodeStorage, "journal: malformed journal: %v", err)
	}
	if head.SchemaVersion == nil {
		return DurableJournal{}, Errorf(CodeStorage, "journal: missing schemaVersion")
	}
	return decodeJournalVersion(*head.SchemaVersion, data)
}

func decodeJournalVersion(version int, data []byte) (DurableJournal, error) {
	switch version {
	case JournalSchemaVersion:
		return decodeJournalV1(data)
	default:
		if version > JournalSchemaVersion {
			return DurableJournal{}, Errorf(CodeCompat,
				"journal: schema version %d is newer than this build supports (%d)",
				version, JournalSchemaVersion)
		}
		return DurableJournal{}, Errorf(CodeStorage, "journal: corrupt schema version %d", version)
	}
}

func decodeJournalV1(data []byte) (DurableJournal, error) {
	var j DurableJournal
	if err := unmarshalStrict(data, &j); err != nil {
		return DurableJournal{}, Errorf(CodeStorage, "journal: malformed journal: %v", err)
	}
	if err := ValidateJournal(j); err != nil {
		return DurableJournal{}, err
	}
	stored := j.Checksum
	if !isLowerHex(stored, 64) {
		return DurableJournal{}, Errorf(CodeStorage, "journal: malformed checksum")
	}
	j.Checksum = ""
	body, err := marshalJournalJSON(j)
	if err != nil {
		return DurableJournal{}, Errorf(CodeStorage, "journal: %v", err)
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != stored {
		return DurableJournal{}, Errorf(CodeStorage, "journal: checksum mismatch (corrupt or tampered)")
	}
	j.Checksum = stored
	return j, nil
}

// unmarshalStrict decodes exactly one JSON value into v, rejecting unknown fields and
// trailing data so an unexpected field (for example a stray key-material field) or a torn
// tail fails closed.
func unmarshalStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data after JSON document")
	}
	return nil
}

// CommitBlocks advances one file's durable high-water checkpoint. It is the ONLY way
// committed progress may be recorded, and its documented precondition is the durability
// contract: every block in [0, committedBlocks) has been verified, written, and made
// durable (flushed/fsynced) BEFORE this call. It refuses to regress committed progress and
// refuses values beyond the file's block count; it stamps UpdatedAt. Any existing digest
// checkpoint for the file is cleared — it could not cover the new high-water mark — so the
// journal can never hold a checkpoint inconsistent with its committedBlocks; the storage
// layer re-attaches the matching state through SetDigestCheckpoint. EncodeJournal
// recomputes the checksum afterwards.
func (j *DurableJournal) CommitBlocks(fileIdx, committedBlocks int, now time.Time) error {
	if fileIdx < 0 || fileIdx >= len(j.Files) {
		return Errorf(CodeStorage, "journal: no file %d in journal", fileIdx)
	}
	f := &j.Files[fileIdx]
	if committedBlocks < 0 || committedBlocks > f.Blocks {
		return Errorf(CodeStorage, "journal: committedBlocks %d out of range for file %d (blocks %d)",
			committedBlocks, fileIdx, f.Blocks)
	}
	if committedBlocks < f.CommittedBlocks {
		return Errorf(CodeStorage, "journal: committed progress may not regress (file %d: %d -> %d)",
			fileIdx, f.CommittedBlocks, committedBlocks)
	}
	f.CommittedBlocks = committedBlocks
	f.DigestCheckpoint = nil
	j.UpdatedAt = now.UnixMilli()
	return nil
}

// CommittedBytes returns the durable byte count a file's checkpoint claims: whole committed
// blocks, with the final block capped at the file size. The checkpoint is block-aligned by
// construction — committedBlocks is a count of blocks, never a byte offset.
func (j DurableJournal) CommittedBytes(fileIdx int) (int64, error) {
	if fileIdx < 0 || fileIdx >= len(j.Files) {
		return 0, Errorf(CodeStorage, "journal: no file %d in journal", fileIdx)
	}
	f := j.Files[fileIdx]
	bytes := int64(f.CommittedBlocks) * int64(f.BlockSize)
	if bytes > f.Size {
		bytes = f.Size
	}
	return bytes, nil
}

// WriteJournalAtomic writes a journal to path through the atomic-replacement primitive:
// the canonical encoding goes to a temp file in the same directory, is fsynced, closed,
// then renamed over path, so a crash at any point leaves either the old journal or the
// complete new one — never a torn mix. The temp file is removed on any failure. On POSIX
// the parent directory is fsynced afterwards (best effort) so the rename itself is
// durable; Go's os.Rename replaces an existing file on Windows too
// (MoveFileEx, MOVEFILE_REPLACE_EXISTING). The temp file inherits CreateTemp's 0600 mode,
// keeping the local filenames and identity material private to the user.
func WriteJournalAtomic(path string, j DurableJournal) error {
	data, err := EncodeJournal(j)
	if err != nil {
		return err
	}
	return atomicWriteFile(path, data)
}

func atomicWriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return Errorf(CodeStorage, "journal: create temp: %v", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return Errorf(CodeStorage, "journal: write temp: %v", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return Errorf(CodeStorage, "journal: sync temp: %v", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return Errorf(CodeStorage, "journal: close temp: %v", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return Errorf(CodeStorage, "journal: replace: %v", err)
	}
	syncDir(dir)
	return nil
}

func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer func() { _ = d.Close() }()
	_ = d.Sync()
}
