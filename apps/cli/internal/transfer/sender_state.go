package transfer

// CLI sender restart state (V13-PR04).
//
// The offerer persists a compact sender-side record binding the stable transfer id to the
// canonical identity of its source, strictly BEFORE the manifest frame is transmitted
// (via the wire SenderOptions.OnManifest hook). A crash after that point can be resumed by
// re-running the same command: the id is reused and the receiver's durable journal (PR02)
// continues the verified blocks. The record holds metadata and local paths only — never
// file bytes, never keys, never AEAD counters (ADR 0004 §5) — so nothing is staged.
//
// Layout:
//
//	<config>/sendbeam/sender/
//	  <transferId>.json       # SenderRecord schema v1, mode 0600, atomic replace
//
// <config> is os.UserConfigDir(), overridable with SENDBEAM_SENDER_STATE for tests.
//
// Identity (fail-closed rules): the record's manifest fingerprint is recomputed from the
// stored transfer id + file set (the same canonical serialization the receiver journal
// binds), so a record is self-verifying — tampering, torn writes, or an id/fields swap are
// caught by both the checksum and the fingerprint. A record that fails decode, validation,
// checksum, or fingerprint is rejected closed — never guessed, never deleted automatically;
// only the explicit discard command removes records, idempotently.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sendbeam/wire"
)

// senderSchemaVersion is the current SenderRecord schema. Schema version 2 adds the optional
// opaque resume-secret envelope (V13-PR07); version 1 records (pre-PR07) are accepted on load
// and migrated in memory to v2 with no cross-session auth material.
const senderSchemaVersion = 2

// senderSchemaVersionLegacy is the pre-PR07 schema still accepted on load.
const senderSchemaVersionLegacy = 1

// senderStateEnv overrides the sender-state directory (tests).
const senderStateEnv = "SENDBEAM_SENDER_STATE"

// SenderFileState is one canonical file entry of a sender record, mirroring wire.FileEntry
// so the record's fingerprint can be recomputed from it (the receiver journal binds the
// same canonical manifest serialization).
type SenderFileState struct {
	Idx          int    `json:"idx"`
	Name         string `json:"name"`
	Size         int64  `json:"size"`
	Mime         string `json:"mime"`
	LastModified int64  `json:"lastModified"`
	BlockSize    int    `json:"blockSize"`
	Blocks       int    `json:"blocks"`
	FileDigest   string `json:"fileDigest"`
}

// SenderRecord is the schema-v2 sender record: the stable transfer id plus the canonical
// source identity (manifest fingerprint) and the exact file set it was computed from, the
// canonical absolute source paths the user invoked, and — for transfers that ran under a
// PR07-aware original session — the opaque transfer-scoped resume credential (V13-PR07). It
// is local state, never sent. The checksum covers every field including the resume-secret
// envelope; the credential is never printed in listings, logs, errors, or diagnostics.
type SenderRecord struct {
	SchemaVersion       int                        `json:"schemaVersion"`
	TransferID          string                     `json:"transferId"`
	ManifestFingerprint string                     `json:"manifestFingerprint"`
	ProtocolVersion     string                     `json:"protocolVersion"`
	CreatedAt           int64                      `json:"createdAt"`
	UpdatedAt           int64                      `json:"updatedAt"`
	Paths               []string                   `json:"paths"`
	Files               []SenderFileState          `json:"files"`
	ResumeSecret        *wire.ResumeSecretEnvelope `json:"resumeSecret,omitempty"`
	Checksum            string                     `json:"checksum"`
}

// SenderEntry is one row of the management list: a valid record or an unreadable one.
type SenderEntry struct {
	TransferID  string
	RecordOK    bool
	Err         string
	Fingerprint string
	Paths       []string
	Files       int
	TotalSize   int64
	CreatedAt   int64
	UpdatedAt   int64
}

// SenderStore owns the sender-state directory: record load/save with atomic replace,
// path-keyed lookup, listing, and the explicit discard operation.
type SenderStore struct {
	dir string
	// now is the clock for record timestamps; tests inject a fixed one.
	now func() time.Time
	// write writes a record atomically; tests inject failures (no sleeps). Defaults to
	// writeRecordAtomic.
	write func(path string, rec SenderRecord) error
}

// SenderStoreDir resolves the sender-state directory: SENDBEAM_SENDER_STATE if set, else
// os.UserConfigDir()/sendbeam/sender. Resolution failure fails closed.
func SenderStoreDir() (string, error) {
	if dir := os.Getenv(senderStateEnv); dir != "" {
		return filepath.Abs(dir)
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", wire.Errorf(wire.CodeStorage, "sender: resolve config dir: %v", err)
	}
	return filepath.Join(base, "sendbeam", "sender"), nil
}

// OpenSenderStore prepares (creating if needed) the sender-state directory and resolves it
// absolutely so a later chdir cannot redirect writes.
func OpenSenderStore(dir string) (*SenderStore, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, wire.Errorf(wire.CodeStorage, "sender: resolve state dir: %v", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, wire.Errorf(wire.CodeStorage, "sender: create %s: %v", abs, err)
	}
	return &SenderStore{
		dir:   abs,
		now:   time.Now,
		write: writeRecordAtomic,
	}, nil
}

// Dir returns the resolved absolute sender-state directory.
func (s *SenderStore) Dir() string { return s.dir }

// Path returns the record file path for one transfer id.
func (s *SenderStore) Path(transferID string) string {
	return filepath.Join(s.dir, transferID+".json")
}

// Load reads, decodes, validates, and checksum-verifies the record for transferID. It
// returns (record, false, nil) when no record exists, and fails closed (error) when the
// file exists but is corrupt, torn, tampered, or from an unsupported version. Nothing is
// deleted on a load error.
func (s *SenderStore) Load(transferID string) (SenderRecord, bool, error) {
	data, err := os.ReadFile(s.Path(transferID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return SenderRecord{}, false, nil
		}
		return SenderRecord{}, true, wire.Errorf(wire.CodeStorage, "sender: read record: %v", err)
	}
	rec, err := decodeSenderRecord(data)
	if err != nil {
		return SenderRecord{}, true, err
	}
	return rec, true, nil
}

// Save validates and writes a record atomically through the configured writer.
func (s *SenderStore) Save(rec SenderRecord) error {
	if err := ValidateSenderRecord(rec); err != nil {
		return err
	}
	if err := s.write(s.Path(rec.TransferID), rec); err != nil {
		return err
	}
	return nil
}

// Lookup finds the record whose canonical source paths produce pathKey. Corrupt or
// unsupported records fail the lookup closed (never treated as absent): the store cannot
// be trusted until the user explicitly discards the bad record, and a fresh transfer could
// silently shadow a resumable one.
func (s *SenderStore) Lookup(pathKey string) (SenderRecord, bool, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return SenderRecord{}, false, wire.Errorf(wire.CodeStorage, "sender: list %s: %v", s.dir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if id == "" {
			continue
		}
		rec, ok, loadErr := s.Load(id)
		if loadErr != nil {
			return SenderRecord{}, false, wire.Errorf(wire.CodeStorage,
				"sender: record %s is unusable (%v); nothing was deleted — run \"sendbeam transfers discard %s\" to remove it",
				id, loadErr, id)
		}
		if !ok {
			continue
		}
		if PathKey(rec.Paths) == pathKey {
			return rec, true, nil
		}
	}
	return SenderRecord{}, false, nil
}

// List scans the store and returns every record (valid or unreadable). A single bad record
// never hides the others and is never deleted.
func (s *SenderStore) List() ([]SenderEntry, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, wire.Errorf(wire.CodeStorage, "sender: list %s: %v", s.dir, err)
	}
	var out []SenderEntry
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if id == "" {
			continue
		}
		rec, ok, loadErr := s.Load(id)
		if loadErr != nil || !ok {
			out = append(out, SenderEntry{TransferID: id, RecordOK: false, Err: loadErr.Error()})
			continue
		}
		var total int64
		for _, f := range rec.Files {
			total += f.Size
		}
		out = append(out, SenderEntry{
			TransferID:  id,
			RecordOK:    true,
			Fingerprint: rec.ManifestFingerprint,
			Paths:       rec.Paths,
			Files:       len(rec.Files),
			TotalSize:   total,
			CreatedAt:   rec.CreatedAt,
			UpdatedAt:   rec.UpdatedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TransferID < out[j].TransferID })
	return out, nil
}

// Discard removes one sender record, idempotently and bounded to that transfer: it never
// touches other records or any receive-side storage.
func (s *SenderStore) Discard(transferID string) error {
	if !isLowerHex32(transferID) {
		return wire.Errorf(wire.CodeStorage, "sender: invalid transfer id %q", transferID)
	}
	if err := os.Remove(s.Path(transferID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return wire.Errorf(wire.CodeStorage, "sender: discard record: %v", err)
	}
	return nil
}

// DiscardAll discards every sender record. It is the explicit --all surface and never runs
// implicitly.
func (s *SenderStore) DiscardAll() error {
	entries, err := s.List()
	if err != nil {
		return err
	}
	var errs []error
	for _, entry := range entries {
		if err := s.Discard(entry.TransferID); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// canonicalPaths resolves, cleans, and sorts the source arguments so the path key is
// independent of argument order and of how each path was spelled.
func canonicalPaths(paths []string) ([]string, error) {
	out := make([]string, len(paths))
	for i, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, err
		}
		out[i] = filepath.Clean(abs)
	}
	sort.Strings(out)
	return out, nil
}

// PathKey is the canonical SHA-256 identity of a source path set: the sorted canonical
// absolute paths joined with NUL. Reordered or re-spelled arguments produce the same key.
func PathKey(paths []string) string {
	canonical, _ := canonicalPaths(paths)
	h := sha256.New()
	_, _ = h.Write([]byte("sendbeam/sender-paths\x00"))
	for _, p := range canonical {
		_, _ = h.Write([]byte(p))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// PrepareSender decides whether the source set resumes an interrupted transfer (V13-PR04
// CLI flow). It returns the stable transfer id to advertise ("" = mint a fresh one), the
// wire OnManifest hook that persists or verifies the sender record strictly before the
// manifest frame is sent, and whether an existing record was reused. A record whose
// canonical path key matches but whose cheap meta (name/size/mime/lastModified) differs,
// or a corrupt/unsupported record, fails closed BEFORE anything is advertised; the
// authoritative whole-file check runs in the returned hook.
func PrepareSender(store *SenderStore, paths []string, sources []wire.FileSource) (transferID string, onManifest func(wire.Manifest) error, reused bool, err error) {
	key := PathKey(paths)
	rec, ok, lookupErr := store.Lookup(key)
	if lookupErr != nil {
		return "", nil, false, lookupErr
	}
	if !ok {
		canonical, canonicalErr := canonicalPaths(paths)
		if canonicalErr != nil {
			return "", nil, false, wire.Errorf(wire.CodeStorage, "sender: resolve source paths: %v", canonicalErr)
		}
		return "", store.createHook(canonical), false, nil
	}
	// Cheap pre-check against the record's file set, in canonical order (both sides sort by
	// name, so indexes line up). The authoritative fingerprint check still runs in the hook
	// — a same-size, same-mtime edit is caught there, before the manifest frame goes out.
	if err := cheapSourceCheck(sources, rec); err != nil {
		return "", nil, false, wire.Errorf(wire.CodeStorage,
			"sender: %v — the source changed since the interrupted transfer %s; re-select the original source, or discard the record with \"sendbeam transfers discard %s\"",
			err, rec.TransferID, rec.TransferID)
	}
	return rec.TransferID, store.verifyHook(rec), true, nil
}

// cheapSourceCheck compares freshly-statted source meta against the record's file set.
func cheapSourceCheck(sources []wire.FileSource, rec SenderRecord) error {
	if len(sources) != len(rec.Files) {
		return errors.New("file count changed")
	}
	for i, source := range sources {
		meta := source.Meta()
		want := rec.Files[i]
		if meta.Name != want.Name || meta.Size != want.Size || meta.Mime != want.Mime ||
			meta.LastModified != want.LastModified {
			return fmt.Errorf("file %q changed (%s, %d bytes, mtime %d -> %s, %d bytes, mtime %d)",
				want.Name, want.Name, want.Size, want.LastModified, meta.Name, meta.Size, meta.LastModified)
		}
	}
	return nil
}

// createHook returns the OnManifest hook for a fresh transfer: it records the transfer id
// the sender minted and the canonical source identity derived from the validated manifest,
// strictly before that manifest is transmitted. A persist failure aborts the send before
// the manifest — the id is never advertised unless a durable record backs it.
func (s *SenderStore) createHook(paths []string) func(wire.Manifest) error {
	return func(manifest wire.Manifest) error {
		validated, err := wire.ValidateManifest(manifest)
		if err != nil {
			return err
		}
		fp, err := wire.ManifestFingerprint(validated)
		if err != nil {
			return err
		}
		now := s.now().UnixMilli()
		rec := SenderRecord{
			SchemaVersion:       senderSchemaVersion,
			TransferID:          validated.TransferID,
			ManifestFingerprint: fp,
			ProtocolVersion:     wire.ProtocolVersion,
			CreatedAt:           now,
			UpdatedAt:           now,
			Paths:               paths,
			Files:               fileStatesFromManifest(validated.Files),
		}
		if err := s.Save(rec); err != nil {
			return wire.Errorf(wire.CodeStorage, "sender: persist transfer record: %v", err)
		}
		return nil
	}
}

// verifyHook returns the OnManifest hook for a resumed transfer: it verifies that the
// manifest the sender is about to advertise carries the record's transfer id and the exact
// canonical identity, then refreshes the timestamp. Any mismatch aborts the send before
// the manifest frame — a changed source is never advertised under the old id.
func (s *SenderStore) verifyHook(rec SenderRecord) func(wire.Manifest) error {
	return func(manifest wire.Manifest) error {
		validated, err := wire.ValidateManifest(manifest)
		if err != nil {
			return err
		}
		if validated.TransferID != rec.TransferID {
			return wire.Errorf(wire.CodeStorage,
				"sender: transfer id changed (%s -> %s); refusing to resume", rec.TransferID, validated.TransferID)
		}
		fp, err := wire.ManifestFingerprint(validated)
		if err != nil {
			return err
		}
		if fp != rec.ManifestFingerprint {
			return wire.Errorf(wire.CodeStorage,
				"sender: source does not match the interrupted transfer %s (fingerprint mismatch); nothing was sent — re-select the original source, or discard the record with \"sendbeam transfers discard %s\"",
				rec.TransferID, rec.TransferID)
		}
		rec.UpdatedAt = s.now().UnixMilli()
		if err := s.Save(rec); err != nil {
			return wire.Errorf(wire.CodeStorage, "sender: refresh transfer record: %v", err)
		}
		return nil
	}
}

// AttachResumeSecret derives the transfer-scoped resume credential from the resume root of
// the ORIGINAL authenticated session and persists it into the record — strictly before the
// manifest frame is transmitted (the driver composes this after the record exists). On a
// restart the record already carries the credential from the original session and it is
// NEVER re-derived or overwritten: a fresh session's master would derive a different secret
// and break the original-session binding.
func (s *SenderStore) AttachResumeSecret(manifest wire.Manifest, resumeRoot []byte) error {
	validated, err := wire.ValidateManifest(manifest)
	if err != nil {
		return err
	}
	if validated.TransferID == "" {
		return nil // no resumption: nothing to attach
	}
	rec, ok, err := s.Load(validated.TransferID)
	if err != nil {
		return err
	}
	if !ok {
		return wire.Errorf(wire.CodeStorage,
			"sender: no record for %s; refusing to attach a resume credential", validated.TransferID)
	}
	// The binding is validated FIRST so a manifest that does not match the record fails
	// closed even when a credential is already persisted (fail-closed ordering).
	fp, err := wire.ManifestFingerprint(validated)
	if err != nil {
		return err
	}
	if rec.ManifestFingerprint != fp {
		return wire.Errorf(wire.CodeStorage,
			"sender: record %s does not match the authenticated manifest; refusing to attach a resume credential",
			validated.TransferID)
	}
	if rec.ResumeSecret != nil {
		return nil // original-session credential already persisted; never replace it
	}
	secret, err := wire.ResumeSecret(resumeRoot, wire.ResumeAuthVersion, validated.TransferID, fp)
	if err != nil {
		return err
	}
	env, err := wire.EncodeResumeSecretEnvelope(secret)
	if err != nil {
		return err
	}
	rec.ResumeSecret = env
	return s.Save(rec)
}

// fileStatesFromManifest mirrors the validated manifest's file entries into the record.
func fileStatesFromManifest(files []wire.FileEntry) []SenderFileState {
	out := make([]SenderFileState, len(files))
	for i, f := range files {
		out[i] = SenderFileState{
			Idx: f.Idx, Name: f.Name, Size: f.Size, Mime: f.Mime,
			LastModified: f.LastModified, BlockSize: f.BlockSize, Blocks: f.Blocks,
			FileDigest: f.FileDigest,
		}
	}
	return out
}

// ValidateSenderRecord enforces the schema-v2 invariants, including the self-check that the
// stored manifest fingerprint is exactly what the stored transfer id + file set produce —
// the same identity the receiver's durable journal binds. Any deviation fails closed. The
// optional resume secret must be the exact version-1 64-hex credential envelope (V13-PR07);
// an arbitrary old opaque value is never reinterpreted as a valid key.
func ValidateSenderRecord(rec SenderRecord) error {
	switch {
	case rec.SchemaVersion != senderSchemaVersion:
		return wire.Errorf(wire.CodeStorage, "sender: corrupt schema version %d", rec.SchemaVersion)
	case !isLowerHex32(rec.TransferID):
		return wire.Errorf(wire.CodeStorage, "sender: malformed transferId")
	case !isLowerHex64(rec.ManifestFingerprint):
		return wire.Errorf(wire.CodeStorage, "sender: malformed manifestFingerprint")
	case rec.ProtocolVersion == "" || rec.ProtocolVersion != wire.ProtocolVersion:
		return wire.Errorf(wire.CodeCompat, "sender: unsupported protocol version %q", rec.ProtocolVersion)
	case rec.CreatedAt < 0 || rec.UpdatedAt < rec.CreatedAt:
		return wire.Errorf(wire.CodeStorage, "sender: corrupt timestamps")
	case len(rec.Paths) == 0:
		return wire.Errorf(wire.CodeStorage, "sender: missing source paths")
	case len(rec.Files) == 0:
		return wire.Errorf(wire.CodeStorage, "sender: missing file set")
	}
	// The record is created from canonical paths; a record whose entries would not
	// canonicalize (relative or unclean) could never match a Lookup and is corrupt.
	for _, p := range rec.Paths {
		if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return wire.Errorf(wire.CodeStorage, "sender: source paths are not canonical")
		}
	}
	// The optional resume credential (V13-PR07) must be the exact version-1 64-hex
	// envelope; nothing else is a valid key.
	if rec.ResumeSecret != nil {
		if _, err := wire.DecodeResumeSecretEnvelope(rec.ResumeSecret); err != nil {
			return err
		}
	}
	var total int64
	for i, f := range rec.Files {
		if f.Idx != i {
			return wire.Errorf(wire.CodeStorage, "sender: non-contiguous file indexes")
		}
		if f.Size < 0 || f.LastModified < 0 || f.BlockSize <= 0 ||
			f.BlockSize > wire.MaxManifestBlockBytes || f.Blocks < 0 {
			return wire.Errorf(wire.CodeStorage, "sender: invalid file entry %d", i)
		}
		if _, err := wire.NormalizeTransferPath(f.Name); err != nil {
			return wire.Errorf(wire.CodeStorage, "sender: unsafe file name %q", f.Name)
		}
		wantBlocks := int((f.Size-1)/int64(f.BlockSize) + 1)
		if f.Size == 0 {
			wantBlocks = 0
		}
		if f.Blocks != wantBlocks {
			return wire.Errorf(wire.CodeStorage, "sender: file %d block count %d does not match size %d / blockSize %d",
				i, f.Blocks, f.Size, f.BlockSize)
		}
		if !isLowerHex64(f.FileDigest) {
			return wire.Errorf(wire.CodeStorage, "sender: malformed file digest for %q", f.Name)
		}
		if f.Size > math.MaxInt64-total {
			return wire.Errorf(wire.CodeStorage, "sender: total size overflow")
		}
		total += f.Size
	}
	// Self-verifying identity: the fingerprint claim must equal the fingerprint of the
	// stored transfer id + file set (the exact bytes the receiver journal binds).
	manifest := wire.Manifest{TransferID: rec.TransferID, Files: make([]wire.FileEntry, len(rec.Files)), TotalSize: total}
	for i, f := range rec.Files {
		manifest.Files[i] = wire.FileEntry{
			Idx: f.Idx, Name: f.Name, Size: f.Size, Mime: f.Mime,
			LastModified: f.LastModified, BlockSize: f.BlockSize, Blocks: f.Blocks,
			FileDigest: f.FileDigest,
		}
	}
	fp, err := wire.ManifestFingerprint(manifest)
	if err != nil {
		return err
	}
	if fp != rec.ManifestFingerprint {
		return wire.Errorf(wire.CodeStorage, "sender: record fingerprint does not match its file set (corrupt or tampered)")
	}
	return nil
}

// encodeSenderRecord produces the canonical file encoding: the checksum covers the exact
// bytes of every other field (same no-HTML-escape, no-trailing-newline rules as the wire
// codec and journal, byte-identical to JSON.stringify so the web twin can share the
// schema).
func encodeSenderRecord(rec SenderRecord) ([]byte, error) {
	if err := ValidateSenderRecord(rec); err != nil {
		return nil, err
	}
	rec.Checksum = ""
	body, err := marshalRecordJSON(rec)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	rec.Checksum = hex.EncodeToString(sum[:])
	return marshalRecordJSON(rec)
}

func decodeSenderRecord(data []byte) (SenderRecord, error) {
	// Peek the schema version from the first JSON value only (trailing data is left for the
	// strict per-version decoder to reject with its own fail-closed message).
	var head struct {
		SchemaVersion int `json:"schemaVersion"`
	}
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&head); err != nil {
		return SenderRecord{}, wire.Errorf(wire.CodeStorage, "sender: malformed record: %v", err)
	}
	switch head.SchemaVersion {
	case senderSchemaVersionLegacy:
		return decodeSenderRecordV1(data)
	case senderSchemaVersion:
		return decodeSenderRecordV2(data)
	default:
		if head.SchemaVersion > senderSchemaVersion {
			return SenderRecord{}, wire.Errorf(wire.CodeCompat,
				"sender: record schema version %d is newer than this build supports (%d)",
				head.SchemaVersion, senderSchemaVersion)
		}
		return SenderRecord{}, wire.Errorf(wire.CodeStorage, "sender: corrupt schema version %d", head.SchemaVersion)
	}
}

// decodeSenderRecordV2 is the current-schema decode: strict parse, checksum verification
// over the v2 body (which may carry the resume-secret envelope), then validation.
func decodeSenderRecordV2(data []byte) (SenderRecord, error) {
	var rec SenderRecord
	if err := unmarshalStrictRecord(data, &rec); err != nil {
		return SenderRecord{}, wire.Errorf(wire.CodeStorage, "sender: malformed record: %v", err)
	}
	if err := verifyRecordChecksum(&rec); err != nil {
		return SenderRecord{}, err
	}
	if err := ValidateSenderRecord(rec); err != nil {
		return SenderRecord{}, err
	}
	return rec, nil
}

// decodeSenderRecordV1 accepts a pre-PR07 schema-v1 record and migrates it in memory to the
// current schema: the v1 checksum is verified over the exact v1 body, then the record is
// re-versioned as v2 with NO cross-session auth material (the original session master is
// gone, so a resume secret is never fabricated for an old record). A re-save re-encodes it
// as v2 with a fresh checksum.
func decodeSenderRecordV1(data []byte) (SenderRecord, error) {
	var rec SenderRecord
	if err := unmarshalStrictRecord(data, &rec); err != nil {
		return SenderRecord{}, wire.Errorf(wire.CodeStorage, "sender: malformed record: %v", err)
	}
	// Verify the checksum over the exact v1 body (schemaVersion 1, no resumeSecret).
	stored := rec.Checksum
	if !isLowerHex64(stored) {
		return SenderRecord{}, wire.Errorf(wire.CodeStorage, "sender: malformed checksum")
	}
	rec.Checksum = ""
	rec.SchemaVersion = senderSchemaVersionLegacy
	body, err := marshalRecordJSON(rec)
	if err != nil {
		return SenderRecord{}, wire.Errorf(wire.CodeStorage, "sender: %v", err)
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != stored {
		return SenderRecord{}, wire.Errorf(wire.CodeStorage, "sender: checksum mismatch (corrupt or tampered)")
	}
	// Migrate: re-version to the current schema. The v1 record has no resume secret and one
	// is never fabricated; the checksum is left empty until a re-save recomputes it.
	rec.SchemaVersion = senderSchemaVersion
	rec.ResumeSecret = nil
	rec.Checksum = ""
	if err := ValidateSenderRecord(rec); err != nil {
		return SenderRecord{}, err
	}
	return rec, nil
}

// verifyRecordChecksum verifies a record's stored checksum over the exact canonical body of
// every other field (the caller must already have strict-decoded `rec`).
func verifyRecordChecksum(rec *SenderRecord) error {
	stored := rec.Checksum
	if !isLowerHex64(stored) {
		return wire.Errorf(wire.CodeStorage, "sender: malformed checksum")
	}
	rec.Checksum = ""
	body, err := marshalRecordJSON(rec)
	if err != nil {
		return wire.Errorf(wire.CodeStorage, "sender: %v", err)
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != stored {
		return wire.Errorf(wire.CodeStorage, "sender: checksum mismatch (corrupt or tampered)")
	}
	rec.Checksum = stored
	return nil
}

// marshalRecordJSON is the canonical JSON encoder for sender records: no HTML escaping and
// no trailing newline, byte-identical to JavaScript's JSON.stringify.
func marshalRecordJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// unmarshalStrictRecord decodes exactly one JSON value into v, rejecting unknown fields
// and trailing data so an unexpected field or a torn tail fails closed.
func unmarshalStrictRecord(data []byte, v any) error {
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

// writeRecordAtomic writes the canonical encoding through the atomic-replacement primitive:
// a temp file in the same directory, fsynced, closed, then renamed over the record, so a
// crash at any point leaves either the old record or the complete new one — never a torn
// mix. The temp file inherits CreateTemp's 0600 mode, keeping the local paths and identity
// material private to the user; the parent directory is fsynced afterwards (best effort).
func writeRecordAtomic(path string, rec SenderRecord) error {
	data, err := encodeSenderRecord(rec)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return wire.Errorf(wire.CodeStorage, "sender: create temp: %v", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return wire.Errorf(wire.CodeStorage, "sender: write temp: %v", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return wire.Errorf(wire.CodeStorage, "sender: sync temp: %v", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return wire.Errorf(wire.CodeStorage, "sender: close temp: %v", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return wire.Errorf(wire.CodeStorage, "sender: replace: %v", err)
	}
	syncSenderDir(dir)
	return nil
}

// syncSenderDir fsyncs a directory so a rename inside it is durable. POSIX only; Windows
// and filesystems that reject directory sync are best-effort (matching wire's journal
// writer).
func syncSenderDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer func() { _ = d.Close() }()
	_ = d.Sync()
}

func isLowerHex32(s string) bool { return isLowerHexLen(s, 32) }

func isLowerHex64(s string) bool { return isLowerHexLen(s, 64) }

func isLowerHexLen(s string, n int) bool {
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
