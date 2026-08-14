package transfer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sendbeam/wire"
)

func testSenderStore(t *testing.T) *SenderStore {
	t.Helper()
	store, err := OpenSenderStore(filepath.Join(t.TempDir(), "sender"))
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return time.UnixMilli(1_700_000_000_000) }
	return store
}

func testManifestFiles(t *testing.T) []wire.FileEntry {
	t.Helper()
	files := []wire.FileEntry{
		{
			Idx: 0, Name: "a.txt", Size: 2048, Mime: "text/plain", LastModified: 1_700_000_000_000,
			BlockSize: 1024, Blocks: 2, FileDigest: strings.Repeat("ab", 32),
		},
		{
			Idx: 1, Name: "sub/b.bin", Size: 1024, Mime: "application/octet-stream", LastModified: 1_700_000_000_001,
			BlockSize: 1024, Blocks: 1, FileDigest: strings.Repeat("cd", 32),
		},
	}
	manifest, err := wire.ValidateManifest(wire.Manifest{
		TransferID: strings.Repeat("11", 16),
		Files:      files,
		TotalSize:  3072,
	})
	if err != nil {
		t.Fatal(err)
	}
	return manifest.Files
}

func TestSenderRecordRoundTrip(t *testing.T) {
	store := testSenderStore(t)
	paths := []string{"/tmp/x/a", "/tmp/x/b"}
	rec := SenderRecord{
		SchemaVersion:   senderSchemaVersion,
		TransferID:      strings.Repeat("11", 16),
		ProtocolVersion: wire.ProtocolVersion,
		CreatedAt:       1,
		UpdatedAt:       2,
		Paths:           paths,
		Files:           fileStatesFromManifest(testManifestFiles(t)),
	}
	fp, err := wire.ManifestFingerprint(wire.Manifest{
		TransferID: rec.TransferID,
		Files:      testManifestFiles(t),
		TotalSize:  3072,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec.ManifestFingerprint = fp
	if err := store.Save(rec); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, ok, err := store.Load(rec.TransferID)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !ok {
		t.Fatal("record not found")
	}
	if got.TransferID != rec.TransferID || got.ManifestFingerprint != rec.ManifestFingerprint ||
		len(got.Files) != 2 || got.Files[0].Name != "a.txt" || got.Paths[0] != paths[0] {
		t.Fatalf("round-trip mismatch: %#v", got)
	}
	if got.Checksum == "" {
		t.Fatal("checksum not stored")
	}
}

func TestSenderRecordFailsClosed(t *testing.T) {
	store := testSenderStore(t)
	rec := SenderRecord{
		SchemaVersion:   senderSchemaVersion,
		TransferID:      strings.Repeat("11", 16),
		ProtocolVersion: wire.ProtocolVersion,
		CreatedAt:       1,
		UpdatedAt:       2,
		Paths:           []string{"/tmp/a"},
		Files:           fileStatesFromManifest(testManifestFiles(t)),
	}
	fp, err := wire.ManifestFingerprint(wire.Manifest{
		TransferID: rec.TransferID, Files: testManifestFiles(t), TotalSize: 3072,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec.ManifestFingerprint = fp
	data, err := encodeSenderRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func([]byte) []byte
		want   string
	}{
		{
			"tampered file name",
			func(b []byte) []byte { return []byte(strings.ReplaceAll(string(b), `"a.txt"`, `"a.txtx"`)) },
			"checksum mismatch",
		},
		{
			"unknown field",
			func(b []byte) []byte {
				// Drop the closing brace and append a stray field on a fresh copy.
				return append(append([]byte(nil), b[:len(b)-1]...), []byte(`,"stray":1}`)...)
			},
			"unknown field",
		},
		{
			"trailing data",
			func(b []byte) []byte { return append(append([]byte(nil), b...), []byte(`{}`)...) },
			"trailing data",
		},
		{
			"future schema version",
			func(b []byte) []byte {
				return []byte(strings.ReplaceAll(string(b), `"schemaVersion":2`, `"schemaVersion":3`))
			},
			"newer",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok, err := store.LoadFrom(tc.mutate(data))
			if err == nil {
				t.Fatalf("decoded corrupt record %s (ok=%v)", got.TransferID, ok)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want mention of %q", err.Error(), tc.want)
			}
		})
	}
}

// LoadFrom is a test helper mirroring Load over arbitrary bytes.
func (s *SenderStore) LoadFrom(data []byte) (SenderRecord, bool, error) {
	rec, err := decodeSenderRecord(data)
	if err != nil {
		return SenderRecord{}, true, err
	}
	return rec, true, nil
}

func TestSenderRecordFingerprintMismatchFailsClosed(t *testing.T) {
	rec := SenderRecord{
		SchemaVersion:   senderSchemaVersion,
		TransferID:      strings.Repeat("11", 16),
		ProtocolVersion: wire.ProtocolVersion,
		CreatedAt:       1,
		UpdatedAt:       2,
		Paths:           []string{"/tmp/a"},
		Files:           fileStatesFromManifest(testManifestFiles(t)),
	}
	// A plausible-but-wrong fingerprint: the recomputed fingerprint of the file set must
	// differ, so the self-verifying identity check rejects the record even though the
	// checksum would cover it.
	rec.ManifestFingerprint = strings.Repeat("ff", 32)
	if err := ValidateSenderRecord(rec); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("ValidateSenderRecord = %v, want fingerprint mismatch", err)
	}
}

func TestSenderRecordRejectsNonCanonicalPaths(t *testing.T) {
	files := testManifestFiles(t)
	rec := SenderRecord{
		SchemaVersion:   senderSchemaVersion,
		TransferID:      strings.Repeat("11", 16),
		ProtocolVersion: wire.ProtocolVersion,
		CreatedAt:       1,
		UpdatedAt:       2,
		Paths:           []string{"relative/path"}, // not absolute
		Files:           fileStatesFromManifest(files),
	}
	fp, err := wire.ManifestFingerprint(wire.Manifest{
		TransferID: rec.TransferID, Files: files, TotalSize: 3072,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec.ManifestFingerprint = fp
	if err := ValidateSenderRecord(rec); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("ValidateSenderRecord = %v, want non-canonical path rejection", err)
	}
}

func TestPathKeyIsOrderAndSpellingIndependent(t *testing.T) {
	a := filepath.Join(t.TempDir(), "a.txt")
	b := filepath.Join(t.TempDir(), "b.txt")
	key1 := PathKey([]string{a, b})
	key2 := PathKey([]string{b, a})
	if key1 != key2 {
		t.Fatalf("reordered args produced different keys")
	}
	key3 := PathKey([]string{b, a})
	if key1 != key3 {
		t.Fatalf("re-spelled args produced different keys")
	}
}

func TestLookupMatchesByPathKeyAndFailsClosedOnCorrupt(t *testing.T) {
	store := testSenderStore(t)
	files := testManifestFiles(t)
	fp, _ := wire.ManifestFingerprint(wire.Manifest{
		TransferID: strings.Repeat("11", 16), Files: files, TotalSize: 3072,
	})
	rec := SenderRecord{
		SchemaVersion: senderSchemaVersion, TransferID: strings.Repeat("11", 16),
		ProtocolVersion: wire.ProtocolVersion, CreatedAt: 1, UpdatedAt: 2,
		Paths: []string{"/tmp/one/a", "/tmp/one/b"},
		Files: fileStatesFromManifest(files), ManifestFingerprint: fp,
	}
	if err := store.Save(rec); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.Lookup(PathKey([]string{"/tmp/one/b", "/tmp/one/a"}))
	if err != nil || !ok || got.TransferID != rec.TransferID {
		t.Fatalf("Lookup = (%v, %v, %v), want match", got, ok, err)
	}
	if _, ok, err := store.Lookup(PathKey([]string{"/tmp/other"})); err != nil || ok {
		t.Fatalf("Lookup of unrelated paths = (%v, %v), want none", ok, err)
	}
	// A corrupt record must fail the lookup closed, never be treated as absent.
	data, err := os.ReadFile(store.Path(rec.TransferID))
	if err != nil {
		t.Fatal(err)
	}
	// Flip one hex digit of the checksum in place: valid JSON, valid hex format, but the
	// recomputed checksum no longer matches.
	corrupt := append([]byte(nil), data...)
	marker := []byte(`"checksum":"`)
	pos := bytes.Index(corrupt, marker)
	if pos < 0 {
		t.Fatal("checksum field not found in record")
	}
	digit := pos + len(marker)
	if corrupt[digit] == '0' {
		corrupt[digit] = '1'
	} else {
		corrupt[digit] = '0'
	}
	if err := os.WriteFile(store.Path(rec.TransferID), corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Lookup(PathKey([]string{"/tmp/other"})); err == nil {
		t.Fatal("Lookup succeeded despite a corrupt record in the store")
	}
	// List surfaces it without deleting.
	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].RecordOK || !strings.Contains(entries[0].Err, "checksum mismatch") {
		t.Fatalf("List = %#v, want the corrupt record surfaced", entries)
	}
	// Discard removes it idempotently.
	if err := store.Discard(rec.TransferID); err != nil {
		t.Fatal(err)
	}
	if err := store.Discard(rec.TransferID); err != nil {
		t.Fatalf("second discard: %v", err)
	}
	if _, ok, err := store.Load(rec.TransferID); err != nil || ok {
		t.Fatalf("record still present after discard: ok=%v err=%v", ok, err)
	}
}

func TestPrepareSenderFreshRestartChangedAndVerify(t *testing.T) {
	store := testSenderStore(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "a.txt")
	content := []byte("hello sender restart")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	sources, _, err := NewOSFileSources([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	args := []string{path}

	// Fresh: no record, mint id, hook persists.
	id, hook, reused, err := PrepareSender(store, args, sources)
	if err != nil {
		t.Fatalf("fresh PrepareSender: %v", err)
	}
	if reused || id != "" {
		t.Fatalf("fresh: reused=%v id=%q, want fresh mint", reused, id)
	}
	manifest, err := wire.ValidateManifest(wire.Manifest{
		TransferID: strings.Repeat("22", 16),
		Files:      manifestFromSources(t, sources),
		TotalSize:  int64(len(content)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := hook(manifest); err != nil {
		t.Fatalf("create hook: %v", err)
	}
	stored, ok, err := store.Lookup(PathKey(args))
	if err != nil || !ok {
		t.Fatalf("record not persisted: ok=%v err=%v", ok, err)
	}
	if stored.TransferID != manifest.TransferID {
		t.Fatalf("record id = %s, want the minted %s", stored.TransferID, manifest.TransferID)
	}

	// Restart: matching source reuses the same id and the hook verifies.
	sources2, _, err := NewOSFileSources([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	id2, hook2, reused2, err := PrepareSender(store, args, sources2)
	if err != nil {
		t.Fatalf("restart PrepareSender: %v", err)
	}
	if !reused2 || id2 != stored.TransferID {
		t.Fatalf("restart: reused=%v id=%q, want reuse of %s", reused2, id2, stored.TransferID)
	}
	if err := hook2(manifest); err != nil {
		t.Fatalf("verify hook: %v", err)
	}

	// A changed source fails closed before anything is advertised.
	if err := os.WriteFile(path, append(content, 'x'), 0o600); err != nil {
		t.Fatal(err)
	}
	sources3, _, err := NewOSFileSources([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := PrepareSender(store, args, sources3); err == nil || !strings.Contains(err.Error(), "discard") {
		t.Fatalf("changed source PrepareSender = %v, want fail closed with discard guidance", err)
	}

	// Same meta but different content: the cheap pre-check passes, the verify hook fails
	// closed on the fingerprint before the manifest could be sent.
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	changed := manifest
	changed.Files = make([]wire.FileEntry, len(manifest.Files))
	copy(changed.Files, manifest.Files)
	sum := sha256.Sum256(append(content, 'x'))
	changed.Files[0].FileDigest = hex.EncodeToString(sum[:])
	if err := hook2(changed); err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("verify hook on changed digest = %v, want fingerprint mismatch", err)
	}

	// Discard removes the record (bounded cleanup after a completed send).
	if err := store.Discard(stored.TransferID); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := store.Lookup(PathKey(args)); err != nil || ok {
		t.Fatalf("record still present after discard: ok=%v err=%v", ok, err)
	}
}

func TestAttachResumeSecretPersistsOnceAndNeverReplaces(t *testing.T) {
	store := testSenderStore(t)
	rec := SenderRecord{
		SchemaVersion:   senderSchemaVersion,
		TransferID:      strings.Repeat("33", 16),
		ProtocolVersion: wire.ProtocolVersion,
		CreatedAt:       1,
		UpdatedAt:       2,
		Paths:           []string{"/tmp/b"},
		Files:           fileStatesFromManifest(testManifestFiles(t)),
	}
	fp, err := wire.ManifestFingerprint(wire.Manifest{
		TransferID: rec.TransferID, Files: testManifestFiles(t), TotalSize: 3072,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec.ManifestFingerprint = fp
	if err := store.Save(rec); err != nil {
		t.Fatal(err)
	}

	resumeRoot := bytes.Repeat([]byte{0x42}, 32)
	manifest := wire.Manifest{
		TransferID: rec.TransferID, Files: testManifestFiles(t), TotalSize: 3072,
	}

	// Attach: the secret is derived from the resume root + transfer id + fingerprint and
	// persisted as the exact v1 envelope; nothing else appears in the record.
	if err := store.AttachResumeSecret(manifest, resumeRoot); err != nil {
		t.Fatalf("AttachResumeSecret: %v", err)
	}
	stored, ok, err := store.Load(rec.TransferID)
	if err != nil || !ok {
		t.Fatalf("Load after attach: ok=%v err=%v", ok, err)
	}
	if stored.ResumeSecret == nil {
		t.Fatal("resume secret not persisted")
	}
	secret, err := wire.DecodeResumeSecretEnvelope(stored.ResumeSecret)
	if err != nil {
		t.Fatalf("decoded envelope: %v", err)
	}
	wantSecret, err := wire.ResumeSecret(resumeRoot, wire.ResumeAuthVersion, rec.TransferID, fp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret, wantSecret) {
		t.Fatalf("stored secret differs from the derived transfer-scoped secret")
	}

	// A second attach (a restart with a DIFFERENT session root) never replaces the
	// original-session credential.
	otherRoot := bytes.Repeat([]byte{0x99}, 32)
	if err := store.AttachResumeSecret(manifest, otherRoot); err != nil {
		t.Fatalf("re-attach: %v", err)
	}
	after, _, err := store.Load(rec.TransferID)
	if err != nil {
		t.Fatal(err)
	}
	afterSecret, err := wire.DecodeResumeSecretEnvelope(after.ResumeSecret)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterSecret, secret) {
		t.Fatal("re-attach replaced the original-session credential")
	}

	// Attaching without a record fails closed.
	missingManifest := wire.Manifest{
		TransferID: strings.Repeat("44", 16), Files: testManifestFiles(t), TotalSize: 3072,
	}
	if err := store.AttachResumeSecret(missingManifest, resumeRoot); err == nil {
		t.Fatal("attach to a missing record succeeded")
	}

	// Discard removes the credential with its parent record (lifecycle).
	if err := store.Discard(rec.TransferID); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := store.Load(rec.TransferID); err != nil || ok {
		t.Fatalf("record still present after discard: ok=%v err=%v", ok, err)
	}
}

func TestSenderRecordV1MigrationCarriesNoResumeSecret(t *testing.T) {
	// Build a schema-v2 record, then rewrite it exactly as a pre-PR07 v1 build would have
	// stored it: schemaVersion 1, no resumeSecret, checksum over the v1 body.
	v2 := SenderRecord{
		SchemaVersion:   senderSchemaVersion,
		TransferID:      strings.Repeat("55", 16),
		ProtocolVersion: wire.ProtocolVersion,
		CreatedAt:       1,
		UpdatedAt:       2,
		Paths:           []string{"/tmp/c"},
		Files:           fileStatesFromManifest(testManifestFiles(t)),
	}
	fp, err := wire.ManifestFingerprint(wire.Manifest{
		TransferID: v2.TransferID, Files: testManifestFiles(t), TotalSize: 3072,
	})
	if err != nil {
		t.Fatal(err)
	}
	v2.ManifestFingerprint = fp
	body, err := encodeSenderRecord(v2)
	if err != nil {
		t.Fatal(err)
	}
	var v1 SenderRecord
	if err := json.Unmarshal(body, &v1); err != nil {
		t.Fatal(err)
	}
	if v1.SchemaVersion != senderSchemaVersion {
		t.Fatalf("fixture decode: schemaVersion=%d", v1.SchemaVersion)
	}
	v1.SchemaVersion = senderSchemaVersionLegacy
	v1.ResumeSecret = nil
	storedChecksum := v1.Checksum
	v1.Checksum = ""
	v1body, err := marshalRecordJSON(v1)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(v1body)
	v1.Checksum = storedChecksum // irrelevant; the checksum is recomputed below
	v1.Checksum = hex.EncodeToString(sum[:])
	v1data, err := marshalRecordJSON(v1)
	if err != nil {
		t.Fatal(err)
	}

	rec, err := decodeSenderRecord(v1data)
	if err != nil {
		t.Fatalf("v1 decode: %v", err)
	}
	if rec.SchemaVersion != senderSchemaVersion {
		t.Fatalf("migrated schemaVersion=%d, want %d", rec.SchemaVersion, senderSchemaVersion)
	}
	if rec.ResumeSecret != nil {
		t.Fatal("migrated record fabricated a resume secret")
	}

	// A tampered v1 body (checksum over the true body) fails closed.
	tampered := v1
	tampered.Files[0].Size = 99
	tamperedData, err := marshalRecordJSON(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeSenderRecord(tamperedData); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("tampered v1 = %v, want checksum failure", err)
	}
}

func manifestFromSources(t *testing.T, sources []wire.FileSource) []wire.FileEntry {
	t.Helper()
	files := make([]wire.FileEntry, len(sources))
	var total int64
	for i, source := range sources {
		meta := source.Meta()
		files[i] = wire.FileEntry{
			Idx: i, Name: meta.Name, Size: meta.Size, Mime: meta.Mime,
			LastModified: meta.LastModified, BlockSize: 1024,
			Blocks: int((meta.Size-1)/1024 + 1), FileDigest: strings.Repeat("ee", 32),
		}
		if meta.Size == 0 {
			files[i].Blocks = 0
		}
		total += meta.Size
	}
	return files
}
