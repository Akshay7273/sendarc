package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// journalTestManifest is the canonical two-file manifest used across journal tests: a
// 2048-byte file (2 blocks of 1024) and a 1024-byte file (1 block), 3072 bytes total.
func journalTestManifest() Manifest {
	m := NewManifest([]FileEntry{
		{Idx: 0, Name: "a.txt", Size: 2048, Mime: "text/plain", LastModified: 1700000000,
			BlockSize: 1024, Blocks: 2, FileDigest: strings.Repeat("ab", 32)},
		{Idx: 1, Name: "b.bin", Size: 1024, Mime: "application/octet-stream", LastModified: 1700000001,
			BlockSize: 1024, Blocks: 1, FileDigest: strings.Repeat("cd", 32)},
	}, 3072)
	m.TransferID = "0123456789abcdef0123456789abcdef"
	return *m
}

func journalTestIdentities() (JournalIdentity, JournalIdentity) {
	return JournalIdentity{Version: 1, Value: "736f757263652d73616d706c65"}, // hex("source-sample")
		JournalIdentity{Version: 1, Value: "646573742d73616d706c65"} // hex("dest-sample")
}

func journalTestTimes() (time.Time, time.Time) {
	return time.UnixMilli(1723500000000), time.UnixMilli(1723500060000)
}

// journalVectorSample builds the exact journal pinned by docs/test-vectors/durable-journal.json:
// zero checkpoints at creation, then file 0 committed through its first block with a digest
// checkpoint (V13-PR05) so the pinned schema also carries the optional field.
func journalVectorSample(t *testing.T) DurableJournal {
	t.Helper()
	created, updated := journalTestTimes()
	source, destination := journalTestIdentities()
	j, err := NewJournal("0123456789abcdef0123456789abcdef", journalTestManifest(), source, destination, created)
	if err != nil {
		t.Fatalf("NewJournal: %v", err)
	}
	if err := j.CommitBlocks(0, 1, updated); err != nil {
		t.Fatalf("CommitBlocks: %v", err)
	}
	// A real Go sha256 state covering the committed prefix (1024 zero bytes, the sample
	// file's first block): the state bytes are opaque but the envelope must round-trip
	// byte-identically in both languages.
	state, err := sampleDigestState(t, 1024)
	if err != nil {
		t.Fatalf("sample digest state: %v", err)
	}
	if err := j.SetDigestCheckpoint(0, &JournalDigestCheckpoint{
		Format:          DigestCheckpointFormatGoStdlib,
		CommittedBlocks: 1,
		CommittedBytes:  1024,
		State:           hex.EncodeToString(state),
	}); err != nil {
		t.Fatalf("SetDigestCheckpoint: %v", err)
	}
	return j
}

// sampleDigestState serializes the Go sha256 state after feeding n zero bytes.
func sampleDigestState(t *testing.T, n int64) ([]byte, error) {
	t.Helper()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(zeroReader{}, n)); err != nil {
		return nil, err
	}
	return (&sha256Digest{h: h}).MarshalState()
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func TestJournalRoundTrip(t *testing.T) {
	j := journalVectorSample(t)
	encoded, err := EncodeJournal(j)
	if err != nil {
		t.Fatalf("EncodeJournal: %v", err)
	}
	decoded, err := DecodeJournal(encoded)
	if err != nil {
		t.Fatalf("DecodeJournal: %v", err)
	}
	if decoded.TransferID != j.TransferID || decoded.ManifestFingerprint != j.ManifestFingerprint ||
		decoded.BlockSize != j.BlockSize || decoded.CreatedAt != j.CreatedAt || decoded.UpdatedAt != j.UpdatedAt {
		t.Fatalf("round-trip lost fields: %#v", decoded)
	}
	if len(decoded.Files) != 2 || decoded.Files[0].CommittedBlocks != 1 || decoded.Files[1].CommittedBlocks != 0 {
		t.Fatalf("round-trip lost checkpoints: %#v", decoded.Files)
	}
	// Re-encoding a decoded journal is byte-identical (canonical form).
	again, err := EncodeJournal(decoded)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if !bytes.Equal(again, encoded) {
		t.Fatalf("re-encode is not byte-identical:\n got %s\nwant %s", again, encoded)
	}
	// A journal with no resume secret round-trips without the field.
	if bytes.Contains(encoded, []byte("resumeSecret")) {
		t.Fatalf("unexpected resumeSecret in output: %s", encoded)
	}
}

func TestJournalRequiredFields(t *testing.T) {
	base := journalVectorSample(t)
	cases := []struct {
		name   string
		mutate func(*DurableJournal)
	}{
		{"empty transferId", func(j *DurableJournal) { j.TransferID = "" }},
		{"short transferId", func(j *DurableJournal) { j.TransferID = "abcd" }},
		{"uppercase transferId", func(j *DurableJournal) { j.TransferID = strings.ToUpper(base.TransferID) }},
		{"empty fingerprint", func(j *DurableJournal) { j.ManifestFingerprint = "" }},
		{"missing protocol version", func(j *DurableJournal) { j.ProtocolVersion = "" }},
		{"wrong protocol version", func(j *DurableJournal) { j.ProtocolVersion = "sendbeam/2" }},
		{"zero resume version", func(j *DurableJournal) { j.ResumeVersion = 0 }},
		{"zero schema version", func(j *DurableJournal) { j.SchemaVersion = 0 }},
		{"zero block size", func(j *DurableJournal) { j.BlockSize = 0 }},
		{"huge block size", func(j *DurableJournal) { j.BlockSize = MaxManifestBlockBytes + 1 }},
		{"zero createdAt", func(j *DurableJournal) { j.CreatedAt = 0 }},
		{"updatedAt before createdAt", func(j *DurableJournal) { j.UpdatedAt = j.CreatedAt - 1 }},
		{"empty files", func(j *DurableJournal) { j.Files = nil }},
		{"too many files", func(j *DurableJournal) { j.Files = append(j.Files, make([]JournalFileState, MaxTransferFiles)...) }},
		{"missing source identity", func(j *DurableJournal) { j.SourceIdentity = JournalIdentity{} }},
		{"missing destination value", func(j *DurableJournal) { j.DestinationIdentity.Value = "" }},
		{"bad identity charset", func(j *DurableJournal) { j.SourceIdentity.Value = "not hex or b64!!" }},
		{"unsupported identity version", func(j *DurableJournal) { j.SourceIdentity.Version = 2 }},
		{"empty resume secret value", func(j *DurableJournal) { j.ResumeSecret = &JournalResumeSecret{Version: 1, Value: ""} }},
		{"unsupported resume secret version", func(j *DurableJournal) {
			j.ResumeSecret = &JournalResumeSecret{Version: 2, Value: strings.Repeat("ab", 32)}
		}},
		{"resume secret wrong length", func(j *DurableJournal) { j.ResumeSecret = &JournalResumeSecret{Version: 1, Value: "00"} }},
		{"resume secret invalid encoding", func(j *DurableJournal) { j.ResumeSecret = &JournalResumeSecret{Version: 1, Value: "not hex or b64!!"} }},
		{"resume secret uppercase hex", func(j *DurableJournal) {
			j.ResumeSecret = &JournalResumeSecret{Version: 1, Value: strings.ToUpper(journalVectorSecretValue)}
		}},
		{"bad file digest", func(j *DurableJournal) { j.Files[0].FileDigest = "xyz" }},
		{"file blocks mismatch", func(j *DurableJournal) { j.Files[0].Blocks = 1 }},
		{"file size negative", func(j *DurableJournal) { j.Files[0].Size = -1 }},
		{"file block size differs from journal", func(j *DurableJournal) { j.Files[1].BlockSize = 512 }},
		{"non-contiguous file indexes", func(j *DurableJournal) { j.Files[1].Idx = 2 }},
		{"duplicate paths", func(j *DurableJournal) { j.Files[1].Name = "a.txt" }},
		{"unsafe path", func(j *DurableJournal) { j.Files[0].Name = "../escape.txt" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := base
			bad.Checksum = ""
			tc.mutate(&bad)
			if err := ValidateJournal(bad); err == nil {
				t.Fatalf("ValidateJournal accepted %s", tc.name)
			}
			if _, err := EncodeJournal(bad); err == nil {
				t.Fatalf("EncodeJournal accepted %s", tc.name)
			}
		})
	}
}

func TestJournalSchemaVersionDispatch(t *testing.T) {
	base, err := EncodeJournal(journalVectorSample(t))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := DecodeJournal(base); err != nil {
		t.Fatalf("version 1 must decode: %v", err)
	}
	for _, future := range []int{2, 99} {
		raw := rewriteJSON(t, base, func(m map[string]any) { m["schemaVersion"] = future })
		_, derr := DecodeJournal(raw)
		if derr == nil || CodeOf(derr) != CodeCompat {
			t.Fatalf("future version %d must fail closed with COMPAT, got %v", future, derr)
		}
		if !strings.Contains(derr.Error(), "newer") {
			t.Fatalf("future version error should name the version policy, got: %v", derr)
		}
	}
	for _, bad := range []int{0, -1} {
		raw := rewriteJSON(t, base, func(m map[string]any) { m["schemaVersion"] = bad })
		_, derr := DecodeJournal(raw)
		if derr == nil || CodeOf(derr) != CodeStorage {
			t.Fatalf("corrupt version %d must fail closed with STORAGE, got %v", bad, derr)
		}
	}
	// A version that is not an integer is corrupt, not "future".
	frac := rewriteJSON(t, base, func(m map[string]any) { m["schemaVersion"] = 1.5 })
	if _, err := DecodeJournal(frac); err == nil {
		t.Fatalf("fractional schema version must fail closed")
	}
	missing := rewriteJSON(t, base, func(m map[string]any) { delete(m, "schemaVersion") })
	_, merr := DecodeJournal(missing)
	if merr == nil || !strings.Contains(merr.Error(), "missing schemaVersion") {
		t.Fatalf("missing schema version must fail closed, got %v", merr)
	}
}

func TestJournalMalformedRejected(t *testing.T) {
	encoded, err := EncodeJournal(journalVectorSample(t))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	cases := map[string][]byte{
		"not json":        []byte(`{`),
		"empty":           nil,
		"array":           []byte(`[1,2,3]`),
		"string":          []byte(`"hello"`),
		"unknown field":   rewriteJSON(t, encoded, func(m map[string]any) { m["masterKey"] = "deadbeef" }),
		"secret-looking":  rewriteJSON(t, encoded, func(m map[string]any) { m["sessionMasterKey"] = strings.Repeat("00", 32) }),
		"trailing data":   append(append([]byte(nil), encoded...), []byte(" x")...),
		"double document": append(append([]byte(nil), encoded...), encoded...),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeJournal(data); err == nil {
				t.Fatalf("DecodeJournal accepted %s", name)
			}
		})
	}
	// Unknown fields must also be rejected even when the checksum field is untouched.
}

func TestJournalTamperedRejected(t *testing.T) {
	encoded, err := EncodeJournal(journalVectorSample(t))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	t.Run("content byte flip", func(t *testing.T) {
		tampered := append([]byte(nil), encoded...)
		// Flip one byte inside the first file name ("a.txt" -> "c.txt" keeps length).
		idx := bytes.Index(tampered, []byte("a.txt"))
		if idx < 0 {
			t.Fatal("name not found in encoded journal")
		}
		tampered[idx] = 'c'
		// A renamed file breaks the fingerprint self-check, so it fails closed either way.
		if _, err := DecodeJournal(tampered); err == nil {
			t.Fatalf("tampered content must fail closed")
		}
	})

	t.Run("checksum byte flip", func(t *testing.T) {
		tampered := append([]byte(nil), encoded...)
		idx := bytes.LastIndex(tampered, []byte(`"checksum":"`))
		if idx < 0 {
			t.Fatal("checksum not found in encoded journal")
		}
		flip := idx + len(`"checksum":"`)
		if tampered[flip] == '0' {
			tampered[flip] = '1'
		} else {
			tampered[flip] = '0'
		}
		if _, err := DecodeJournal(tampered); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
			t.Fatalf("flipped checksum must fail closed, got %v", err)
		}
	})

	t.Run("checkpoint beyond file", func(t *testing.T) {
		raw := rewriteJSON(t, encoded, func(m map[string]any) {
			files := m["files"].([]any)
			f0 := files[0].(map[string]any)
			f0["committedBlocks"] = 99 // > blocks (2)
		})
		if _, err := DecodeJournal(raw); err == nil || !strings.Contains(err.Error(), "out of range") {
			t.Fatalf("impossible high-water must fail closed, got %v", err)
		}
	})

	t.Run("updatedAt moved forward but checksum stale", func(t *testing.T) {
		// A valid, fingerprint-neutral content change with a stale checksum must fail on
		// the checksum — this is the pure tamper-evidence path.
		raw := rewriteJSON(t, encoded, func(m map[string]any) { m["updatedAt"] = 1723500120000 })
		if _, err := DecodeJournal(raw); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
			t.Fatalf("stale-checksum content must fail closed, got %v", err)
		}
	})

	t.Run("checkpoint within bounds but checksum stale", func(t *testing.T) {
		raw := rewriteJSON(t, encoded, func(m map[string]any) {
			files := m["files"].([]any)
			f0 := files[0].(map[string]any)
			f0["committedBlocks"] = 2      // valid claim, but checksum was not recomputed
			delete(f0, "digestCheckpoint") // drop it too: a checkpoint cannot cover the new high-water
		})
		if _, err := DecodeJournal(raw); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
			t.Fatalf("stale-checksum checkpoint must fail closed, got %v", err)
		}
	})

	t.Run("tampered identity", func(t *testing.T) {
		raw := rewriteJSON(t, encoded, func(m map[string]any) {
			src := m["sourceIdentity"].(map[string]any)
			src["value"] = "deadbeef" // structurally fine, checksum stale
		})
		if _, err := DecodeJournal(raw); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
			t.Fatalf("tampered identity must fail closed on checksum, got %v", err)
		}
	})

	t.Run("tampered fingerprint", func(t *testing.T) {
		raw := rewriteJSON(t, encoded, func(m map[string]any) {
			m["manifestFingerprint"] = strings.Repeat("ef", 32) // no longer matches the files
		})
		// The fingerprint self-check catches this before the checksum is even consulted.
		if _, err := DecodeJournal(raw); err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") {
			t.Fatalf("tampered fingerprint must fail closed, got %v", err)
		}
	})
}

// TestJournalFingerprintBinding proves the fingerprint is a semantic binding, not just a
// string: any change to the file set a journal claims (name, size, digest, transferId) is
// rejected even if the checksum were recomputed — ValidateJournal recomputes the
// fingerprint from the journal's own entries and compares.
func TestJournalFingerprintBinding(t *testing.T) {
	base := journalVectorSample(t)
	// Each mutation keeps the journal structurally plausible (valid geometry, valid
	// envelopes) but changes the file set the checkpoints claim, so only the fingerprint
	// self-check can catch it — the way an attacker recomputing the checksum would still
	// be stopped by ValidateJournal.
	tamper := []struct {
		name   string
		mutate func(*DurableJournal)
	}{
		{"renamed file", func(j *DurableJournal) { j.Files[0].Name = "c.txt" }},
		{"swapped digest", func(j *DurableJournal) { j.Files[0].FileDigest = strings.Repeat("ff", 32) }},
		{"changed transferId", func(j *DurableJournal) { j.TransferID = strings.Repeat("11", 16) }},
		{"changed mime", func(j *DurableJournal) { j.Files[0].Mime = "image/png" }},
	}
	for _, tc := range tamper {
		t.Run(tc.name, func(t *testing.T) {
			bad := base
			bad.Checksum = ""
			tc.mutate(&bad)
			err := ValidateJournal(bad)
			if err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") {
				t.Fatalf("fingerprint must bind %s, got %v", tc.name, err)
			}
		})
	}
	// A tampered field that also breaks manifest geometry (size) is caught by geometry
	// validation before the fingerprint check — still fail closed.
	bad := base
	bad.Checksum = ""
	bad.Files[0].Size = 1024
	if err := ValidateJournal(bad); err == nil {
		t.Fatalf("resized file must fail closed")
	}
}

func TestJournalNonBlockAlignedCheckpoint(t *testing.T) {
	encoded, err := EncodeJournal(journalVectorSample(t))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// The schema has no byte-offset field: committedBlocks is a whole-block count, so the
	// only way to express a non-block-aligned claim is a fractional count, which is not a
	// valid integer and must fail closed.
	frac := rewriteJSON(t, encoded, func(m map[string]any) {
		files := m["files"].([]any)
		f0 := files[0].(map[string]any)
		f0["committedBlocks"] = 1.5
	})
	if _, err := DecodeJournal(frac); err == nil {
		t.Fatalf("fractional committedBlocks must fail closed")
	}

	j := journalVectorSample(t)
	got, err := j.CommittedBytes(0)
	if err != nil {
		t.Fatalf("CommittedBytes: %v", err)
	}
	if got != 1024 { // 1 block x 1024
		t.Fatalf("CommittedBytes(file 0) = %d, want 1024", got)
	}
	// Committing every block of file 0 claims exactly the file size (final block capped).
	if err := j.CommitBlocks(0, 2, time.UnixMilli(1723500120000)); err != nil {
		t.Fatalf("CommitBlocks: %v", err)
	}
	if got, _ := j.CommittedBytes(0); got != 2048 {
		t.Fatalf("CommittedBytes(file 0) = %d, want 2048", got)
	}
}

func TestJournalTornTruncated(t *testing.T) {
	encoded, err := EncodeJournal(journalVectorSample(t))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Truncate at many byte positions: a torn journal must never decode, whether the cut
	// lands mid-structure (JSON error) or on a clean field boundary (validation/checksum).
	for cut := 0; cut < len(encoded); cut += 7 {
		if _, err := DecodeJournal(encoded[:cut]); err == nil {
			t.Fatalf("truncated journal at byte %d/%d decoded successfully", cut, len(encoded))
		}
	}
}

func TestJournalCommitBlocksContract(t *testing.T) {
	j := journalVectorSample(t)
	now := time.UnixMilli(1723500120000)

	// Regression is refused.
	if err := j.CommitBlocks(0, 0, now); err == nil {
		t.Fatalf("regression must be refused")
	}
	// Bounds are enforced.
	if err := j.CommitBlocks(0, 3, now); err == nil {
		t.Fatalf("beyond-blocks checkpoint must be refused")
	}
	if err := j.CommitBlocks(0, -1, now); err == nil {
		t.Fatalf("negative checkpoint must be refused")
	}
	if err := j.CommitBlocks(7, 0, now); err == nil {
		t.Fatalf("unknown file must be refused")
	}
	// Advancement stamps UpdatedAt and survives a round-trip.
	if err := j.CommitBlocks(1, 1, now); err != nil {
		t.Fatalf("advance: %v", err)
	}
	if j.UpdatedAt != now.UnixMilli() {
		t.Fatalf("UpdatedAt = %d, want %d", j.UpdatedAt, now.UnixMilli())
	}
	encoded, err := EncodeJournal(j)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeJournal(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Files[1].CommittedBlocks != 1 {
		t.Fatalf("committed checkpoint lost: %#v", decoded.Files)
	}
	// A fully committed file is still a valid journal (progress exactly equals the file).
	if err := j.CommitBlocks(0, 2, now); err != nil {
		t.Fatalf("final commit: %v", err)
	}
	if _, err := EncodeJournal(j); err != nil {
		t.Fatalf("fully committed journal must encode: %v", err)
	}
}

func TestJournalAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "journal.json")

	j := journalVectorSample(t)
	if err := WriteJournalAtomic(path, j); err != nil {
		t.Fatalf("first write: %v", err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if _, err := DecodeJournal(first); err != nil {
		t.Fatalf("written journal must decode: %v", err)
	}

	// No temp files may survive an atomic write.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("leftover temp file %s", e.Name())
		}
	}

	// Overwrite with an advanced checkpoint: the file is replaced atomically.
	if err := j.CommitBlocks(0, 2, time.UnixMilli(1723500120000)); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := WriteJournalAtomic(path, j); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	decoded, err := DecodeJournal(second)
	if err != nil {
		t.Fatalf("overwritten journal must decode: %v", err)
	}
	if decoded.Files[0].CommittedBlocks != 2 {
		t.Fatalf("overwrite did not replace content: %#v", decoded.Files)
	}

	// A failed write (missing parent directory) is an error and creates nothing.
	if err := WriteJournalAtomic(filepath.Join(dir, "missing", "journal.json"), j); err == nil {
		t.Fatalf("write into missing directory must fail")
	}
	if _, err := os.Stat(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed write created something: %v", err)
	}
}

func TestJournalNeverSerializesKeyMaterial(t *testing.T) {
	// The schema is a closed set: no field may carry raw session material. Assert the
	// serialized form of every journal type contains only the documented keys, that a
	// journal loaded with an unexpected key-material field fails closed, and that bytes
	// passed alongside construction never leak into the output.
	forbidden := []string{
		"master", "sessionKey", "sessionkey", "trafficKey", "aeadKey", "aead",
		"counter", "nonce", "invite", "password", "credential", "token", "secret",
	}
	types := []any{DurableJournal{}, JournalFileState{}, JournalIdentity{}, JournalResumeSecret{}}
	for _, typ := range types {
		rv := reflect.TypeOf(typ)
		for i := 0; i < rv.NumField(); i++ {
			tag := rv.Field(i).Tag.Get("json")
			key := strings.Split(tag, ",")[0]
			for _, pattern := range forbidden {
				// resumeSecret is the one documented opaque envelope; its content is
				// versioned and defined by the resume protocol, not raw key material.
				if key == "resumeSecret" {
					continue
				}
				if strings.Contains(strings.ToLower(key), pattern) {
					t.Fatalf("journal field %q matches forbidden key-material pattern %q", key, pattern)
				}
			}
		}
	}

	// Unknown fields — including plausible key-material names — are rejected on load.
	encoded, err := EncodeJournal(journalVectorSample(t))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	for _, key := range []string{"masterKey", "sessionMasterKey", "o2jKey", "counter"} {
		raw := rewriteJSON(t, encoded, func(m map[string]any) { m[key] = strings.Repeat("00", 32) })
		if _, err := DecodeJournal(raw); err == nil {
			t.Fatalf("journal with %q field must fail closed", key)
		}
	}

	// Serializing a journal next to raw session material never embeds it.
	master := []byte("raw-pake-master-key-0000")
	dirKey := []byte("directional-o2j-key-0000")
	j := journalVectorSample(t)
	out, err := EncodeJournal(j)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	for _, secret := range [][]byte{master, dirKey} {
		if bytes.Contains(out, secret) {
			t.Fatalf("serialized journal contains raw key material")
		}
	}
}

func TestJournalChecksumIsWriteTimeDerivation(t *testing.T) {
	// The checksum is recomputed on encode: mutating a decoded journal and re-encoding
	// must produce a valid, updated journal, never one that fails its own checksum.
	j := journalVectorSample(t)
	encoded, err := EncodeJournal(j)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeJournal(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := decoded.CommitBlocks(0, 2, time.UnixMilli(1723500120000)); err != nil {
		t.Fatalf("commit: %v", err)
	}
	reencoded, err := EncodeJournal(decoded)
	if err != nil {
		t.Fatalf("re-encode after mutation: %v", err)
	}
	if _, err := DecodeJournal(reencoded); err != nil {
		t.Fatalf("re-encoded journal must decode: %v", err)
	}
}

func TestJournalResumeSecretV1Credential(t *testing.T) {
	// V13-PR07: version-1 resume secret is the exact 256-bit credential — 64 lowercase hex
	// characters. The envelope round-trips byte-identically and the checksum covers it.
	j := journalVectorSample(t)
	j.ResumeSecret = &JournalResumeSecret{Version: 1, Value: journalVectorSecretValue}
	encoded, err := EncodeJournal(j)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeJournal(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.ResumeSecret == nil || decoded.ResumeSecret.Value != j.ResumeSecret.Value {
		t.Fatalf("resume secret lost: %#v", decoded.ResumeSecret)
	}
	// The secret participates in the checksum: mutating it breaks verification.
	tampered, err := EncodeJournal(j)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	mutated := rewriteJSON(t, tampered, func(m map[string]any) {
		env := m["resumeSecret"].(map[string]any)
		env["value"] = strings.Repeat("cd", 32)
	})
	if _, err := DecodeJournal(mutated); err == nil {
		t.Fatal("tampered resume secret must fail checksum verification")
	}
	// A value that is not the exact 64-hex credential is rejected — an arbitrary old opaque
	// value is never reinterpreted as a valid key.
	for _, value := range []string{"c2VjcmV0LW1hdGVyaWFs", "00", strings.Repeat("ab", 33), "not hex!!"} {
		bad := j
		bad.ResumeSecret.Value = value
		bad.Checksum = ""
		if err := ValidateJournal(bad); err == nil {
			t.Fatalf("malformed resume secret value %q must be rejected", value)
		}
	}
}

// TestJournalVector pins the committed cross-language vector: rebuilding the sample
// journal from the vector's inputs must reproduce the recorded fingerprint and the
// byte-exact canonical JSON (including its checksum). The TypeScript twin asserts the
// same file, so any drift between the two implementations fails one of them.
func TestJournalDigestCheckpointContract(t *testing.T) {
	j := journalVectorSample(t)
	now := time.UnixMilli(1723500120000)

	// The vector sample carries a valid checkpoint on file 0; a round-trip preserves it.
	decoded, err := DecodeJournal(mustEncode(t, j))
	if err != nil {
		t.Fatalf("round-trip: %v", err)
	}
	cp := decoded.Files[0].DigestCheckpoint
	if cp == nil {
		t.Fatal("digest checkpoint lost in round-trip")
	}
	if cp.Format != DigestCheckpointFormatGoStdlib || cp.CommittedBlocks != 1 || cp.CommittedBytes != 1024 {
		t.Fatalf("round-trip checkpoint mismatch: %+v", cp)
	}

	// A checkpoint must describe exactly the file's committed blocks.
	if err := j.SetDigestCheckpoint(0, &JournalDigestCheckpoint{
		Format: DigestCheckpointFormatGoStdlib, CommittedBlocks: 2, CommittedBytes: 2048,
		State: strings.Repeat("ab", 54),
	}); err == nil {
		t.Fatal("checkpoint block count diverging from committedBlocks must be refused")
	}
	if err := j.SetDigestCheckpoint(7, nil); err == nil {
		t.Fatal("unknown file must be refused")
	}

	// CommitBlocks clears the stale checkpoint so the journal can never hold an
	// inconsistent one; the storage layer re-attaches the matching state afterwards.
	if err := j.CommitBlocks(0, 2, now); err != nil {
		t.Fatalf("advance: %v", err)
	}
	if j.Files[0].DigestCheckpoint != nil {
		t.Fatal("commit must clear a checkpoint that cannot cover the new high-water mark")
	}
	if err := j.SetDigestCheckpoint(0, &JournalDigestCheckpoint{
		Format: DigestCheckpointFormatGoStdlib, CommittedBlocks: 2, CommittedBytes: 2048,
		State: strings.Repeat("ab", 54),
	}); err != nil {
		t.Fatalf("re-attach: %v", err)
	}
	if _, err := DecodeJournal(mustEncode(t, j)); err != nil {
		t.Fatalf("re-attached checkpoint round-trip: %v", err)
	}

	// Structural violations fail closed, each on its own claim.
	valid := func() DurableJournal { j, _ := DecodeJournal(mustEncode(t, journalVectorSample(t))); return j }
	for name, mutate := range map[string]func(*JournalDigestCheckpoint){
		"invalid format identifier": func(cp *JournalDigestCheckpoint) {
			cp.Format = "Sha256-go-v1"
		},
		"block count mismatch": func(cp *JournalDigestCheckpoint) { cp.CommittedBlocks = 0 },
		"byte count mismatch":  func(cp *JournalDigestCheckpoint) { cp.CommittedBytes = 512 },
		"empty state":          func(cp *JournalDigestCheckpoint) { cp.State = "" },
		"non-hex state":        func(cp *JournalDigestCheckpoint) { cp.State = "ZZ" },
		"odd-length state":     func(cp *JournalDigestCheckpoint) { cp.State = "abc" },
	} {
		bad := valid()
		cp := bad.Files[0].DigestCheckpoint
		mutate(cp)
		if _, err := EncodeJournal(bad); err == nil {
			t.Fatalf("%s: must fail closed", name)
		}
	}

	// An UNKNOWN format identifier is structurally fine — the journal is valid and merely
	// falls back to prefix re-hash at resume time (the format is an opaque claim).
	ok := valid()
	ok.Files[0].DigestCheckpoint.Format = "some-future-impl-v9"
	if _, err := EncodeJournal(ok); err != nil {
		t.Fatalf("unknown format must stay decodable (resume re-hashes), got %v", err)
	}

	// Oversized state is bounded.
	bad := valid()
	bad.Files[0].DigestCheckpoint.State = strings.Repeat("ab", 2049) // 4098 hex chars
	if _, err := EncodeJournal(bad); err == nil {
		t.Fatal("oversized checkpoint state must fail closed")
	}
}

// mustEncode encodes without failing the test, for tests that only care about decoding.
func mustEncode(t *testing.T, j DurableJournal) []byte {
	t.Helper()
	encoded, err := EncodeJournal(j)
	if err != nil {
		t.Fatalf("EncodeJournal: %v", err)
	}
	return encoded
}

func TestJournalVector(t *testing.T) {
	var doc journalVectorDoc
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "test-vectors", "durable-journal.json"))
	if err != nil {
		t.Fatalf("read vector: %v (regenerate with GENERATE_VECTORS=1)", err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	msg, err := DecodeControl([]byte(doc.Manifest))
	if err != nil {
		t.Fatalf("decode vector manifest: %v", err)
	}
	manifest, ok := msg.(*Manifest)
	if !ok {
		t.Fatalf("vector manifest is not a manifest")
	}
	j, err := NewJournal(doc.TransferID, *manifest, doc.SourceIdentity, doc.DestinationIdentity,
		time.UnixMilli(doc.CreatedAt))
	if err != nil {
		t.Fatalf("NewJournal: %v", err)
	}
	for i, blocks := range doc.CommittedBlocks {
		if err := j.CommitBlocks(i, blocks, time.UnixMilli(doc.UpdatedAt)); err != nil {
			t.Fatalf("CommitBlocks(%d, %d): %v", i, blocks, err)
		}
		if cp := doc.DigestCheckpoints[i]; cp != nil {
			if err := j.SetDigestCheckpoint(i, cp); err != nil {
				t.Fatalf("SetDigestCheckpoint(%d): %v", i, err)
			}
		}
	}
	if j.ManifestFingerprint != doc.Fingerprint {
		t.Fatalf("fingerprint mismatch:\n got %s\nwant %s", j.ManifestFingerprint, doc.Fingerprint)
	}
	encoded, err := EncodeJournal(j)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if string(encoded) != doc.Journal {
		t.Fatalf("journal bytes mismatch:\n got %s\nwant %s", encoded, doc.Journal)
	}
	// The with-secret canonical journal pins the resumeSecret serialization (V13-PR07).
	withSecret := j
	withSecret.ResumeSecret = &JournalResumeSecret{Version: 1, Value: journalVectorSecretValue}
	encodedWithSecret, err := EncodeJournal(withSecret)
	if err != nil {
		t.Fatalf("encode with secret: %v", err)
	}
	if string(encodedWithSecret) != doc.JournalWithSecret {
		t.Fatalf("journal-with-secret bytes mismatch:\n got %s\nwant %s", encodedWithSecret, doc.JournalWithSecret)
	}
	// The resume-secret envelope cases pin the exact v1 credential format.
	for _, tc := range doc.ResumeSecretCases {
		candidate := j
		candidate.ResumeSecret = tc.Envelope
		_, encodeErr := EncodeJournal(candidate)
		valid := encodeErr == nil
		if valid != tc.Valid {
			t.Fatalf("resumeSecret case %q: valid=%v, want %v (err=%v)", tc.Name, valid, tc.Valid, encodeErr)
		}
	}
}

// rewriteJSON round-trips encoded JSON through a mutation for tamper tests, preserving the
// untouched fields verbatim apart from the mutation.
func rewriteJSON(t *testing.T, encoded []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(encoded, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	mutate(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}
