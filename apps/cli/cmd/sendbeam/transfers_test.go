package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	clitransfer "github.com/sendbeam/cli/internal/transfer"
	"github.com/sendbeam/wire"
)

// attachSeedSecret attaches a valid resume-secret envelope to the journal for id so the
// management list classifies it as ready to resume (V13-PR08).
func attachSeedSecret(t *testing.T, store *clitransfer.DurableStore, id string) error {
	t.Helper()
	j, ok, err := store.LoadJournal(id)
	if err != nil || !ok {
		return fmt.Errorf("load journal: ok=%v err=%v", ok, err)
	}
	env, err := wire.EncodeResumeSecretEnvelope(bytes.Repeat([]byte{0x5A}, 32))
	if err != nil {
		return err
	}
	j.ResumeSecret = &wire.JournalResumeSecret{Version: env.Version, Value: env.Value}
	return store.SaveJournal(j)
}

// captureStderr runs fn with os.Stderr redirected to a pipe and returns its exit code
// and captured output.
func captureStderr(t *testing.T, fn func() int) (int, string) {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	code := fn()
	_ = w.Close()
	os.Stderr = old
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	return code, string(data)
}

// seedDurableStore creates a one-block durable receive checkpoint under dir and returns
// its transfer id.
func seedDurableStore(t *testing.T, dir string) string {
	t.Helper()
	blockSize := 1024
	content := make([]byte, blockSize)
	for i := range content {
		content[i] = byte(i)
	}
	sum := sha256.Sum256(content)
	id := "0123456789abcdef0123456789abcdef"
	manifest := wire.NewManifest([]wire.FileEntry{{
		Idx: 0, Name: "seed.bin", Size: int64(len(content)), Mime: "application/octet-stream",
		LastModified: 1_700_000_000_000, BlockSize: blockSize, Blocks: 1,
		FileDigest: hex.EncodeToString(sum[:]),
	}}, int64(len(content)))
	manifest.TransferID = id
	dest, err := clitransfer.NewDurableDestination(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := dest.Prepare(*manifest); err != nil {
		t.Fatal(err)
	}
	sink, err := dest.Open(manifest.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(0, content); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestTransfersListInspectResumeDiscard(t *testing.T) {
	dir := t.TempDir()
	id := seedDurableStore(t, dir)

	code, out := captureStderr(t, func() int {
		return runTransfers([]string{"list", "--out", dir})
	})
	if code != 0 || !strings.Contains(out, id) || !strings.Contains(out, "committed") {
		t.Fatalf("list: code=%d out=%q", code, out)
	}
	// The seeded journal has no resume credential: the list must classify it honestly.
	if !strings.Contains(out, "Legacy — restart required") {
		t.Fatalf("list status: missing legacy classification in %q", out)
	}

	code, out = captureStderr(t, func() int {
		return runTransfers([]string{"inspect", id, "--out", dir})
	})
	if code != 0 || !strings.Contains(out, "self-consistent") || !strings.Contains(out, "manifest fingerprint") {
		t.Fatalf("inspect: code=%d out=%q", code, out)
	}

	// V13-PR08: resume requires the fresh invite code from the sender's re-run.
	code, out = captureStderr(t, func() int {
		return runTransfers([]string{"resume", id, "--out", dir})
	})
	if code != 2 || !strings.Contains(out, "--code") {
		t.Fatalf("resume without --code: code=%d out=%q", code, out)
	}
	// A legacy no-secret journal cannot authenticate a cross-session resume.
	code, out = captureStderr(t, func() int {
		return runTransfers([]string{"resume", id, "--code", "7-alpha-bravo", "--out", dir})
	})
	if code != 1 || !strings.Contains(out, "no resume credential") {
		t.Fatalf("resume legacy: code=%d out=%q", code, out)
	}
	// Once the credential is attached, the journal is classified as ready to resume.
	store, err := clitransfer.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := attachSeedSecret(t, store, id); err != nil {
		t.Fatal(err)
	}
	code, out = captureStderr(t, func() int {
		return runTransfers([]string{"list", "--out", dir})
	})
	if code != 0 || !strings.Contains(out, "Ready to resume") || !strings.Contains(out, "resume "+id+" --code <code>") {
		t.Fatalf("list after credential: code=%d out=%q", code, out)
	}

	code, out = captureStderr(t, func() int {
		return runTransfers([]string{"discard", id, "--out", dir})
	})
	if code != 0 || !strings.Contains(out, "Discarded") {
		t.Fatalf("discard: code=%d out=%q", code, out)
	}

	code, out = captureStderr(t, func() int {
		return runTransfers([]string{"list", "--out", dir})
	})
	if code != 0 || !strings.Contains(out, "No durable transfers") {
		t.Fatalf("list after discard: code=%d out=%q", code, out)
	}

	// Repeated discard is a safe no-op.
	code, _ = captureStderr(t, func() int {
		return runTransfers([]string{"discard", id, "--out", dir})
	})
	if code != 0 {
		t.Fatalf("repeat discard: code=%d", code)
	}
}

func TestTransfersDiscardAllRequiresConfirmation(t *testing.T) {
	dir := t.TempDir()
	seedDurableStore(t, dir)

	// Without --yes the command refuses and deletes nothing.
	code, out := captureStderr(t, func() int {
		return runTransfers([]string{"discard", "--all", "--out", dir})
	})
	if code != 2 || !strings.Contains(out, "--yes") {
		t.Fatalf("discard --all without --yes: code=%d out=%q", code, out)
	}
	store, err := clitransfer.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if entries, _ := store.List(); len(entries) != 1 {
		t.Fatalf("state deleted without confirmation: %+v", entries)
	}

	code, _ = captureStderr(t, func() int {
		return runTransfers([]string{"discard", "--all", "--yes", "--out", dir})
	})
	if code != 0 {
		t.Fatalf("discard --all --yes: code=%d", code)
	}
	if entries, _ := store.List(); len(entries) != 0 {
		t.Fatalf("store not empty after --all: %+v", entries)
	}
}

func TestTransfersInspectAndResumeFailClosedOnInconsistency(t *testing.T) {
	dir := t.TempDir()
	id := seedDurableStore(t, dir)

	// Truncate the partial below its checkpoint claim.
	store, err := clitransfer.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	part := store.PartialPath(id, "seed.bin")
	if err := os.Truncate(part, 0); err != nil {
		t.Fatal(err)
	}

	code, out := captureStderr(t, func() int {
		return runTransfers([]string{"inspect", id, "--out", dir})
	})
	if code != 1 || !strings.Contains(out, "partial") {
		t.Fatalf("inspect inconsistent: code=%d out=%q", code, out)
	}
	code, out = captureStderr(t, func() int {
		return runTransfers([]string{"resume", id, "--code", "7-alpha-bravo", "--out", dir})
	})
	if code != 1 || !strings.Contains(out, "not resumable") {
		t.Fatalf("resume inconsistent: code=%d out=%q", code, out)
	}
	// Fail-closed: nothing was deleted.
	if entries, _ := store.List(); len(entries) != 1 {
		t.Fatalf("state deleted on inspection error: %+v", entries)
	}
}

func TestTransfersUnknownIDFailsCleanly(t *testing.T) {
	dir := t.TempDir()
	code, out := captureStderr(t, func() int {
		return runTransfers([]string{"inspect", "deadbeefdeadbeefdeadbeefdeadbeef", "--out", dir})
	})
	if code != 1 || !strings.Contains(out, "nothing was deleted") {
		t.Fatalf("inspect unknown: code=%d out=%q", code, out)
	}
}

func TestTransfersStorePathIsBoundedToOutDir(t *testing.T) {
	dir := t.TempDir()
	seedDurableStore(t, dir)
	// The .sendbeam tree lives only under the out dir; nothing is created elsewhere.
	sendbeam := filepath.Join(dir, ".sendbeam")
	info, err := os.Stat(sendbeam)
	if err != nil || !info.IsDir() {
		t.Fatalf(".sendbeam missing under out dir: %v", err)
	}
	parent := filepath.Dir(dir)
	if entries, _ := os.ReadDir(parent); len(entries) != 1 {
		t.Fatalf("storage escaped the out dir: %v", entries)
	}
}

// TestSendLegacyRecordNeverRecommendsDowngrade pins the V13-PR08 security-UX rule: a
// pre-PR07 sender record with NO resume credential must refuse with restart/discard
// guidance only — never a suggestion to use an old receiver/binary/protocol as a
// workaround. The refusal happens before dialing, so no server is needed.
func TestSendLegacyRecordNeverRecommendsDowngrade(t *testing.T) {
	t.Setenv("SENDBEAM_SENDER_STATE", t.TempDir())
	srcDir := t.TempDir()
	content := []byte("legacy source bytes")
	srcPath := filepath.Join(srcDir, "legacy.bin")
	if err := os.WriteFile(srcPath, content, 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := clitransfer.OpenSenderStore(os.Getenv("SENDBEAM_SENDER_STATE"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := wire.ManifestFingerprint(wire.Manifest{
		TransferID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Files: []wire.FileEntry{{
			Idx: 0, Name: filepath.Base(srcPath), Size: int64(len(content)),
			Mime: "application/octet-stream", LastModified: info.ModTime().UnixMilli(),
			BlockSize: 1024, Blocks: 1, FileDigest: strings.Repeat("0", 64),
		}},
		TotalSize: int64(len(content)),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Legacy pre-PR07 record: schema v2 shape but NO resume secret (exactly what a
	// pre-PR07 record decodes to).
	if err := store.Save(clitransfer.SenderRecord{
		SchemaVersion:       2,
		TransferID:          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ManifestFingerprint: fp,
		ProtocolVersion:     wire.ProtocolVersion,
		CreatedAt:           1_700_000_000_000,
		UpdatedAt:           1_700_000_000_000,
		Paths:               []string{srcPath},
		Files: []clitransfer.SenderFileState{{
			Idx: 0, Name: filepath.Base(srcPath), Size: int64(len(content)),
			Mime: "application/octet-stream", LastModified: info.ModTime().UnixMilli(),
			BlockSize: 1024, Blocks: 1, FileDigest: strings.Repeat("0", 64),
		}},
	}); err != nil {
		t.Fatal(err)
	}

	code, out := captureStderr(t, func() int { return runSend([]string{srcPath}) })
	if code != 1 {
		t.Fatalf("legacy send: code=%d out=%q", code, out)
	}
	if !strings.Contains(out, "no resume credential") {
		t.Fatalf("legacy send must name the missing credential: %q", out)
	}
	if !strings.Contains(out, "cannot be reused") {
		t.Fatalf("legacy send must refuse the old transfer id: %q", out)
	}
	// No downgrade guidance: an old receiver/binary/protocol must never be offered.
	for _, banned := range []string{"pre-PR07-compatible", "old receiver", "old binary", "downgrade"} {
		if strings.Contains(out, banned) {
			t.Fatalf("legacy send must not recommend downgrade %q: %q", banned, out)
		}
	}
	// The record is preserved for explicit discard; nothing was deleted.
	if _, ok, err := store.Lookup(clitransfer.PathKey([]string{srcPath})); err != nil || !ok {
		t.Fatalf("legacy record must be preserved: ok=%v err=%v", ok, err)
	}
}
