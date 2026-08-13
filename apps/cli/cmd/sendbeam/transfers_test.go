package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	clitransfer "github.com/sendbeam/cli/internal/transfer"
	"github.com/sendbeam/wire"
)

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

	code, out = captureStderr(t, func() int {
		return runTransfers([]string{"inspect", id, "--out", dir})
	})
	if code != 0 || !strings.Contains(out, "self-consistent") || !strings.Contains(out, "manifest fingerprint") {
		t.Fatalf("inspect: code=%d out=%q", code, out)
	}

	code, out = captureStderr(t, func() int {
		return runTransfers([]string{"resume", id, "--out", dir})
	})
	if code != 0 || !strings.Contains(out, "resumable") || !strings.Contains(out, "sendbeam receive") {
		t.Fatalf("resume: code=%d out=%q", code, out)
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
		return runTransfers([]string{"resume", id, "--out", dir})
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
