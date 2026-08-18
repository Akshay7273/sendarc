package updater

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func createTestTarGz(t *testing.T, binaryName string, binaryContent []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	hdr := &tar.Header{
		Name: binaryName,
		Mode: 0755,
		Size: int64(len(binaryContent)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if _, err := tw.Write(binaryContent); err != nil {
		t.Fatalf("Write binary: %v", err)
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("tw.Close: %v", err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatalf("gzw.Close: %v", err)
	}
	return buf.Bytes()
}

func createTestZip(t *testing.T, binaryName string, binaryContent []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	w, err := zw.Create(binaryName)
	if err != nil {
		t.Fatalf("Create zip entry: %v", err)
	}
	if _, err := w.Write(binaryContent); err != nil {
		t.Fatalf("Write zip binary: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zw.Close: %v", err)
	}
	return buf.Bytes()
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func TestApplyUpdate_HappyPathTarGz(t *testing.T) {
	tempDir := t.TempDir()
	targetBinary := filepath.Join(tempDir, "sendbeam")

	oldContent := []byte("old-binary-v1.3.0")
	if err := os.WriteFile(targetBinary, oldContent, 0755); err != nil {
		t.Fatalf("WriteFile targetBinary: %v", err)
	}

	newContent := []byte("new-binary-v1.4.0")
	tarData := createTestTarGz(t, "sendbeam", newContent)
	expectedHash := sha256Hex(tarData)

	opts := ApplyOptions{
		TargetPath:     targetBinary,
		TargetOS:       "linux",
		ExpectedSHA256: expectedHash,
		ArchiveName:    "sendbeam-cli-linux-amd64.tar.gz",
	}

	if err := ApplyUpdate(context.Background(), bytes.NewReader(tarData), opts); err != nil {
		t.Fatalf("ApplyUpdate failed: %v", err)
	}

	got, err := os.ReadFile(targetBinary)
	if err != nil {
		t.Fatalf("ReadFile after update: %v", err)
	}
	if !bytes.Equal(got, newContent) {
		t.Fatalf("updated binary content mismatch: got %q, expected %q", string(got), string(newContent))
	}

	// Verify backup is cleaned up
	if _, err := os.Stat(targetBinary + ".old"); !os.IsNotExist(err) {
		t.Errorf("expected backup file to be cleaned up, stat err = %v", err)
	}
}

func TestApplyUpdate_HappyPathZip(t *testing.T) {
	tempDir := t.TempDir()
	targetBinary := filepath.Join(tempDir, "sendbeam.exe")

	oldContent := []byte("old-binary-windows")
	if err := os.WriteFile(targetBinary, oldContent, 0755); err != nil {
		t.Fatalf("WriteFile targetBinary: %v", err)
	}

	newContent := []byte("new-binary-windows-updated")
	zipData := createTestZip(t, "sendbeam.exe", newContent)
	expectedHash := sha256Hex(zipData)

	opts := ApplyOptions{
		TargetPath:     targetBinary,
		TargetOS:       "windows",
		ExpectedSHA256: expectedHash,
		ArchiveName:    "sendbeam-cli-windows-amd64.zip",
	}

	if err := ApplyUpdate(context.Background(), bytes.NewReader(zipData), opts); err != nil {
		t.Fatalf("ApplyUpdate failed: %v", err)
	}

	got, err := os.ReadFile(targetBinary)
	if err != nil {
		t.Fatalf("ReadFile after update: %v", err)
	}
	if !bytes.Equal(got, newContent) {
		t.Fatalf("updated binary content mismatch: got %q, expected %q", string(got), string(newContent))
	}
}

func TestApplyUpdate_ChecksumMismatchPreservesBinary(t *testing.T) {
	tempDir := t.TempDir()
	targetBinary := filepath.Join(tempDir, "sendbeam")

	originalContent := []byte("original-unmodified-binary")
	if err := os.WriteFile(targetBinary, originalContent, 0755); err != nil {
		t.Fatalf("WriteFile targetBinary: %v", err)
	}

	newContent := []byte("new-binary")
	tarData := createTestTarGz(t, "sendbeam", newContent)

	opts := ApplyOptions{
		TargetPath:     targetBinary,
		TargetOS:       "linux",
		ExpectedSHA256: "0000000000000000000000000000000000000000000000000000000000000000",
		ArchiveName:    "sendbeam-cli-linux-amd64.tar.gz",
	}

	err := ApplyUpdate(context.Background(), bytes.NewReader(tarData), opts)
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("expected ErrChecksumMismatch, got %v", err)
	}

	// Active binary must be 100% untouched
	got, err := os.ReadFile(targetBinary)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, originalContent) {
		t.Fatalf("active binary was modified on checksum failure: got %q", string(got))
	}

	// No stale temp files or backup files
	entries, _ := os.ReadDir(tempDir)
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 entry in dir, got %d", len(entries))
	}
}

func TestApplyUpdate_MissingBinaryPreservesTarget(t *testing.T) {
	tempDir := t.TempDir()
	targetBinary := filepath.Join(tempDir, "sendbeam")

	originalContent := []byte("original-binary")
	if err := os.WriteFile(targetBinary, originalContent, 0755); err != nil {
		t.Fatalf("WriteFile targetBinary: %v", err)
	}

	tarData := createTestTarGz(t, "other-binary", []byte("not-sendbeam"))
	expectedHash := sha256Hex(tarData)

	opts := ApplyOptions{
		TargetPath:     targetBinary,
		TargetOS:       "linux",
		ExpectedSHA256: expectedHash,
		ArchiveName:    "sendbeam-cli-linux-amd64.tar.gz",
	}

	err := ApplyUpdate(context.Background(), bytes.NewReader(tarData), opts)
	if !errors.Is(err, ErrBinaryNotFoundInArchive) {
		t.Fatalf("expected ErrBinaryNotFoundInArchive, got %v", err)
	}

	got, err := os.ReadFile(targetBinary)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, originalContent) {
		t.Fatalf("active binary was altered on missing binary error")
	}
}

func TestApplyUpdate_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled

	tarData := createTestTarGz(t, "sendbeam", []byte("payload"))
	opts := ApplyOptions{
		TargetPath: "/tmp/sendbeam",
	}

	err := ApplyUpdate(ctx, bytes.NewReader(tarData), opts)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
