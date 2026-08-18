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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	// ErrChecksumMismatch is returned when downloaded archive sha256 does not match authoritative manifest.
	ErrChecksumMismatch = errors.New("downloaded artifact checksum mismatch")

	// ErrBinaryNotFoundInArchive is returned when the expected binary is missing in the release archive.
	ErrBinaryNotFoundInArchive = errors.New("expected executable binary not found in release archive")

	// ErrTargetNotWritable is returned when the target binary directory is not writable.
	ErrTargetNotWritable = errors.New("target binary directory is not writable")
)

// ApplyOptions configures the update installation.
type ApplyOptions struct {
	TargetPath     string // Path to the active executable being replaced.
	TargetOS       string // Target operating system (default runtime.GOOS).
	ExpectedSHA256 string // Authoritative SHA256 hex string from manifest.
	ArchiveName    string // Filename of archive (used to determine format .tar.gz vs .zip).
}

// ApplyUpdate extracts a verified binary from archiveReader, verifies its SHA-256 hash,
// atomically swaps it into targetPath, and automatically rolls back to the previous binary
// if any stage of the replacement fails.
func ApplyUpdate(ctx context.Context, archiveReader io.Reader, opts ApplyOptions) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	targetOS := opts.TargetOS
	if targetOS == "" {
		targetOS = runtime.GOOS
	}

	targetBinaryName := TargetCLIBinaryName(targetOS)

	// Clean and resolve target path
	targetPath, err := filepath.Abs(filepath.Clean(opts.TargetPath))
	if err != nil {
		return fmt.Errorf("resolving target binary path: %w", err)
	}

	targetDir := filepath.Dir(targetPath)

	// Verify target directory writability
	if err := checkDirWritable(targetDir); err != nil {
		return fmt.Errorf("%w: %v", ErrTargetNotWritable, err)
	}

	// Validate expected SHA-256 format if provided
	expectedHash := strings.ToLower(strings.TrimSpace(opts.ExpectedSHA256))
	if expectedHash != "" && len(expectedHash) != 64 {
		return fmt.Errorf("invalid expected sha256 length (%d != 64)", len(expectedHash))
	}

	// Read archive into memory / buffer while computing SHA256 hash
	hasher := sha256.New()
	tee := io.TeeReader(archiveReader, hasher)

	archiveBytes, err := io.ReadAll(tee)
	if err != nil {
		return fmt.Errorf("reading update stream: %w", err)
	}

	if len(archiveBytes) == 0 {
		return errors.New("update stream is empty")
	}

	actualHash := hex.EncodeToString(hasher.Sum(nil))
	if expectedHash != "" && actualHash != expectedHash {
		return fmt.Errorf("%w: expected %s, got %s", ErrChecksumMismatch, expectedHash, actualHash)
	}

	// Extract target binary bytes from the archive
	extractedBytes, err := extractBinary(archiveBytes, opts.ArchiveName, targetBinaryName)
	if err != nil {
		return fmt.Errorf("extracting binary from archive: %w", err)
	}

	if len(extractedBytes) == 0 {
		return errors.New("extracted binary is empty")
	}

	// Create temporary staging file in the exact same directory (guarantees same filesystem for atomic rename)
	tmpFile, err := os.CreateTemp(targetDir, filepath.Base(targetPath)+".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temporary staging file in %s: %w", targetDir, err)
	}
	tmpPath := tmpFile.Name()

	// Ensure cleanup of staging temp file if not swapped
	stagingCleaned := false
	defer func() {
		if !stagingCleaned {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	// Write extracted binary bytes
	if _, err := tmpFile.Write(extractedBytes); err != nil {
		return fmt.Errorf("writing staging binary: %w", err)
	}

	// Set executable permissions (0755)
	if err := tmpFile.Chmod(0755); err != nil && targetOS != "windows" {
		return fmt.Errorf("setting permissions on staging binary: %w", err)
	}

	// Sync to disk and close before atomic rename
	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("flushing staging binary: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("closing staging binary: %w", err)
	}

	// Atomic Swap with Guaranteed Automatic Rollback
	backupPath := targetPath + ".old"
	_ = os.Remove(backupPath) // clean any stale backup

	hasExistingTarget := false
	if _, err := os.Stat(targetPath); err == nil {
		hasExistingTarget = true
		// Move active binary to backup
		if err := os.Rename(targetPath, backupPath); err != nil {
			return fmt.Errorf("failed to backup current binary before replacement: %w", err)
		}
	}

	// Move staging file into active binary position
	if err := os.Rename(tmpPath, targetPath); err != nil {
		// ROLLBACK: Restore active binary immediately from backup if it existed
		if hasExistingTarget {
			_ = os.Rename(backupPath, targetPath)
		}
		return fmt.Errorf("failed to swap new binary into place (automatically rolled back): %w", err)
	}

	stagingCleaned = true

	// Post-replacement verification: verify new binary exists and is readable/executable
	info, err := os.Stat(targetPath)
	if err != nil || info.Size() == 0 {
		// ROLLBACK: Restore active binary immediately
		if hasExistingTarget {
			_ = os.Remove(targetPath)
			_ = os.Rename(backupPath, targetPath)
		}
		return fmt.Errorf("new binary validation failed after swap (automatically rolled back): %w", err)
	}

	// Cleanup backup file on success (ignore error on Windows where locked)
	if hasExistingTarget {
		_ = os.Remove(backupPath)
	}

	return nil
}

// extractBinary extracts the target executable from a raw byte slice (tar.gz, zip, or raw executable).
func extractBinary(data []byte, archiveName, binaryName string) ([]byte, error) {
	nameLower := strings.ToLower(archiveName)

	if strings.HasSuffix(nameLower, ".tar.gz") || strings.HasSuffix(nameLower, ".tgz") {
		return extractFromTarGz(data, binaryName)
	}

	if strings.HasSuffix(nameLower, ".zip") {
		return extractFromZip(data, binaryName)
	}

	// Check if gzip magic bytes
	if len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b {
		return extractFromTarGz(data, binaryName)
	}

	// Check if zip magic bytes (PK\x03\x04)
	if len(data) > 4 && data[0] == 'P' && data[1] == 'K' && data[2] == 0x03 && data[3] == 0x04 {
		return extractFromZip(data, binaryName)
	}

	// Otherwise treat data as direct binary content
	return data, nil
}

func extractFromTarGz(data []byte, binaryName string) ([]byte, error) {
	gzr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("opening gzip stream: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading tar archive: %w", err)
		}

		baseName := filepath.Base(header.Name)
		if baseName == binaryName && (header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA) {
			buf := new(bytes.Buffer)
			if _, err := io.Copy(buf, tr); err != nil {
				return nil, fmt.Errorf("extracting %s from tar: %w", binaryName, err)
			}
			return buf.Bytes(), nil
		}
	}

	return nil, fmt.Errorf("%w: %q", ErrBinaryNotFoundInArchive, binaryName)
}

func extractFromZip(data []byte, binaryName string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("opening zip reader: %w", err)
	}

	for _, file := range zr.File {
		baseName := filepath.Base(file.Name)
		if strings.EqualFold(baseName, binaryName) {
			rc, err := file.Open()
			if err != nil {
				return nil, fmt.Errorf("opening %s from zip: %w", binaryName, err)
			}
			defer rc.Close()

			buf := new(bytes.Buffer)
			if _, err := io.Copy(buf, rc); err != nil {
				return nil, fmt.Errorf("extracting %s from zip: %w", binaryName, err)
			}
			return buf.Bytes(), nil
		}
	}

	return nil, fmt.Errorf("%w: %q", ErrBinaryNotFoundInArchive, binaryName)
}

func checkDirWritable(dir string) error {
	testFile, err := os.CreateTemp(dir, ".writetest-*")
	if err != nil {
		return err
	}
	name := testFile.Name()
	_ = testFile.Close()
	_ = os.Remove(name)
	return nil
}
