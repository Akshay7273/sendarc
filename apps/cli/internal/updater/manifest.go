package updater

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"runtime"
	"strings"
	"time"
)

// ReleaseAsset represents an available downloadable binary or distribution archive.
type ReleaseAsset struct {
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	DownloadURL string `json:"download_url"`
	SHA256      string `json:"sha256,omitempty"`
}

// ReleaseMetadata represents the release record and available assets.
type ReleaseMetadata struct {
	Version      Version           `json:"version"`
	TagName      string            `json:"tag_name"`
	Prerelease   bool              `json:"prerelease"`
	PublishedAt  time.Time         `json:"published_at"`
	ReleaseNotes string            `json:"release_notes,omitempty"`
	Assets       []ReleaseAsset    `json:"assets"`
	Checksums    map[string]string `json:"checksums,omitempty"` // filename -> lowercase hex sha256
}

// ParseChecksums parses a standard SHA256SUMS.txt manifest stream into a filename -> sha256 map.
func ParseChecksums(r io.Reader) (map[string]string, error) {
	result := make(map[string]string)
	scanner := bufio.NewScanner(r)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Format: <sha256> [* ]<filename>
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		hash := strings.ToLower(fields[0])
		if len(hash) != 64 {
			return nil, fmt.Errorf("line %d: invalid sha256 hash length (%d != 64)", lineNum, len(hash))
		}
		if _, err := hex.DecodeString(hash); err != nil {
			return nil, fmt.Errorf("line %d: invalid hex in sha256 hash %q: %w", lineNum, hash, err)
		}

		// Filename may contain spaces if fields were split; join remaining or strip leading *
		name := strings.TrimPrefix(strings.Join(fields[1:], " "), "*")
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}

		result[name] = hash
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading checksum manifest: %w", err)
	}

	return result, nil
}

// TargetCLIArchiveName returns the canonical archive filename for a given OS and architecture.
func TargetCLIArchiveName(targetOS, targetArch string) string {
	ext := "tar.gz"
	if targetOS == "windows" {
		ext = "zip"
	}
	return fmt.Sprintf("sendbeam-cli-%s-%s.%s", targetOS, targetArch, ext)
}

// TargetCLIBinaryName returns the executable filename for a given OS.
func TargetCLIBinaryName(targetOS string) string {
	if targetOS == "windows" {
		return "sendbeam.exe"
	}
	return "sendbeam"
}

// CurrentPlatformArchiveName returns the expected CLI archive name for the active runtime platform.
func CurrentPlatformArchiveName() string {
	return TargetCLIArchiveName(runtime.GOOS, runtime.GOARCH)
}

// FindTargetAsset finds the asset matching the expected platform archive or binary.
func (rm *ReleaseMetadata) FindTargetAsset(targetOS, targetArch string) (*ReleaseAsset, error) {
	archiveName := TargetCLIArchiveName(targetOS, targetArch)
	for i := range rm.Assets {
		if rm.Assets[i].Name == archiveName {
			asset := rm.Assets[i]
			if asset.SHA256 == "" && rm.Checksums != nil {
				asset.SHA256 = rm.Checksums[archiveName]
			}
			return &asset, nil
		}
	}
	return nil, fmt.Errorf("no distribution artifact found for %s/%s (expected %q)", targetOS, targetArch, archiveName)
}
