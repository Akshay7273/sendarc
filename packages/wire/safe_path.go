package wire

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	// MaxTransferFiles caps manifest allocation and stays well below the u16 file index limit.
	MaxTransferFiles = 4096
	// MaxTransferPathBytes is the maximum UTF-8 encoded canonical relative path.
	MaxTransferPathBytes = 1024
	// MaxTransferPathDepth caps nested folder components.
	MaxTransferPathDepth = 32
	// MaxTransferSegmentBytes matches the common filesystem component limit.
	MaxTransferSegmentBytes = 255
)

var (
	drivePath       = regexp.MustCompile(`^[A-Za-z]:`)
	windowsReserved = regexp.MustCompile(`(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\.|$)`)
)

// NormalizeTransferPath canonicalizes an untrusted manifest path without touching disk.
func NormalizeTransferPath(input string) (string, error) {
	if input == "" {
		return "", Errorf(CodeProtocol, "manifest path is empty")
	}
	if strings.HasPrefix(input, "/") || strings.HasPrefix(input, `\`) || drivePath.MatchString(input) {
		return "", Errorf(CodeProtocol, "manifest path must be relative")
	}
	canonical := strings.ReplaceAll(input, `\`, "/")
	segments := strings.Split(canonical, "/")
	if len(segments) > MaxTransferPathDepth {
		return "", Errorf(CodeProtocol, "manifest path is too deep")
	}
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return "", Errorf(CodeProtocol, "manifest path contains an unsafe segment")
		}
		for _, r := range segment {
			if r <= 0x1f || strings.ContainsRune(`<>:"|?*`, r) {
				return "", Errorf(CodeProtocol, "manifest path contains unsafe characters")
			}
		}
		if strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") {
			return "", Errorf(CodeProtocol, "manifest path has an unsafe suffix")
		}
		if windowsReserved.MatchString(segment) {
			return "", Errorf(CodeProtocol, "manifest path uses a reserved name")
		}
		if len(segment) > MaxTransferSegmentBytes {
			return "", Errorf(CodeProtocol, "manifest path segment is too long")
		}
	}
	if len(canonical) > MaxTransferPathBytes {
		return "", Errorf(CodeProtocol, "manifest path is too long")
	}
	if !utf8.ValidString(canonical) {
		return "", Errorf(CodeProtocol, "manifest path is not valid UTF-8")
	}
	return canonical, nil
}

// ValidateManifest checks aggregate geometry and returns a copy with canonical relative paths.
func ValidateManifest(manifest Manifest) (Manifest, error) {
	if len(manifest.Files) == 0 || len(manifest.Files) > MaxTransferFiles {
		return Manifest{}, Errorf(CodeProtocol, "manifest has an invalid file count")
	}
	files := make([]FileEntry, len(manifest.Files))
	paths := make(map[string]struct{}, len(manifest.Files))
	var total int64
	for idx, file := range manifest.Files {
		if file.Idx != idx {
			return Manifest{}, Errorf(CodeProtocol, "manifest file indexes must be contiguous")
		}
		if file.Size < 0 || file.LastModified < 0 || file.BlockSize <= 0 || file.Blocks < 0 {
			return Manifest{}, Errorf(CodeProtocol, "manifest has invalid file geometry")
		}
		if file.BlockSize > MaxManifestBlockBytes {
			return Manifest{}, fmt.Errorf("manifest block size %d exceeds the %d-byte ceiling", file.BlockSize, MaxManifestBlockBytes)
		}
		wantBlocks := 0
		if file.Size > 0 {
			wantBlocks = int((file.Size-1)/int64(file.BlockSize) + 1)
		}
		if file.Blocks != wantBlocks {
			return Manifest{}, Errorf(CodeProtocol, "manifest has invalid block geometry")
		}
		name, err := NormalizeTransferPath(file.Name)
		if err != nil {
			return Manifest{}, err
		}
		key := strings.ToLower(name)
		if _, exists := paths[key]; exists {
			return Manifest{}, errors.New("manifest contains duplicate paths")
		}
		paths[key] = struct{}{}
		if file.Size > math.MaxInt64-total {
			return Manifest{}, errors.New("manifest total size is too large")
		}
		total += file.Size
		file.Name = name
		files[idx] = file
	}
	if manifest.TotalSize != total {
		return Manifest{}, fmt.Errorf("manifest total size mismatch: got %d, want %d", manifest.TotalSize, total)
	}
	manifest.Files = files
	manifest.Type = FrameManifest
	return manifest, nil
}
