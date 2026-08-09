package wire

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// CompletionDigest preserves the original single-file token and commits an ordered multi-file
// set by hashing its newline-delimited canonical per-file digests.
func CompletionDigest(files []FileEntry) string {
	if len(files) == 1 {
		return files[0].FileDigest
	}
	digests := make([]string, len(files))
	for i, file := range files {
		digests[i] = file.FileDigest
	}
	sum := sha256.Sum256([]byte(strings.Join(digests, "\n")))
	return hex.EncodeToString(sum[:])
}
