package wire

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
)

// lengthPrefixLE encodes n as an 8-byte little-endian length — the len(...) encoding of
// the RFC 9382 SPAKE2 transcript (§3.3).
func lengthPrefixLE(n int) []byte {
	out := make([]byte, 8)
	binary.LittleEndian.PutUint64(out, uint64(n))
	return out
}

// withLengthPrefix returns len(x) || x with an 8-byte little-endian length.
func withLengthPrefix(x []byte) []byte {
	out := make([]byte, 0, 8+len(x))
	out = append(out, lengthPrefixLE(len(x))...)
	return append(out, x...)
}

// hkdfSHA256 mirrors the TypeScript hkdfSha256 helper: HKDF-SHA256 extract-and-expand
// with the given salt and info. A nil or empty salt follows RFC 5869 (a string of
// HashLen zero bytes), which is HMAC-equivalent to WebCrypto's zero-length salt.
func hkdfSHA256(ikm, salt, info []byte, length int) ([]byte, error) {
	return hkdf.Key(sha256.New, ikm, salt, string(info), length)
}
