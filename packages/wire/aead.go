package wire

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

const u16Max = 0xffff

// FrameHeaderInput is the header fields the caller supplies; Len is set from the
// plaintext by Seal.
type FrameHeaderInput struct {
	Version  uint8
	Type     uint8
	Flags    uint8
	FileIdx  uint16
	BlockIdx uint32
	FrameOff uint32
}

// nonce builds the 12-byte GCM nonce: the direction's 4-byte salt followed by a
// big-endian u64 frame counter.
func nonce(salt []byte, counter uint64) []byte {
	out := make([]byte, aeadNonceBytes)
	copy(out, salt)
	binary.BigEndian.PutUint64(out[aeadSaltBytes:], counter)
	return out
}

func gcmFor(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seal encrypts plaintext into a frame: header(16) || ciphertext || tag(16). The header's
// Len field is set to the plaintext length and authenticated as GCM additional data.
func Seal(dir DirectionalKey, counter uint64, h FrameHeaderInput, plaintext []byte) ([]byte, error) {
	if len(plaintext) > u16Max {
		return nil, fmt.Errorf("frame payload %d exceeds u16 max %d", len(plaintext), u16Max)
	}
	aad := encodeFrameHeader(FrameHeader{
		Version:  h.Version,
		Type:     h.Type,
		Flags:    h.Flags,
		FileIdx:  h.FileIdx,
		BlockIdx: h.BlockIdx,
		FrameOff: h.FrameOff,
		Len:      uint16(len(plaintext)),
	})
	gcm, err := gcmFor(dir.Key)
	if err != nil {
		return nil, err
	}
	// Seal appends ciphertext||tag onto aad, giving header || ciphertext || tag.
	return gcm.Seal(aad, nonce(dir.Salt, counter), plaintext, aad), nil
}

// OpenedFrame is a decrypted frame: its parsed header and recovered plaintext.
type OpenedFrame struct {
	Header    FrameHeader
	Plaintext []byte
}

// Open decrypts a frame produced by Seal. It verifies the GCM tag over the header AAD and
// the expected nonce, and fails if authentication fails, the frame is truncated, or the
// header Len disagrees with the ciphertext length.
func Open(dir DirectionalKey, counter uint64, frame []byte) (*OpenedFrame, error) {
	if len(frame) < frameHeaderBytes+aeadTagBytes {
		return nil, fmt.Errorf("frame too short: %d bytes", len(frame))
	}
	aad := frame[:frameHeaderBytes]
	header, err := decodeFrameHeader(aad)
	if err != nil {
		return nil, err
	}
	body := frame[frameHeaderBytes:]
	if len(body) != int(header.Len)+aeadTagBytes {
		return nil, fmt.Errorf("frame len field %d disagrees with body %d", header.Len, len(body))
	}
	gcm, err := gcmFor(dir.Key)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce(dir.Salt, counter), body, aad)
	if err != nil {
		return nil, err
	}
	return &OpenedFrame{Header: header, Plaintext: plaintext}, nil
}
