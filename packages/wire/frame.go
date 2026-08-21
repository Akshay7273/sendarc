package wire

import (
	"encoding/binary"
	"fmt"
)

const frameHeaderBytes = 16

// FrameVersion is the frame-header format version (the header's first byte). It mirrors
// FRAME_VERSION in packages/protocol/src/constants.ts and is bumped only if the header
// layout changes.
const FrameVersion uint8 = 1

// FrameHeader is the 16-byte frame header. Its encoded bytes are the
// AES-GCM additional authenticated data, so the codec must be exact and stable.
//
// Layout (big-endian):
//
//	version(u8) type(u8) flags(u8) reserved(u8)
//	fileIdx(u16) blockIdx(u32) frameOff(u32) len(u16)
//
// FrameOff is a byte offset within the block, so it must span the whole block: at the
// default 1 MiB block a 16 KiB frame reaches offset ~1 MiB, far past u16. It is u32
// (not u16, as an earlier draft miscalculated), which the header absorbs by dropping the
// former trailing reserved(u16) — the header stays a fixed 16 bytes.
type FrameHeader struct {
	Version  uint8
	Type     uint8
	Flags    uint8
	FileIdx  uint16
	BlockIdx uint32
	FrameOff uint32 // byte offset within the block, not the file
	Len      uint16 // ciphertext payload length
}

// Frame type tags (the Type byte). Mirrors FrameType in transfer.ts.
const (
	FrameCaps        uint8 = 1
	FrameManifest    uint8 = 2
	FrameBlockData   uint8 = 3
	FrameBlockHash   uint8 = 4
	FrameBlockRecv   uint8 = 5
	FrameAck         uint8 = 6
	FrameNack        uint8 = 7
	FrameControl     uint8 = 8
	FrameComplete    uint8 = 9
	FrameDone        uint8 = 10
	FrameFail        uint8 = 11
	FrameResumeState uint8 = 12
	// FrameResumeAuth carries one resume-auth message (EncodeResumeMessage JSON) sealed
	// under the SESSION directional keys, exchanged strictly before the transfer engine
	// starts (V13-PR08). It is never used for transfer protocol frames; after mutual
	// authentication the transfer runs under the fresh resumed key epoch.
	FrameResumeAuth uint8 = 13
	// FramePairingExchange carries one pairing message (PairingRequest, PairingResponse,
	// or PairingConfirm JSON) sealed under the SESSION directional keys (V15-PR02).
	FramePairingExchange uint8 = 14
)

// encodeFrameHeader encodes h into a fresh 16-byte buffer.
func encodeFrameHeader(h FrameHeader) []byte {
	buf := make([]byte, frameHeaderBytes)
	buf[0] = h.Version
	buf[1] = h.Type
	buf[2] = h.Flags
	buf[3] = 0 // reserved
	binary.BigEndian.PutUint16(buf[4:6], h.FileIdx)
	binary.BigEndian.PutUint32(buf[6:10], h.BlockIdx)
	binary.BigEndian.PutUint32(buf[10:14], h.FrameOff)
	binary.BigEndian.PutUint16(buf[14:16], h.Len)
	return buf
}

// decodeFrameHeader decodes a header from the first 16 bytes of buf.
func decodeFrameHeader(buf []byte) (FrameHeader, error) {
	if len(buf) < frameHeaderBytes {
		return FrameHeader{}, fmt.Errorf("frame header needs %d bytes, got %d", frameHeaderBytes, len(buf))
	}
	return FrameHeader{
		Version:  buf[0],
		Type:     buf[1],
		Flags:    buf[2],
		FileIdx:  binary.BigEndian.Uint16(buf[4:6]),
		BlockIdx: binary.BigEndian.Uint32(buf[6:10]),
		FrameOff: binary.BigEndian.Uint32(buf[10:14]),
		Len:      binary.BigEndian.Uint16(buf[14:16]),
	}, nil
}
