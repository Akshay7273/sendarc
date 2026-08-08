/**
 * Binary codec for the 16-byte frame header (plan.md §6.3). The encoded header bytes
 * are used verbatim as the AES-GCM AAD, so encode/decode must be exact and stable.
 *
 * Layout (big-endian):
 *   version(u8) type(u8) flags(u8) reserved(u8)
 *   fileIdx(u16) blockIdx(u32) frameOff(u16) len(u16)
 */
import type { FrameHeader } from './transfer.js';
/** Encode a header into a fresh 16-byte buffer. */
export declare function encodeFrameHeader(h: FrameHeader): Uint8Array;
/** Decode a header from the first 16 bytes of `buf`. */
export declare function decodeFrameHeader(buf: Uint8Array): FrameHeader;
//# sourceMappingURL=frame.d.ts.map