/**
 * Binary codec for the 16-byte frame header (plan.md §6.3). The encoded header bytes
 * are used verbatim as the AES-GCM AAD, so encode/decode must be exact and stable.
 *
 * Layout (big-endian):
 *   version(u8) type(u8) flags(u8) reserved(u8)
 *   fileIdx(u16) blockIdx(u32) frameOff(u16) len(u16)
 */
import { FRAME_HEADER_BYTES } from './constants.js';
const U8_MAX = 0xff;
const U16_MAX = 0xffff;
const U32_MAX = 0xffffffff;
function assertRange(name, value, max) {
    if (!Number.isInteger(value) || value < 0 || value > max) {
        throw new RangeError(`frame header field ${name}=${value} out of range [0, ${max}]`);
    }
}
/** Encode a header into a fresh 16-byte buffer. */
export function encodeFrameHeader(h) {
    assertRange('version', h.version, U8_MAX);
    assertRange('type', h.type, U8_MAX);
    assertRange('flags', h.flags, U8_MAX);
    assertRange('fileIdx', h.fileIdx, U16_MAX);
    assertRange('blockIdx', h.blockIdx, U32_MAX);
    assertRange('frameOff', h.frameOff, U16_MAX);
    assertRange('len', h.len, U16_MAX);
    const buf = new Uint8Array(FRAME_HEADER_BYTES);
    const dv = new DataView(buf.buffer);
    dv.setUint8(0, h.version);
    dv.setUint8(1, h.type);
    dv.setUint8(2, h.flags);
    dv.setUint8(3, 0); // reserved
    dv.setUint16(4, h.fileIdx, false);
    dv.setUint32(6, h.blockIdx, false);
    dv.setUint16(10, h.frameOff, false);
    dv.setUint16(12, h.len, false);
    dv.setUint16(14, 0, false); // reserved tail — keeps header at a fixed 16 bytes
    return buf;
}
/** Decode a header from the first 16 bytes of `buf`. */
export function decodeFrameHeader(buf) {
    if (buf.byteLength < FRAME_HEADER_BYTES) {
        throw new RangeError(`frame header needs ${FRAME_HEADER_BYTES} bytes, got ${buf.byteLength}`);
    }
    const dv = new DataView(buf.buffer, buf.byteOffset, FRAME_HEADER_BYTES);
    return {
        version: dv.getUint8(0),
        type: dv.getUint8(1),
        flags: dv.getUint8(2),
        fileIdx: dv.getUint16(4, false),
        blockIdx: dv.getUint32(6, false),
        frameOff: dv.getUint16(10, false),
        len: dv.getUint16(12, false),
    };
}
//# sourceMappingURL=frame.js.map