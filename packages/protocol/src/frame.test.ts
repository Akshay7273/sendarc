import { describe, it, expect } from 'vitest';
import { encodeFrameHeader, decodeFrameHeader } from './frame.js';
import { FRAME_HEADER_BYTES } from './constants.js';
import { FrameType, type FrameHeader } from './transfer.js';

const sample: FrameHeader = {
  version: 1,
  type: FrameType.BlockData,
  flags: 0,
  fileIdx: 7,
  blockIdx: 123456,
  frameOff: 4096,
  len: 16384,
};

describe('frame header codec', () => {
  it('round-trips a header exactly', () => {
    const encoded = encodeFrameHeader(sample);
    expect(encoded.byteLength).toBe(FRAME_HEADER_BYTES);
    expect(decodeFrameHeader(encoded)).toEqual(sample);
  });

  it('is stable and big-endian for known values', () => {
    const bytes = encodeFrameHeader(sample);
    // version, type, flags, reserved
    expect([bytes[0], bytes[1], bytes[2], bytes[3]]).toEqual([1, FrameType.BlockData, 0, 0]);
    // fileIdx u16 = 7
    expect([bytes[4], bytes[5]]).toEqual([0, 7]);
    // blockIdx u32 = 123456 = 0x0001E240
    expect([bytes[6], bytes[7], bytes[8], bytes[9]]).toEqual([0x00, 0x01, 0xe2, 0x40]);
  });

  it('decodes from a byte-offset view without reading neighbours', () => {
    const outer = new Uint8Array(FRAME_HEADER_BYTES + 8);
    outer.set(encodeFrameHeader(sample), 4);
    const view = outer.subarray(4, 4 + FRAME_HEADER_BYTES);
    expect(decodeFrameHeader(view)).toEqual(sample);
  });

  it('carries a within-block byte offset past u16 (a 1 MiB block needs u32)', () => {
    // The default 1 MiB block framed at 16 KiB reaches offsets well past 0xffff; the
    // field is u32, so such an offset must round-trip rather than throw.
    const off = 1_000_000;
    expect(decodeFrameHeader(encodeFrameHeader({ ...sample, frameOff: off })).frameOff).toBe(off);
  });

  it('rejects a frame offset that would overflow u32 (guards the multi-GB bug)', () => {
    expect(() => encodeFrameHeader({ ...sample, frameOff: 0x1_0000_0000 })).toThrow(RangeError);
  });

  it('rejects out-of-range block index', () => {
    expect(() => encodeFrameHeader({ ...sample, blockIdx: 0x1_0000_0000 })).toThrow(RangeError);
  });

  it('rejects a short buffer on decode', () => {
    expect(() => decodeFrameHeader(new Uint8Array(FRAME_HEADER_BYTES - 1))).toThrow(RangeError);
  });
});
