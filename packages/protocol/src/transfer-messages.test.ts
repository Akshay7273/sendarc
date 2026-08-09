import { describe, it, expect } from 'vitest';
import { encodeControl, decodeControl } from './transfer-messages.js';
import { FrameType, type Manifest } from './transfer.js';

describe('control-message codec', () => {
  it('round-trips a manifest', () => {
    const manifest: Manifest = {
      type: FrameType.Manifest,
      files: [
        {
          idx: 0,
          name: 'a.bin',
          size: 10,
          mime: 'application/octet-stream',
          lastModified: 5,
          blockSize: 8,
          blocks: 2,
          fileDigest: 'ab',
        },
      ],
      totalSize: 10,
    };
    expect(decodeControl(encodeControl(manifest))).toEqual(manifest);
  });

  it('round-trips block and terminal messages', () => {
    const msgs = [
      { type: FrameType.BlockHash, fileIdx: 0, blockIdx: 1, sha256: 'ff' },
      { type: FrameType.BlockRecv, fileIdx: 0, blockIdx: 1 },
      { type: FrameType.Ack, fileIdx: 0, blockIdx: 1 },
      { type: FrameType.Nack, fileIdx: 0, blockIdx: 2, reason: 'missing' },
      { type: FrameType.Nack, fileIdx: 0, blockIdx: 3, reason: 'timeout' },
      { type: FrameType.Control, op: 'pause' },
      { type: FrameType.Control, op: 'resume' },
      { type: FrameType.Control, op: 'cancel' },
      { type: FrameType.Complete, fileDigest: 'deadbeef' },
      { type: FrameType.Done },
      { type: FrameType.Fail, reason: 'digest_mismatch' },
      { type: FrameType.Fail, reason: 'retry_exhausted' },
    ] as const;
    for (const m of msgs) expect(decodeControl(encodeControl(m))).toEqual(m);
  });

  it('rejects malformed JSON and unknown/invalid shapes', () => {
    expect(() => decodeControl(new Uint8Array([0x7b, 0x7b]))).toThrow(); // "{{"
    expect(() => decodeControl(encodeControl({ type: 999 } as never))).toThrow();
    expect(() =>
      decodeControl(encodeControl({ type: FrameType.Fail, reason: 'nope' } as never)),
    ).toThrow();
    expect(() =>
      decodeControl(
        encodeControl({ type: FrameType.Nack, fileIdx: 0, blockIdx: 1, reason: 'bad' } as never),
      ),
    ).toThrow();
    expect(() =>
      decodeControl(encodeControl({ type: FrameType.Control, op: 'stop' } as never)),
    ).toThrow();
    expect(() => decodeControl(encodeControl({ type: FrameType.Complete } as never))).toThrow(); // missing fileDigest
  });
});
