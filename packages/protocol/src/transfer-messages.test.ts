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

  it('round-trips a manifest carrying a transferId', () => {
    const manifest: Manifest = {
      type: FrameType.Manifest,
      transferId: '0123456789abcdef0123456789abcdef',
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
    const wire = encodeControl(manifest);
    expect(new TextDecoder().decode(wire)).toBe(
      '{"type":2,"transferId":"0123456789abcdef0123456789abcdef","files":[{"idx":0,"name":"a.bin","size":10,"mime":"application/octet-stream","lastModified":5,"blockSize":8,"blocks":2,"fileDigest":"ab"}],"totalSize":10}',
    );
    expect(decodeControl(wire)).toEqual(manifest);
  });

  it('round-trips a resume_state', () => {
    const msg = {
      type: FrameType.ResumeState,
      transferId: '0123456789abcdef0123456789abcdef',
      files: [
        { idx: 0, haveBlocks: 3 },
        { idx: 1, haveBlocks: 0 },
      ],
    } as const;
    const wire = encodeControl(msg);
    expect(new TextDecoder().decode(wire)).toBe(
      '{"type":12,"transferId":"0123456789abcdef0123456789abcdef","files":[{"idx":0,"haveBlocks":3},{"idx":1,"haveBlocks":0}]}',
    );
    expect(decodeControl(wire)).toEqual(msg);
  });

  it('round-trips a resume_state carrying the manifest fingerprint', () => {
    const fp = '0123456789abcdef'.repeat(4);
    const msg = {
      type: FrameType.ResumeState,
      transferId: '0123456789abcdef0123456789abcdef',
      manifestFingerprint: fp,
      files: [
        { idx: 0, haveBlocks: 3 },
        { idx: 1, haveBlocks: 0 },
      ],
    } as const;
    const wire = encodeControl(msg);
    // Key order is pinned: type, transferId, manifestFingerprint, then files.
    expect(new TextDecoder().decode(wire)).toBe(
      `{"type":12,"transferId":"0123456789abcdef0123456789abcdef","manifestFingerprint":"${fp}","files":[{"idx":0,"haveBlocks":3},{"idx":1,"haveBlocks":0}]}`,
    );
    expect(decodeControl(wire)).toEqual(msg);
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
    expect(() =>
      decodeControl(encodeControl({ type: FrameType.ResumeState, files: [] } as never)),
    ).toThrow(); // missing transferId + empty files
    expect(() =>
      decodeControl(
        encodeControl({ type: FrameType.ResumeState, transferId: 'x', files: [] } as never),
      ),
    ).toThrow(); // empty files
    expect(() =>
      decodeControl(
        encodeControl({
          type: FrameType.ResumeState,
          transferId: 'x',
          files: [{ idx: 0 }],
        } as never),
      ),
    ).toThrow(); // resume file missing haveBlocks
    expect(() =>
      decodeControl(
        encodeControl({
          type: FrameType.ResumeState,
          transferId: 'x',
          manifestFingerprint: 'nope',
          files: [{ idx: 0, haveBlocks: 0 }],
        } as never),
      ),
    ).toThrow(); // malformed manifest fingerprint
  });
});
