import { describe, it, expect } from 'vitest';
import { encodeFrameHeader, decodeFrameHeader } from './frame.js';
import { FRAME_HEADER_BYTES } from './constants.js';
import { FrameType, type FrameHeader, type FileEntry, type Manifest } from './transfer.js';
import { normalizeTransferPath, validateManifest } from './safe-path.js';
import { deriveMaster, deriveTransferKeys } from './keyschedule.js';
import { seal, open, type FrameHeaderInput } from './aead.js';

// Deterministic seeded PRNG (mulberry32) so "property" checks are reproducible
// in CI without pulling in a property-testing dependency.
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function intIn(rand: () => number, max: number): number {
  return Math.floor(rand() * (max + 1));
}

function u8(rand: () => number): number {
  return intIn(rand, 0xff);
}
function u16(rand: () => number): number {
  return intIn(rand, 0xffff);
}
function u32(rand: () => number): number {
  return intIn(rand, 0xffffffff);
}

const master = new Uint8Array(32).fill(9);

// Frame header encode/decode round-trip over many arbitrary but
// in-range headers; decode(encode(h)) must equal h exactly and stay 16 bytes.
describe('frame header property', () => {
  it('round-trips arbitrary in-range headers', () => {
    const rand = rng(0xbeef);
    for (let i = 0; i < 2000; i++) {
      const h: FrameHeader = {
        version: u8(rand),
        type: u8(rand),
        flags: u8(rand),
        fileIdx: u16(rand),
        blockIdx: u32(rand),
        frameOff: u32(rand),
        len: u16(rand),
      };
      const buf = encodeFrameHeader(h);
      expect(buf.byteLength).toBe(FRAME_HEADER_BYTES);
      expect(decodeFrameHeader(buf)).toEqual(h);
    }
  });

  it('rejects out-of-range fields for every width', () => {
    const base: FrameHeader = {
      version: 1,
      type: FrameType.BlockData,
      flags: 0,
      fileIdx: 0,
      blockIdx: 0,
      frameOff: 0,
      len: 0,
    };
    const cases: Array<Partial<FrameHeader>> = [
      { version: 256 },
      { type: 256 },
      { flags: 256 },
      { fileIdx: 65536 },
      { blockIdx: 0x100000000 },
      { frameOff: 0x100000000 },
      { len: 65536 },
      { version: -1 },
      { blockIdx: 1.5 },
    ];
    for (const patch of cases) {
      expect(() => encodeFrameHeader({ ...base, ...patch })).toThrow(RangeError);
    }
  });

  it('rejects buffers shorter than the header', () => {
    for (let n = 0; n < FRAME_HEADER_BYTES; n++) {
      expect(() => decodeFrameHeader(new Uint8Array(n))).toThrow(RangeError);
    }
  });
});

// AEAD seal/open inverse over arbitrary plaintext lengths, plus the
// guarantee that any single-byte mutation of a sealed frame fails to open.
describe('AEAD frame property', () => {
  it('seal then open recovers plaintext and header len', async () => {
    const keys = await deriveTransferKeys(await deriveMaster(master, new Uint8Array(0)));
    const rand = rng(0xdeadbeef);
    for (let i = 0; i < 50; i++) {
      const len = intIn(rand, 2048);
      const plaintext = new Uint8Array(len);
      for (let j = 0; j < len; j++) plaintext[j] = u8(rand);
      const header: FrameHeaderInput = {
        version: 1,
        type: FrameType.BlockData,
        flags: i % 2 === 0 ? 0 : 1,
        fileIdx: u16(rand),
        blockIdx: u32(rand),
        frameOff: u32(rand),
      };
      const frame = await seal(keys.o2j, i, header, plaintext);
      const opened = await open(keys.o2j, i, frame);
      expect(opened.header.len).toBe(len);
      expect(opened.header.type).toBe(FrameType.BlockData);
      expect(opened.plaintext).toEqual(plaintext);
    }
  });

  it('a single-byte mutation never opens', async () => {
    const keys = await deriveTransferKeys(await deriveMaster(master, new Uint8Array(0)));
    const plaintext = new Uint8Array(64).fill(7);
    const frame = await seal(
      keys.o2j,
      0,
      { version: 1, type: FrameType.BlockData, flags: 0, fileIdx: 0, blockIdx: 0, frameOff: 0 },
      plaintext,
    );
    const mutated = frame.slice();
    mutated[mutated.length - 1] ^= 0x01;
    await expect(open(keys.o2j, 0, mutated)).rejects.toThrow();
  });
});

// Arbitrary safe relative segment strings must produce canonical,
// absolute-free, dot-free output; structural invariants mirror the Go fuzzer.
describe('normalizeTransferPath property', () => {
  const alpha = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_ .',
    legal = 64;

  it('accepts and canonicalizes arbitrary well-formed relative paths', () => {
    const rand = rng(0x1111);
    for (let i = 0; i < 2000; i++) {
      const depth = 1 + intIn(rand, 10);
      const segs: string[] = [];
      for (let d = 0; d < depth; d++) {
        const n = 1 + intIn(rand, 40);
        // Every segment starts with 'z' so it can never collide with a Windows
        // reserved name (con/prn/aux/nul/com[1-9]/lpt[1-9]) and thus always passes
        // normalization.
        let s = 'z';
        for (let k = 1; k < n; k++) s += alpha[intIn(rand, legal - 1)];
        if (d % 3 === 0 && d > 0) {
          // Occasionally embed a backslash to exercise canonicalization without
          // making the path absolute or creating empty segments.
          segs.push(`${s}\\tail`);
        } else {
          segs.push(s);
        }
      }
      const input = segs.join('/');
      const out = normalizeTransferPath(input);
      expect(out).not.toMatch(/^[/\\]/);
      expect(out).not.toMatch(/\\/);
      for (const part of out.split('/')) {
        expect(part.length).toBeGreaterThan(0);
        expect(part).not.toBe('.');
        expect(part).not.toBe('..');
      }
    }
  });

  it('rejects unsafe inputs deterministically', () => {
    const rand = rng(0x2222);
    const unsafe = [
      '/',
      '\\',
      '..',
      '.',
      'nul',
      'CON',
      'a:b',
      'a*',
      'a?',
      'a"',
      'a<',
      'a>',
      'a|',
      'x ',
      'a.',
    ];
    for (let i = 0; i < 2000; i++) {
      const pick = unsafe[intIn(rand, unsafe.length - 1)];
      // Prepend/append a legal segment so the input is a plausible path that
      // must still be rejected (traversal, reserved names, bad chars, suffixes).
      const input = `${alpha[intIn(rand, legal - 1)]}/${pick}`;
      expect(() => normalizeTransferPath(input)).toThrow();
    }
    expect(() => normalizeTransferPath('')).toThrow();
    expect(() => normalizeTransferPath('/etc/passwd')).toThrow();
    expect(() => normalizeTransferPath('C:\\secret')).toThrow();
  });
});

// validateManifest accepts geometrically consistent manifests and
// rejects any whose block geometry, size sum, or paths are inconsistent.
describe('validateManifest property', () => {
  function file(idx: number, name: string, size: number, blockSize: number): FileEntry {
    return {
      idx,
      name,
      size,
      mime: 'application/octet-stream',
      lastModified: 1,
      blockSize,
      blocks: size === 0 ? 0 : Math.ceil(size / blockSize),
      fileDigest: 'aa',
    };
  }

  it('accepts consistent multi-file manifests and canonicalizes paths', () => {
    const rand = rng(0x3333);
    for (let i = 0; i < 200; i++) {
      const n = 1 + intIn(rand, 8);
      const files: FileEntry[] = [];
      let total = 0;
      for (let k = 0; k < n; k++) {
        const size = intIn(rand, 1 << 20);
        total += size;
        files.push(file(k, `dir${k}/file-${k}.bin`, size, 1 + intIn(rand, 65536)));
      }
      const m: Manifest = { type: FrameType.Manifest, files, totalSize: total };
      const out = validateManifest(m);
      expect(out.files.length).toBe(n);
      expect(out.totalSize).toBe(total);
      for (let k = 0; k < n; k++) expect(out.files[k].idx).toBe(k);
    }
  });

  it('rejects size/geometry inconsistencies', () => {
    const good = file(0, 'a.bin', 100, 16);
    const wrongTotal: Manifest = { type: FrameType.Manifest, files: [good], totalSize: 99 };
    expect(() => validateManifest(wrongTotal)).toThrow();
    const badBlocks: Manifest = {
      type: FrameType.Manifest,
      files: [{ ...good, blocks: good.blocks + 1 }],
      totalSize: 100,
    };
    expect(() => validateManifest(badBlocks)).toThrow();
    const badPath: Manifest = {
      type: FrameType.Manifest,
      files: [{ ...good, name: '../escape' }],
      totalSize: 100,
    };
    expect(() => validateManifest(badPath)).toThrow();
  });
});
