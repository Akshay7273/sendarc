import { describe, expect, it } from 'vitest';
import type { FileEntry } from './transfer.js';
import { completionDigest } from './transfer-set.js';

const file = (idx: number, digest: string): FileEntry => ({
  idx,
  name: `${idx}.bin`,
  size: 0,
  mime: '',
  lastModified: 0,
  blockSize: 1,
  blocks: 0,
  fileDigest: digest,
});

describe('completionDigest', () => {
  it('preserves the single-file digest and matches the Go multi-file vector', async () => {
    const a = 'a'.repeat(64);
    const b = 'b'.repeat(64);
    expect(await completionDigest([file(0, a)])).toBe(a);
    expect(await completionDigest([file(0, a), file(1, b)])).toBe(
      '5e9ae866add9a85d69c3481d059bb9f158a39e5670ba11f95112fc409630894e',
    );
  });
});
