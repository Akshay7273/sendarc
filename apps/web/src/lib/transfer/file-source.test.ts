import { describe, it, expect } from 'vitest';
import { blobFileSource } from './file-source.js';

async function collect(src: { stream(): AsyncIterable<Uint8Array> }): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  for await (const c of src.stream()) parts.push(c);
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

describe('blobFileSource', () => {
  it('exposes File metadata', () => {
    const f = new File([new Uint8Array([1, 2, 3])], 'a.bin', {
      type: 'application/octet-stream',
      lastModified: 42,
    });
    const src = blobFileSource(f);
    expect(src.meta).toEqual({
      name: 'a.bin',
      size: 3,
      mime: 'application/octet-stream',
      lastModified: 42,
    });
  });

  it('streams the exact bytes and is re-callable', async () => {
    const bytes = new Uint8Array(5000).map((_, i) => i & 0xff);
    const f = new File([bytes], 'big.bin');
    const src = blobFileSource(f, 1024);
    const first = await collect(src);
    const second = await collect(src);
    expect(first).toEqual(bytes);
    expect(second).toEqual(bytes);
  });

  it('yields chunks no larger than the chunk size', async () => {
    const f = new File([new Uint8Array(2500)], 'x');
    const src = blobFileSource(f, 1000);
    const sizes: number[] = [];
    for await (const c of src.stream()) sizes.push(c.length);
    expect(Math.max(...sizes)).toBeLessThanOrEqual(1000);
    expect(sizes.reduce((a, b) => a + b, 0)).toBe(2500);
  });
});
