import { describe, it, expect } from 'vitest';
import { MemorySink, bytesSource } from './transfer-ports.js';

describe('MemorySink', () => {
  it('reassembles out-of-order offsets into one buffer', () => {
    const s = new MemorySink();
    s.write(4, new Uint8Array([5, 6, 7, 8]));
    s.write(0, new Uint8Array([1, 2, 3, 4]));
    s.close();
    expect([...s.bytes()]).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(s.isClosed).toBe(true);
  });

  it('records an abort reason and refuses writes afterward', () => {
    const s = new MemorySink();
    s.abort('integrity');
    expect(s.abortReason).toBe('integrity');
    expect(() => s.write(0, new Uint8Array([1]))).toThrow();
  });
});

describe('bytesSource', () => {
  it('re-streams the same bytes on each call in chunk-sized pieces', async () => {
    const data = new Uint8Array(200).map((_, i) => i % 256);
    const src = bytesSource(data, { name: 'f', size: 200, mime: '', lastModified: 0 }, 64);
    for (let pass = 0; pass < 2; pass++) {
      const got: number[] = [];
      const sizes: number[] = [];
      for await (const c of src.stream()) {
        sizes.push(c.length);
        got.push(...c);
      }
      expect(got).toEqual([...data]);
      expect(sizes).toEqual([64, 64, 64, 8]);
    }
  });

  it('yields nothing for an empty source', async () => {
    const src = bytesSource(new Uint8Array(0), { name: 'f', size: 0, mime: '', lastModified: 0 });
    const chunks: Uint8Array[] = [];
    for await (const c of src.stream()) chunks.push(c);
    expect(chunks).toEqual([]);
  });
});
