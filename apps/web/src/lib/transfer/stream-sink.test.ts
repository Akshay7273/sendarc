import { describe, it, expect } from 'vitest';
import { streamSink, type WritableFileLike } from './stream-sink.js';

describe('streamSink', () => {
  it('maps offsets to positioned writes and closes', async () => {
    const writes: Array<{ position: number; len: number }> = [];
    let closed = false;
    const w: WritableFileLike = {
      async write(d) {
        writes.push({ position: d.position, len: (d.data as Uint8Array).length });
      },
      async close() {
        closed = true;
      },
    };
    const s = streamSink(w);
    await s.write(0, new Uint8Array(10));
    await s.write(10, new Uint8Array(5));
    await s.close();
    expect(writes).toEqual([
      { position: 0, len: 10 },
      { position: 10, len: 5 },
    ]);
    expect(closed).toBe(true);
  });

  it('aborts via the underlying stream when available', async () => {
    let abortReason: unknown;
    let closed = false;
    const w: WritableFileLike = {
      async write() {},
      async close() {
        closed = true;
      },
      async abort(r) {
        abortReason = r;
      },
    };
    const s = streamSink(w);
    await s.abort('integrity');
    expect(abortReason).toBe('integrity');
    expect(closed).toBe(false);
  });

  it('falls back to close when abort is unavailable', async () => {
    let closed = false;
    const w: WritableFileLike = {
      async write() {},
      async close() {
        closed = true;
      },
    };
    const s = streamSink(w);
    await s.abort('x');
    expect(closed).toBe(true);
  });
});
