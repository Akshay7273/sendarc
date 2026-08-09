import { afterEach, describe, expect, it, vi } from 'vitest';
import { DurableOpfsFile, openDurableOpfsFile, type SyncAccessHandleLike } from './opfs-file.js';

/** In-memory sync access handle: a growable buffer with the read/write/truncate surface we use. */
class FakeSyncHandle implements SyncAccessHandleLike {
  buf: Uint8Array;
  flushes = 0;
  closed = false;
  constructor(initial: Uint8Array = new Uint8Array()) {
    this.buf = initial;
  }
  write(buffer: Uint8Array, options?: { at?: number }): number {
    const at = options?.at ?? 0;
    const end = at + buffer.length;
    if (end > this.buf.length) {
      const grown = new Uint8Array(end);
      grown.set(this.buf);
      this.buf = grown;
    }
    this.buf.set(buffer, at);
    return buffer.length;
  }
  read(buffer: Uint8Array, options?: { at?: number }): number {
    const at = options?.at ?? 0;
    const n = Math.max(0, Math.min(buffer.length, this.buf.length - at));
    buffer.set(this.buf.subarray(at, at + n));
    return n;
  }
  truncate(newSize: number): void {
    const next = new Uint8Array(newSize);
    next.set(this.buf.subarray(0, Math.min(newSize, this.buf.length)));
    this.buf = next;
  }
  getSize(): number {
    return this.buf.length;
  }
  flush(): void {
    this.flushes++;
  }
  close(): void {
    this.closed = true;
  }
}

afterEach(() => vi.unstubAllGlobals());

describe('DurableOpfsFile', () => {
  it('writes positioned blocks and reads the committed prefix back', () => {
    const handle = new FakeSyncHandle();
    const file = new DurableOpfsFile(handle);
    file.write(0, new Uint8Array([1, 2, 3, 4]));
    file.write(4, new Uint8Array([5, 6, 7, 8]));
    expect(file.size()).toBe(8);
    const into = new Uint8Array(8);
    expect(file.read(0, into)).toBe(8);
    expect(into).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
  });

  it('truncates a torn tail down to the recorded high-water mark', () => {
    const handle = new FakeSyncHandle();
    const file = new DurableOpfsFile(handle);
    file.write(0, new Uint8Array([1, 2, 3, 4]));
    file.write(4, new Uint8Array([9, 9])); // a partial, unrecorded tail
    file.truncate(4);
    expect(file.size()).toBe(4);
    const into = new Uint8Array(4);
    expect(file.read(0, into)).toBe(4);
    expect(into).toEqual(new Uint8Array([1, 2, 3, 4]));
  });

  it('flushes then releases the handle on close, and is idempotent', () => {
    const handle = new FakeSyncHandle();
    const file = new DurableOpfsFile(handle);
    file.close();
    file.close();
    expect(handle.flushes).toBe(1);
    expect(handle.closed).toBe(true);
  });

  it('releases the handle without flushing on abort', () => {
    const handle = new FakeSyncHandle();
    const file = new DurableOpfsFile(handle);
    file.abort();
    expect(handle.flushes).toBe(0);
    expect(handle.closed).toBe(true);
  });

  it('rejects a write after close and a short write', () => {
    const closedFile = new DurableOpfsFile(new FakeSyncHandle());
    closedFile.close();
    expect(() => closedFile.write(0, new Uint8Array([1]))).toThrow(/write after close/);

    const short = new FakeSyncHandle();
    short.write = () => 1; // report fewer bytes written than requested
    expect(() => new DurableOpfsFile(short).write(0, new Uint8Array([1, 2]))).toThrow(
      /short OPFS write/,
    );
  });
});

describe('openDurableOpfsFile', () => {
  function stubStorage(handle: FakeSyncHandle | undefined): void {
    const fileHandle =
      handle === undefined ? {} : { createSyncAccessHandle: vi.fn(async () => handle) };
    vi.stubGlobal('navigator', {
      storage: {
        getDirectory: vi.fn(async () => ({ getFileHandle: vi.fn(async () => fileHandle) })),
      },
    });
  }

  it('opens a sync-access-backed durable file and round-trips through it', async () => {
    const handle = new FakeSyncHandle();
    stubStorage(handle);
    const file = await openDurableOpfsFile('sendarc-key');
    file.write(0, new Uint8Array([42, 43]));
    file.close();
    expect(handle.buf).toEqual(new Uint8Array([42, 43]));
    expect(handle.closed).toBe(true);
  });

  it('fails when synchronous OPFS access is unavailable', async () => {
    stubStorage(undefined);
    await expect(openDurableOpfsFile('sendarc-key')).rejects.toThrow(/synchronous OPFS access/);
  });
});
