import { afterEach, describe, expect, it, vi } from 'vitest';
import { opfsResumeStore, type ResumeRecord } from './resume-store.js';
import type { WritableFileLike } from './stream-sink.js';

/** A single OPFS file entry backed by a byte buffer, exposing the getFile/createWritable seam. */
class FakeEntry {
  kind = 'file' as const;
  bytes = new Uint8Array();
  constructor(public name: string) {}
  async getFile(): Promise<{ text(): Promise<string> }> {
    const bytes = this.bytes;
    return { text: async () => new TextDecoder().decode(bytes) };
  }
  createWritable(): Promise<WritableFileLike> {
    return Promise.resolve({
      write: async (request: {
        type: 'write';
        position: number;
        data: Uint8Array;
      }): Promise<void> => {
        this.bytes = request.data.slice();
      },
      close: async (): Promise<void> => {},
      abort: async (): Promise<void> => {},
    });
  }
}

/** An in-memory OPFS root implementing just the handle/iterator surface the store touches. */
class FakeRoot {
  entries = new Map<string, FakeEntry>();
  async getFileHandle(name: string, options?: { create?: boolean }): Promise<FakeEntry> {
    let entry = this.entries.get(name);
    if (!entry) {
      if (!options?.create) {
        throw new DOMException(`${name} not found`, 'NotFoundError');
      }
      entry = new FakeEntry(name);
      this.entries.set(name, entry);
    }
    return entry;
  }
  async removeEntry(name: string): Promise<void> {
    this.entries.delete(name);
  }
  async *values(): AsyncIterable<FakeEntry> {
    yield* this.entries.values();
  }
}

function stubRoot(root: FakeRoot): void {
  vi.stubGlobal('navigator', {
    storage: { getDirectory: vi.fn(async () => root) },
  });
}

function record(room: number, over: Partial<ResumeRecord> = {}): ResumeRecord {
  return {
    room,
    transferId: 'ffeeddccbbaa99887766554433221100',
    opfsKey: `sendarc-key-${room}`,
    name: 'movie.bin',
    mime: 'application/octet-stream',
    size: 1000,
    blockSize: 64,
    haveBlocks: 5,
    updatedAt: 1,
    ...over,
  };
}

afterEach(() => vi.unstubAllGlobals());

describe('opfsResumeStore', () => {
  it('round-trips a record by room', async () => {
    stubRoot(new FakeRoot());
    const store = opfsResumeStore();
    await store.put(record(7));
    expect(await store.get(7)).toEqual(record(7));
  });

  it('returns undefined for an absent room', async () => {
    stubRoot(new FakeRoot());
    expect(await opfsResumeStore().get(404)).toBeUndefined();
  });

  it('overwrites an earlier record for the same room', async () => {
    stubRoot(new FakeRoot());
    const store = opfsResumeStore();
    await store.put(record(3, { haveBlocks: 2 }));
    await store.put(record(3, { haveBlocks: 9, updatedAt: 2 }));
    expect((await store.get(3))?.haveBlocks).toBe(9);
  });

  it('deletes a record', async () => {
    stubRoot(new FakeRoot());
    const store = opfsResumeStore();
    await store.put(record(1));
    await store.delete(1);
    expect(await store.get(1)).toBeUndefined();
  });

  it('lists only well-formed resume sidecars', async () => {
    const root = new FakeRoot();
    stubRoot(root);
    const store = opfsResumeStore();
    await store.put(record(1));
    await store.put(record(2));
    // An unrelated OPFS entry and a torn sidecar must both be skipped.
    root.entries.set('sendarc-uuid-movie.bin', new FakeEntry('sendarc-uuid-movie.bin'));
    const torn = new FakeEntry('sendarc-resume-3.json');
    torn.bytes = new TextEncoder().encode('{ not json');
    root.entries.set('sendarc-resume-3.json', torn);

    const rooms = (await store.list()).map((r) => r.room).sort();
    expect(rooms).toEqual([1, 2]);
  });

  it('discards a sidecar whose JSON is not a resume record', async () => {
    const root = new FakeRoot();
    stubRoot(root);
    const bad = new FakeEntry('sendarc-resume-8.json');
    bad.bytes = new TextEncoder().encode(JSON.stringify({ room: 8 })); // missing fields
    root.entries.set('sendarc-resume-8.json', bad);
    expect(await opfsResumeStore().get(8)).toBeUndefined();
  });
});
