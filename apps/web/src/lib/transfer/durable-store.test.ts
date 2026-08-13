import { afterEach, describe, expect, it, vi } from 'vitest';
import { FrameType, type Manifest } from '@sendbeam/protocol';
import {
  DURABLE_LEASE_TTL_MS,
  durableOpfsFiles,
  indexedDbDurableStore,
  type DurableJournalStore,
  type DurableFiles,
} from './durable-store.js';
import type { WritableFileLike } from './stream-sink.js';

// ---------------------------------------------------------------------------
// Minimal but faithful in-memory IndexedDB for the browser-backend tests. Requests
// resolve on microtasks; a readwrite transaction completes after its requests, so the
// store's await-request-then-await-commit ordering is exercised for real.
// ---------------------------------------------------------------------------

type EventHandler = ((ev: Event) => void) | null;

class FakeRequest {
  result: unknown = undefined;
  error: DOMException | null = null;
  onsuccess: EventHandler = null;
  onerror: EventHandler = null;
  constructor(
    private readonly tx: FakeTransaction,
    private readonly run: () => void,
  ) {}
  fire(): void {
    this.run();
    // Success handlers run before the transaction completion microtask is queued, so a
    // store that awaits the request before registering tx.oncomplete still observes it.
    if (this.error) this.onerror?.(new Event('error'));
    else this.onsuccess?.(new Event('success'));
    this.tx.requestDone();
  }
}

class FakeObjectStore {
  constructor(
    private readonly tx: FakeTransaction,
    private readonly data: Map<string, unknown>,
  ) {}
  get(key: string): FakeRequest {
    return this.tx.request(() => this.data.get(key));
  }
  put(value: unknown, key: string): FakeRequest {
    return this.tx.request(() => void this.data.set(key, value));
  }
  delete(key: string): FakeRequest {
    return this.tx.request(() => void this.data.delete(key));
  }
  getAll(): FakeRequest {
    return this.tx.request(() => [...this.data.values()]);
  }
}

class FakeTransaction {
  oncomplete: EventHandler = null;
  onerror: EventHandler = null;
  onabort: EventHandler = null;
  private pending = 0;
  private settled = false;
  private aborted = false;
  constructor(private readonly stores: Map<string, Map<string, unknown>>) {}
  objectStore(name: string): FakeObjectStore {
    return new FakeObjectStore(this, this.stores.get(name)!);
  }
  request<T>(run: () => T): FakeRequest {
    const req = new FakeRequest(this, () => {
      req.result = run();
    });
    this.pending++;
    queueMicrotask(() => req.fire());
    return req;
  }
  requestDone(): void {
    this.pending--;
    if (this.pending === 0 && !this.aborted) {
      queueMicrotask(() => {
        if (this.settled) return;
        this.settled = true;
        this.oncomplete?.(new Event('complete'));
      });
    }
  }
  abort(): void {
    if (this.aborted) return;
    this.aborted = true;
    queueMicrotask(() => {
      if (this.settled) return;
      this.settled = true;
      this.onabort?.(new Event('abort'));
      this.onerror?.(new Event('error'));
    });
  }
}

class FakeDatabase {
  readonly objectStoreNames = {
    contains: (name: string) => this.stores.has(name),
  };
  constructor(private readonly stores: Map<string, Map<string, unknown>>) {}
  createObjectStore(name: string): void {
    if (!this.stores.has(name)) this.stores.set(name, new Map());
  }
  transaction(names: string[], mode: string): FakeTransaction {
    void mode; // the fake serializes every readwrite transaction on the same store map
    const selected = new Map<string, Map<string, unknown>>();
    for (const name of names) selected.set(name, this.stores.get(name)!);
    return new FakeTransaction(selected);
  }
  close(): void {}
}

class FakeOpenRequest {
  result: FakeDatabase | undefined;
  error: DOMException | null = null;
  onupgradeneeded: EventHandler = null;
  onsuccess: EventHandler = null;
  onerror: EventHandler = null;
}

interface FakeIndexedDB {
  open(name: string, version: number): FakeOpenRequest;
  readonly db: FakeDatabase;
}

async function readLease(
  idb: FakeIndexedDB,
  transferId: string,
): Promise<{ transferId: string; ownerId: string; expiresAt: number } | undefined> {
  const tx = idb.db.transaction(['leases'], 'readwrite');
  const req = tx.objectStore('leases').get(transferId);
  await new Promise((resolve) => setTimeout(resolve, 0));
  return req.result as { transferId: string; ownerId: string; expiresAt: number } | undefined;
}

function makeFakeIndexedDB(): FakeIndexedDB {
  const stores = new Map<string, Map<string, unknown>>();
  const db = new FakeDatabase(stores);
  return {
    db,
    open() {
      const req = new FakeOpenRequest();
      queueMicrotask(() => {
        // Real IDB exposes the database on the request before the upgrade handler runs.
        req.result = db;
        for (const name of ['journals', 'leases']) db.createObjectStore(name);
        req.onupgradeneeded?.(new Event('upgradeneeded'));
        req.onsuccess?.(new Event('success'));
      });
      return req;
    },
  };
}

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

function manifest(names: Array<[string, number]>): Manifest {
  return {
    type: FrameType.Manifest,
    transferId: 'a'.repeat(32),
    files: names.map(([name, size], idx) => ({
      idx,
      name,
      size,
      mime: 'application/octet-stream',
      lastModified: 0,
      blockSize: 8,
      blocks: Math.ceil(size / 8),
      fileDigest: 'a'.repeat(64),
    })),
    totalSize: names.reduce((total, [, size]) => total + size, 0),
  };
}

const TRANSFER_ID = 'a'.repeat(32);
const OWNER_A = 'a'.repeat(16);
const OWNER_B = 'b'.repeat(16);
const partKey = (rel: string): string => `sendbeam/durable/${TRANSFER_ID}/${rel}.part`;

afterEach(() => vi.unstubAllGlobals());

// ---------------------------------------------------------------------------
// IndexedDB journal + lease store
// ---------------------------------------------------------------------------

describe('indexedDbDurableStore', () => {
  function store(): DurableJournalStore {
    const idb = makeFakeIndexedDB();
    vi.stubGlobal('indexedDB', idb);
    return indexedDbDurableStore();
  }

  it('round-trips a journal through real encode/decode with checksum verification', async () => {
    const s = store();
    const loaded = await s.loadJournal(TRANSFER_ID);
    expect(loaded.kind).toBe('none');

    const created = await s.createJournal(
      TRANSFER_ID,
      manifest([['a.bin', 10]]),
      { version: 1, value: '0'.repeat(64) },
      { version: 1, value: '1'.repeat(64) },
      1_000,
    );
    expect(created.files[0]!.committedBlocks).toBe(0);

    const reloaded = await s.loadJournal(TRANSFER_ID);
    expect(reloaded.kind).toBe('ok');
    if (reloaded.kind !== 'ok') return;
    expect(reloaded.journal.transferId).toBe(TRANSFER_ID);
    expect(reloaded.journal.manifestFingerprint).toBe(created.manifestFingerprint);
  });

  it('fails closed on a corrupt journal and never deletes it', async () => {
    const s = store();
    // Opening the store creates the object stores.
    expect((await s.loadJournal(TRANSFER_ID)).kind).toBe('none');
    const idb = (globalThis as unknown as { indexedDB: FakeIndexedDB }).indexedDB;
    const tx = idb.db.transaction(['journals'], 'readwrite');
    tx.objectStore('journals').put(new Uint8Array([1, 2, 3, 4]), TRANSFER_ID);
    // Let the write land.
    await new Promise((resolve) => setTimeout(resolve, 0));

    const loaded = await s.loadJournal(TRANSFER_ID);
    expect(loaded.kind).toBe('corrupt');
    // Still present for explicit discard.
    const again = await s.loadJournal(TRANSFER_ID);
    expect(again.kind).toBe('corrupt');
  });

  it('advances a checkpoint only when the caller still owns the lease', async () => {
    const s = store();
    await s.createJournal(
      TRANSFER_ID,
      manifest([['a.bin', 16]]),
      { version: 1, value: '0'.repeat(64) },
      { version: 1, value: '1'.repeat(64) },
      1_000,
    );
    expect((await s.acquireLease(TRANSFER_ID, OWNER_A, 1_000)).kind).toBe('acquired');

    const loaded = await s.loadJournal(TRANSFER_ID);
    if (loaded.kind !== 'ok') throw new Error('expected journal');
    const j = await s.commitBlocks(loaded.journal, 0, 1, 2_000, OWNER_A);
    expect(j.files[0]!.committedBlocks).toBe(1);

    // A different owner (or a discarded lease) must not advance the journal.
    await expect(s.commitBlocks(j, 0, 2, 3_000, OWNER_B)).rejects.toThrow(/lease lost/);
    const reloaded = await s.loadJournal(TRANSFER_ID);
    expect(reloaded.kind).toBe('ok');
    if (reloaded.kind !== 'ok') return;
    expect(reloaded.journal.files[0]!.committedBlocks).toBe(1);
  });

  it('serializes lease acquisition: acquired → contended → stale-taken on TTL expiry', async () => {
    const s = store();
    await s.createJournal(
      TRANSFER_ID,
      manifest([['a.bin', 8]]),
      { version: 1, value: '0'.repeat(64) },
      { version: 1, value: '1'.repeat(64) },
      1_000,
    );
    expect((await s.acquireLease(TRANSFER_ID, OWNER_A, 1_000)).kind).toBe('acquired');
    // Second tab, same owner: renewed (re-entry).
    expect((await s.acquireLease(TRANSFER_ID, OWNER_A, 1_100)).kind).toBe('renewed');
    // Another tab while unexpired: contended.
    expect((await s.acquireLease(TRANSFER_ID, OWNER_B, 1_100)).kind).toBe('contended');
    // After the (renewed) TTL the lease is stale and deterministically taken over.
    expect(
      (await s.acquireLease(TRANSFER_ID, OWNER_B, 1_100 + DURABLE_LEASE_TTL_MS + 1)).kind,
    ).toBe('stale-taken');
    // The new owner can now commit.
    const j = await s.loadJournal(TRANSFER_ID);
    if (j.kind !== 'ok') throw new Error('expected journal');
    await s.commitBlocks(j.journal, 0, 1, 1_100 + DURABLE_LEASE_TTL_MS + 2, OWNER_B);
  });

  it('renews, releases (owner-bound), and discards idempotently', async () => {
    const s = store();
    await s.createJournal(
      TRANSFER_ID,
      manifest([['a.bin', 8]]),
      { version: 1, value: '0'.repeat(64) },
      { version: 1, value: '1'.repeat(64) },
      1_000,
    );
    await s.acquireLease(TRANSFER_ID, OWNER_A, 1_000);
    await s.renewLease(TRANSFER_ID, OWNER_A, 50_000);
    // The renewal moved the expiry forward.
    const idb = (globalThis as unknown as { indexedDB: FakeIndexedDB }).indexedDB;
    expect(await readLease(idb, TRANSFER_ID)).toEqual({
      transferId: TRANSFER_ID,
      ownerId: OWNER_A,
      expiresAt: 50_000 + DURABLE_LEASE_TTL_MS,
    });

    // A non-owner cannot release the lease.
    await s.releaseLease(TRANSFER_ID, OWNER_B);
    expect((await readLease(idb, TRANSFER_ID))?.ownerId).toBe(OWNER_A);

    await s.releaseLease(TRANSFER_ID, OWNER_A);
    await s.discard(TRANSFER_ID);
    await s.discard(TRANSFER_ID); // idempotent
    expect((await s.loadJournal(TRANSFER_ID)).kind).toBe('none');
  });
});

// ---------------------------------------------------------------------------
// OPFS partial-data layer
// ---------------------------------------------------------------------------

/** In-memory OPFS handle tree with optional sync-access-handle availability. */
function fakeStorage(opts: { sync?: boolean; quota?: number } = {}) {
  const syncAvailable = opts.sync ?? true;
  const files = new Map<string, Uint8Array>();
  const writableStreams = new Map<string, FakeWritable>();

  class FakeSyncHandle {
    private size: number;
    constructor(private readonly key: string) {
      this.size = files.get(key)?.length ?? 0;
    }
    write(buffer: Uint8Array, options: { at?: number }): number {
      const at = options.at ?? 0;
      const cur = files.get(this.key) ?? new Uint8Array();
      const end = at + buffer.length;
      const grown = new Uint8Array(Math.max(end, cur.length));
      grown.set(cur);
      grown.set(buffer, at);
      files.set(this.key, grown);
      this.size = grown.length;
      return buffer.length;
    }
    flush(): void {
      // No-op for this test layer; flush-before-commit ordering is asserted at the
      // destination layer where the store and files share an event log.
    }
    getSize(): number {
      return this.size;
    }
    truncate(size: number): void {
      const cur = files.get(this.key) ?? new Uint8Array();
      files.set(this.key, cur.slice(0, size));
      this.size = size;
    }
    close(): void {}
  }

  const makeFileHandle = (key: string): FileSystemHandle =>
    ({
      kind: 'file',
      getFile: async () => {
        const blob = files.get(key) ?? new Uint8Array();
        return new File(
          [blob.buffer.slice(blob.byteOffset, blob.byteOffset + blob.byteLength) as ArrayBuffer],
          key,
        );
      },
      createWritable: async () => {
        const writable = new FakeWritable();
        writableStreams.set(key, writable);
        return writable;
      },
      createSyncAccessHandle: async () => {
        if (!syncAvailable) throw new TypeError('sync access handles unavailable');
        return new FakeSyncHandle(key);
      },
    }) as unknown as FileSystemHandle;

  const join = (prefix: string, name: string): string =>
    prefix === '' ? name : `${prefix}/${name}`;
  const makeDir = (prefix: string): FileSystemDirectoryHandle => {
    const dir = {
      kind: 'directory',
      getDirectoryHandle: (name: string, options: { create?: boolean }) => {
        void options;
        return Promise.resolve(makeDir(join(prefix, name)));
      },
      getFileHandle: (name: string, options: { create?: boolean }) => {
        const key = join(prefix, name);
        if (!options.create && !files.has(key)) throw new DOMException('missing', 'NotFoundError');
        if (options.create && !files.has(key)) files.set(key, new Uint8Array()); // create-on-open
        return Promise.resolve(makeFileHandle(key));
      },
      removeEntry: (name: string, options: { recursive?: boolean } = {}) => {
        const key = join(prefix, name);
        if (options.recursive) {
          for (const existing of [...files.keys()]) {
            if (existing.startsWith(`${key}/`)) files.delete(existing);
          }
        }
        files.delete(key);
        return Promise.resolve();
      },
      entries: () => {
        const children = new Map<string, { kind: 'directory' | 'file' }>();
        for (const key of files.keys()) {
          if (prefix !== '' && !key.startsWith(`${prefix}/`)) continue;
          const rest = prefix === '' ? key : key.slice(prefix.length + 1);
          const slash = rest.indexOf('/');
          const name = slash === -1 ? rest : rest.slice(0, slash);
          const kind: 'directory' | 'file' = slash === -1 ? 'file' : 'directory';
          children.set(name, { kind });
        }
        // Directory children are real directory handles so walk() can recurse; file
        // children carry the read/write surface walk() and listRelPaths need.
        const pairs: Array<[string, FileSystemHandle]> = [...children.entries()].map(
          ([name, meta]) =>
            meta.kind === 'directory'
              ? [name, makeDir(join(prefix, name))]
              : [name, makeFileHandle(join(prefix, name))],
        );
        return rootIterator(pairs);
      },
    } as unknown as FileSystemDirectoryHandle;
    return dir;
  };

  vi.stubGlobal('navigator', {
    storage: {
      getDirectory: async () => makeDir(''),
      ...(opts.quota !== undefined
        ? {
            estimate: async () => ({ quota: opts.quota, usage: 0 }),
          }
        : {}),
    },
  });

  return { files, writableStreams };
}

class FakeWritable implements WritableFileLike {
  bytes = new Uint8Array();
  closed = false;
  async write(request: { type: 'write'; position: number; data: Uint8Array }): Promise<void> {
    const end = request.position + request.data.length;
    if (end > this.bytes.length) {
      const grown = new Uint8Array(end);
      grown.set(this.bytes);
      this.bytes = grown;
    }
    this.bytes.set(request.data, request.position);
  }
  async close(): Promise<void> {
    this.closed = true;
  }
}

function rootIterator(
  entries: Array<[string, FileSystemHandle]>,
): AsyncIterableIterator<[string, FileSystemHandle]> {
  let i = 0;
  return {
    async next() {
      if (i >= entries.length) return { done: true, value: undefined };
      return { done: false, value: entries[i++]! };
    },
    [Symbol.asyncIterator]() {
      return this;
    },
  } as AsyncIterableIterator<[string, FileSystemHandle]>;
}

describe('durableOpfsFiles', () => {
  it('writes through the sync path with flush before every checkpoint and truncates stale tails', async () => {
    const { files } = fakeStorage({ sync: true });
    const f: DurableFiles = durableOpfsFiles();
    expect(await f.probeSync(TRANSFER_ID)).toBe(true);

    const writer = await f.openWriter(TRANSFER_ID, 'folder/a.bin', 0, true);
    await writer.write(0, new Uint8Array([1, 2, 3]));
    await writer.write(8, new Uint8Array([4]));
    await writer.close();
    expect(files.get(partKey('folder/a.bin'))).toEqual(new Uint8Array([1, 2, 3, 0, 0, 0, 0, 0, 4]));
  });

  it('fails closed when a partial is missing or shorter than the checkpoint claims', async () => {
    fakeStorage({ sync: true });
    const f: DurableFiles = durableOpfsFiles();
    await expect(f.openWriter(TRANSFER_ID, 'a.bin', 16, true)).rejects.toThrow(/truncated/);
  });

  it('uses the async fallback and reports sync unavailability honestly', async () => {
    const { writableStreams } = fakeStorage({ sync: false });
    const f: DurableFiles = durableOpfsFiles();
    expect(await f.probeSync(TRANSFER_ID)).toBe(false);
    const writer = await f.openWriter(TRANSFER_ID, 'a.bin', 0, false);
    await writer.write(0, new Uint8Array([9]));
    await writer.close();
    expect(writableStreams.get(partKey('a.bin'))?.bytes).toEqual(new Uint8Array([9]));
    expect(writableStreams.get(partKey('a.bin'))?.closed).toBe(true);
  });

  it('lists, reads prefixes, streams chunks, and removes partials and data dirs', async () => {
    fakeStorage({ sync: true });
    const f: DurableFiles = durableOpfsFiles();
    const writer = await f.openWriter(TRANSFER_ID, 'folder/a.bin', 0, true);
    await writer.write(0, new Uint8Array([1, 2, 3]));
    await writer.write(3, new Uint8Array([4, 5, 6, 7]));
    await writer.close();
    await f.openWriter(TRANSFER_ID, 'b.bin', 0, true).then((w) => w.close());

    expect(await f.listRelPaths(TRANSFER_ID)).toEqual(['b.bin', 'folder/a.bin']);
    expect(await f.partialSize(TRANSFER_ID, 'folder/a.bin')).toBe(7);

    const digest = {
      parts: [] as Uint8Array[],
      update(b: Uint8Array): void {
        this.parts.push(b.slice());
      },
      hexDigest: async (): Promise<string> => '',
    };
    await f.readPrefix(TRANSFER_ID, 'folder/a.bin', 5, digest);
    expect(digest.parts).toEqual([new Uint8Array([1, 2, 3, 4, 5])]);

    const chunks: Uint8Array[] = [];
    await f.readPartialChunks(TRANSFER_ID, 'folder/a.bin', (c) => {
      chunks.push(c.slice());
    });
    expect(chunks).toEqual([new Uint8Array([1, 2, 3, 4, 5, 6, 7])]);

    await f.removePartial(TRANSFER_ID, 'b.bin');
    expect(await f.listRelPaths(TRANSFER_ID)).toEqual(['folder/a.bin']);

    await f.removeData(TRANSFER_ID);
    await f.removeData(TRANSFER_ID); // idempotent
    expect(await f.partialSize(TRANSFER_ID, 'folder/a.bin')).toBeUndefined();
  });
});
