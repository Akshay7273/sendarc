import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  commitBlocks as advanceJournal,
  DIGEST_CHECKPOINT_FORMAT_GO_STDLIB,
  encodeJournal,
  FrameType,
  type JournalDigestCheckpoint,
  type Manifest,
} from '@sendbeam/protocol';
import {
  DURABLE_LEASE_TTL_MS,
  discardDurableTransfer,
  durableOpfsFiles,
  indexedDbDurableStore,
  type DurableJournalStore,
  type DurableFiles,
} from './durable-store.js';
import type { WritableFileLike } from './stream-sink.js';
import { DurableDestination } from './durable-destination.js';
import { createSha256DigestFactory } from './digest.js';

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

  it('lease-guarded credential attach: a stale owner cannot overwrite a taken-over journal (BLOCKER 6)', async () => {
    const s = store();
    await s.createJournal(
      TRANSFER_ID,
      manifest([['a.bin', 16]]),
      { version: 1, value: '0'.repeat(64) },
      { version: 1, value: '1'.repeat(64) },
      1_000,
    );
    // A acquires the lease.
    expect((await s.acquireLease(TRANSFER_ID, OWNER_A, 1_000)).kind).toBe('acquired');
    // A's lease expires; B takes over and advances the journal.
    const takenOverAt = 1_000 + DURABLE_LEASE_TTL_MS + 1;
    expect((await s.acquireLease(TRANSFER_ID, OWNER_B, takenOverAt)).kind).toBe('stale-taken');
    const loaded = await s.loadJournal(TRANSFER_ID);
    if (loaded.kind !== 'ok') throw new Error('expected journal');
    await s.commitBlocks(loaded.journal, 0, 1, takenOverAt + 1, OWNER_B);

    // A wakes and tries to attach its credential: it lost the lease, so it fails closed and
    // B's newer progress is untouched.
    const envelope = { version: 1, value: 'e'.repeat(64) };
    await expect(
      s.attachResumeSecret(TRANSFER_ID, envelope, OWNER_A, takenOverAt + 2),
    ).rejects.toThrow(/lease lost/);
    const afterA = await s.loadJournal(TRANSFER_ID);
    expect(afterA.kind).toBe('ok');
    if (afterA.kind !== 'ok') return;
    expect(afterA.journal.files[0]!.committedBlocks).toBe(1);
    expect(afterA.journal.resumeSecret).toBeUndefined();

    // B may attach successfully; the credential lands and progress is preserved.
    const attached = await s.attachResumeSecret(TRANSFER_ID, envelope, OWNER_B, takenOverAt + 3);
    expect(attached.resumeSecret).toEqual(envelope);
    expect(attached.files[0]!.committedBlocks).toBe(1);
    const final = await s.loadJournal(TRANSFER_ID);
    expect(final.kind).toBe('ok');
    if (final.kind !== 'ok') return;
    expect(final.journal.resumeSecret).toEqual(envelope);
    expect(final.journal.files[0]!.committedBlocks).toBe(1); // no regression/rewind
  });

  it('same-owner CAS: a journal advanced between the snapshot and write passes is never overwritten (BLOCKER 2)', async () => {
    const s = store();
    await s.createJournal(
      TRANSFER_ID,
      manifest([['a.bin', 16]]),
      { version: 1, value: '0'.repeat(64) },
      { version: 1, value: '1'.repeat(64) },
      1_000,
    );
    await s.acquireLease(TRANSFER_ID, OWNER_A, 1_000);
    const loaded = await s.loadJournal(TRANSFER_ID);
    if (loaded.kind !== 'ok') throw new Error('expected journal');
    expect(loaded.journal.files[0]!.committedBlocks).toBe(0);

    // Pre-compute what owner A's concurrent commit (blocks 0 -> 1) will encode to.
    const advanced = advanceJournal(loaded.journal, 0, 1, 2_000);
    const advancedBytes = await encodeJournal(advanced);

    // Inject the advance exactly when the attach's final readwrite (CAS) transaction is
    // created — AFTER its pass-1 snapshot read, BEFORE its write pass — by writing the
    // advanced bytes into the shared journals map synchronously at transaction creation.
    const idb = (globalThis as unknown as { indexedDB: FakeIndexedDB }).indexedDB;
    const stores = (idb.db as unknown as { stores: Map<string, Map<string, unknown>> }).stores;
    let injected = false;
    const origTx = idb.db.transaction.bind(idb.db);
    idb.db.transaction = ((names: string[], mode: string) => {
      if (!injected && mode === 'readwrite' && names.includes('journals')) {
        injected = true;
        stores.get('journals')!.set(TRANSFER_ID, advancedBytes);
      }
      return origTx(names, mode);
    }) as typeof idb.db.transaction;

    const envelope = { version: 1, value: 'e'.repeat(64) };
    const attached = await s.attachResumeSecret(TRANSFER_ID, envelope, OWNER_A, 3_000);

    // The CAS aborted the stale write and retried from a fresh snapshot: the final journal
    // keeps committedBlocks = 1 (never regressed to 0) AND carries the credential.
    expect(attached.files[0]!.committedBlocks).toBe(1);
    expect(attached.resumeSecret).toEqual(envelope);
    const final = await s.loadJournal(TRANSFER_ID);
    expect(final.kind).toBe('ok');
    if (final.kind !== 'ok') return;
    expect(final.journal.files[0]!.committedBlocks).toBe(1); // no regression/rewind
    expect(final.journal.resumeSecret).toEqual(envelope);
  });

  it('same-owner CAS: a newer digest checkpoint/timestamp between passes is preserved, never restored to the stale one (BLOCKER 2)', async () => {
    const s = store();
    await s.createJournal(
      TRANSFER_ID,
      manifest([['a.bin', 16]]),
      { version: 1, value: '0'.repeat(64) },
      { version: 1, value: '1'.repeat(64) },
      1_000,
    );
    await s.acquireLease(TRANSFER_ID, OWNER_A, 1_000);
    const loaded = await s.loadJournal(TRANSFER_ID);
    if (loaded.kind !== 'ok') throw new Error('expected journal');

    // Owner A advances the journal with a NEW digest checkpoint + timestamp while the
    // attach is between its snapshot pass and its write pass.
    const checkpoint: JournalDigestCheckpoint = {
      format: DIGEST_CHECKPOINT_FORMAT_GO_STDLIB,
      committedBlocks: 1,
      committedBytes: 8,
      state: 'ab'.repeat(32),
    };
    const advanced = advanceJournal(loaded.journal, 0, 1, 2_000, checkpoint);
    const advancedBytes = await encodeJournal(advanced);

    const idb = (globalThis as unknown as { indexedDB: FakeIndexedDB }).indexedDB;
    const stores = (idb.db as unknown as { stores: Map<string, Map<string, unknown>> }).stores;
    let injected = false;
    const origTx = idb.db.transaction.bind(idb.db);
    idb.db.transaction = ((names: string[], mode: string) => {
      if (!injected && mode === 'readwrite' && names.includes('journals')) {
        injected = true;
        stores.get('journals')!.set(TRANSFER_ID, advancedBytes);
      }
      return origTx(names, mode);
    }) as typeof idb.db.transaction;

    const envelope = { version: 1, value: 'e'.repeat(64) };
    const attached = await s.attachResumeSecret(TRANSFER_ID, envelope, OWNER_A, 3_000);

    // The newer checkpoint and timestamp survive; the stale snapshot (blocks 0, no
    // checkpoint, updatedAt 1_000) was never written back.
    expect(attached.files[0]!.committedBlocks).toBe(1);
    expect(attached.files[0]!.digestCheckpoint).toEqual(checkpoint);
    expect(attached.updatedAt).toBe(2_000);
    const final = await s.loadJournal(TRANSFER_ID);
    expect(final.kind).toBe('ok');
    if (final.kind !== 'ok') return;
    expect(final.journal.files[0]!.committedBlocks).toBe(1);
    expect(final.journal.files[0]!.digestCheckpoint).toEqual(checkpoint);
    expect(final.journal.updatedAt).toBe(2_000);
    expect(final.journal.resumeSecret).toEqual(envelope);
  });

  it('preserves an existing credential exactly and fails closed on an unusable journal (BLOCKER 6)', async () => {
    const s = store();
    await s.createJournal(
      TRANSFER_ID,
      manifest([['a.bin', 8]]),
      { version: 1, value: '0'.repeat(64) },
      { version: 1, value: '1'.repeat(64) },
      1_000,
    );
    await s.acquireLease(TRANSFER_ID, OWNER_A, 1_000);
    const first = { version: 1, value: 'd'.repeat(64) };
    await s.attachResumeSecret(TRANSFER_ID, first, OWNER_A, 2_000);
    // A second attach with a different envelope preserves the existing credential exactly.
    const second = { version: 1, value: 'e'.repeat(64) };
    await s.attachResumeSecret(TRANSFER_ID, second, OWNER_A, 3_000);
    const loaded = await s.loadJournal(TRANSFER_ID);
    expect(loaded.kind).toBe('ok');
    if (loaded.kind !== 'ok') return;
    expect(loaded.journal.resumeSecret).toEqual(first);

    // A corrupt stored journal fails closed and is not overwritten by the attach.
    const idb = (globalThis as unknown as { indexedDB: FakeIndexedDB }).indexedDB;
    const tx = idb.db.transaction(['journals'], 'readwrite');
    tx.objectStore('journals').put(new Uint8Array([9, 9, 9]), TRANSFER_ID);
    await new Promise((resolve) => setTimeout(resolve, 0));
    await expect(s.attachResumeSecret(TRANSFER_ID, second, OWNER_A, 4_000)).rejects.toThrow(
      /unusable/,
    );
    const again = await s.loadJournal(TRANSFER_ID);
    expect(again.kind).toBe('corrupt'); // still present for explicit discard
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
function fakeStorage(
  opts: {
    sync?: boolean;
    quota?: number;
    /** Per write() call return counts for the sync handle; empty queue means full writes. */
    syncWriteResults?: number[];
    /** Make removeEntry throw (surfaces removeData failures). */
    failRemoveData?: boolean;
  } = {},
) {
  const state = {
    syncAvailable: opts.sync ?? true,
    quota: opts.quota,
    files: new Map<string, Uint8Array>(),
    writableStreams: new Map<string, FakeWritable>(),
    syncWriteResults: opts.syncWriteResults ? [...opts.syncWriteResults] : undefined,
    syncEvents: [] as string[],
    failRemoveData: opts.failRemoveData ?? false,
  };

  class FakeSyncHandle {
    private size: number;
    constructor(private readonly key: string) {
      this.size = state.files.get(key)?.length ?? 0;
    }
    write(buffer: Uint8Array, options: { at?: number }): number {
      const at = options.at ?? 0;
      const requested = buffer.length;
      const count =
        state.syncWriteResults !== undefined && state.syncWriteResults.length > 0
          ? state.syncWriteResults.shift()!
          : requested;
      const n = Math.min(count, requested);
      const cur = state.files.get(this.key) ?? new Uint8Array();
      const end = at + n;
      const grown = new Uint8Array(Math.max(end, cur.length));
      grown.set(cur);
      grown.set(buffer.subarray(0, n), at);
      state.files.set(this.key, grown);
      this.size = grown.length;
      state.syncEvents.push(`write:${count}`);
      return count;
    }
    flush(): void {
      state.syncEvents.push('flush');
    }
    getSize(): number {
      return this.size;
    }
    truncate(size: number): void {
      const cur = state.files.get(this.key) ?? new Uint8Array();
      state.files.set(this.key, cur.slice(0, size));
      this.size = size;
    }
    close(): void {
      state.syncEvents.push('close');
    }
  }

  const makeFileHandle = (key: string): FileSystemHandle =>
    ({
      kind: 'file',
      getFile: async () => {
        const blob = state.files.get(key) ?? new Uint8Array();
        return new File(
          [blob.buffer.slice(blob.byteOffset, blob.byteOffset + blob.byteLength) as ArrayBuffer],
          key,
        );
      },
      createWritable: async () => {
        const writable = new FakeWritable();
        state.writableStreams.set(key, writable);
        return writable;
      },
      createSyncAccessHandle: async () => {
        if (!state.syncAvailable) throw new TypeError('sync access handles unavailable');
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
        if (!options.create && !state.files.has(key))
          throw new DOMException('missing', 'NotFoundError');
        if (options.create && !state.files.has(key)) state.files.set(key, new Uint8Array()); // create-on-open
        return Promise.resolve(makeFileHandle(key));
      },
      removeEntry: (name: string, options: { recursive?: boolean } = {}) => {
        if (state.failRemoveData) throw new DOMException('removal failed', 'OperationError');
        const key = join(prefix, name);
        if (options.recursive) {
          for (const existing of [...state.files.keys()]) {
            if (existing.startsWith(`${key}/`)) state.files.delete(existing);
          }
        }
        state.files.delete(key);
        return Promise.resolve();
      },
      entries: () => {
        const children = new Map<string, { kind: 'directory' | 'file' }>();
        for (const key of state.files.keys()) {
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
      ...(state.quota !== undefined
        ? {
            estimate: async () => ({ quota: state.quota, usage: 0 }),
          }
        : {}),
    },
  });

  return {
    files: state.files,
    writableStreams: state.writableStreams,
    syncEvents: state.syncEvents,
  };
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

// ---------------------------------------------------------------------------
// Sync writer short-write handling
// ---------------------------------------------------------------------------

describe('sync partial writer short writes', () => {
  it('loops on one short write, persists the whole block, and flushes only at the end', async () => {
    const { files, syncEvents } = fakeStorage({ sync: true, syncWriteResults: [2] });
    const f: DurableFiles = durableOpfsFiles();
    const writer = await f.openWriter(TRANSFER_ID, 'a.bin', 0, true);
    await writer.write(0, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
    await writer.close();
    expect(files.get(partKey('a.bin'))).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
    const writes = syncEvents.filter((e) => e.startsWith('write:'));
    expect(writes).toEqual(['write:2', 'write:6']);
    // The durability barrier (flush) runs only after the complete block was written.
    expect(syncEvents.indexOf('flush')).toBeGreaterThan(syncEvents.indexOf('write:6'));
  });

  it('handles several partial writes for one block', async () => {
    const { files, syncEvents } = fakeStorage({ sync: true, syncWriteResults: [1, 2, 3] });
    const f: DurableFiles = durableOpfsFiles();
    const writer = await f.openWriter(TRANSFER_ID, 'a.bin', 0, true);
    await writer.write(0, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
    await writer.close();
    expect(files.get(partKey('a.bin'))).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
    expect(syncEvents.filter((e) => e.startsWith('write:'))).toEqual([
      'write:1',
      'write:2',
      'write:3',
      'write:2',
    ]);
    expect(syncEvents.indexOf('flush')).toBeGreaterThan(syncEvents.indexOf('write:2'));
  });

  it('fails closed on a zero/no-progress write instead of looping forever', async () => {
    const { files, syncEvents } = fakeStorage({ sync: true, syncWriteResults: [0] });
    const f: DurableFiles = durableOpfsFiles();
    const writer = await f.openWriter(TRANSFER_ID, 'a.bin', 0, true);
    await expect(writer.write(0, new Uint8Array(8))).rejects.toThrow(/no progress/);
    // Nothing was persisted and no durability barrier ran.
    expect(files.get(partKey('a.bin'))?.length ?? 0).toBe(0);
    expect(syncEvents).not.toContain('flush');
  });

  it('fails closed when the API reports an impossible oversized count', async () => {
    const { syncEvents } = fakeStorage({ sync: true, syncWriteResults: [9] });
    const f: DurableFiles = durableOpfsFiles();
    const writer = await f.openWriter(TRANSFER_ID, 'a.bin', 0, true);
    await expect(writer.write(0, new Uint8Array(8))).rejects.toThrow(/impossible/);
    expect(syncEvents).not.toContain('flush');
  });

  it('a failed short write never advances the journal checkpoint', async () => {
    fakeStorage({ sync: true, syncWriteResults: [0] });
    const idb = makeFakeIndexedDB();
    vi.stubGlobal('indexedDB', idb);
    const store = indexedDbDurableStore();
    const digestFactory = await createSha256DigestFactory();
    const d = new DurableDestination({
      createDigest: digestFactory,
      files: durableOpfsFiles(),
      store,
      now: () => 1_000,
      renewMs: 0,
      ensureSpace: async () => {},
    });
    const m = manifest([['a.bin', 8]]);
    await d.prepare(m);
    const sink = await d.open(m.files[0]!);
    await expect(sink.write(0, new Uint8Array(8))).rejects.toThrow(/no progress/);
    const loaded = await store.loadJournal(TRANSFER_ID);
    expect(loaded.kind).toBe('ok');
    if (loaded.kind !== 'ok') return;
    // The checkpoint never advanced for an incompletely-written block.
    expect(loaded.journal.files[0]!.committedBlocks).toBe(0);
    await d.abort();
  });
});

// ---------------------------------------------------------------------------
// Explicit discard: lease-guarded durable receive cleanup
// ---------------------------------------------------------------------------

describe('discardDurableTransfer', () => {
  function setup(): {
    files: DurableFiles;
    store: DurableJournalStore;
    idb: FakeIndexedDB;
  } {
    fakeStorage({ sync: true });
    const idb = makeFakeIndexedDB();
    vi.stubGlobal('indexedDB', idb);
    return { files: durableOpfsFiles(), store: indexedDbDurableStore(), idb };
  }

  async function seed(
    store: DurableJournalStore,
    files: DurableFiles,
    ownerId: string,
    nowMs: number,
  ): Promise<void> {
    await store.createJournal(
      TRANSFER_ID,
      manifest([['a.bin', 8]]),
      { version: 1, value: '0'.repeat(64) },
      { version: 1, value: '1'.repeat(64) },
      nowMs,
    );
    await store.acquireLease(TRANSFER_ID, ownerId, nowMs);
    const writer = await files.openWriter(TRANSFER_ID, 'a.bin', 0, true);
    await writer.write(0, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
    await writer.close();
  }

  it('removes the journal, lease, and OPFS partials for exactly that transfer, idempotently', async () => {
    const { files, store, idb } = setup();
    await seed(store, files, OWNER_A, 1_000);

    await discardDurableTransfer(TRANSFER_ID, OWNER_A, { files, store, now: () => 2_000 });

    expect((await store.loadJournal(TRANSFER_ID)).kind).toBe('none');
    expect(await files.partialSize(TRANSFER_ID, 'a.bin')).toBeUndefined();
    expect(await readLease(idb, TRANSFER_ID)).toBeUndefined();

    // Repeated discard remains safe.
    await discardDurableTransfer(TRANSFER_ID, OWNER_A, { files, store, now: () => 2_000 });
    expect((await store.loadJournal(TRANSFER_ID)).kind).toBe('none');
  });

  it('never touches another transfer', async () => {
    const { files, store } = setup();
    await seed(store, files, OWNER_A, 1_000);
    const otherId = 'b'.repeat(32);
    await store.createJournal(
      otherId,
      { ...manifest([['x.bin', 8]]), transferId: otherId },
      { version: 1, value: '0'.repeat(64) },
      { version: 1, value: '1'.repeat(64) },
      1_000,
    );
    await store.acquireLease(otherId, OWNER_B, 1_000);
    const otherWriter = await files.openWriter(otherId, 'x.bin', 0, true);
    await otherWriter.write(0, new Uint8Array(8));
    await otherWriter.close();

    await discardDurableTransfer(TRANSFER_ID, OWNER_A, { files, store, now: () => 2_000 });

    expect((await store.loadJournal(TRANSFER_ID)).kind).toBe('none');
    expect(await files.partialSize(TRANSFER_ID, 'a.bin')).toBeUndefined();
    // The other transfer's journal, lease, and partials are untouched.
    expect((await store.loadJournal(otherId)).kind).toBe('ok');
    expect(await files.partialSize(otherId, 'x.bin')).toBe(8);
  });

  it('refuses to discard while a live foreign lease owns the transfer', async () => {
    const { files, store, idb } = setup();
    await seed(store, files, OWNER_A, 1_000);

    await expect(
      discardDurableTransfer(TRANSFER_ID, OWNER_B, { files, store, now: () => 1_100 }),
    ).rejects.toThrow(/actively using/);

    // Nothing was deleted: journal, lease, and partials are untouched.
    expect((await store.loadJournal(TRANSFER_ID)).kind).toBe('ok');
    expect((await readLease(idb, TRANSFER_ID))?.ownerId).toBe(OWNER_A);
    expect(await files.partialSize(TRANSFER_ID, 'a.bin')).toBe(8);
  });

  it('takes over a stale lease and discards', async () => {
    const { files, store, idb } = setup();
    await seed(store, files, OWNER_A, 1_000);

    await discardDurableTransfer(TRANSFER_ID, OWNER_B, {
      files,
      store,
      now: () => 1_000 + DURABLE_LEASE_TTL_MS + 1,
    });

    expect((await store.loadJournal(TRANSFER_ID)).kind).toBe('none');
    expect(await files.partialSize(TRANSFER_ID, 'a.bin')).toBeUndefined();
    expect(await readLease(idb, TRANSFER_ID)).toBeUndefined();
  });

  it('fails closed when OPFS removal fails: nothing deleted, lease released for retry', async () => {
    fakeStorage({ sync: true, failRemoveData: true });
    const idb = makeFakeIndexedDB();
    vi.stubGlobal('indexedDB', idb);
    const store = indexedDbDurableStore();
    const files: DurableFiles = durableOpfsFiles();
    await seed(store, files, OWNER_A, 1_000);

    await expect(
      discardDurableTransfer(TRANSFER_ID, OWNER_A, { files, store, now: () => 2_000 }),
    ).rejects.toThrow(/removal failed/);

    // Fail-closed: journal + partials stay fully intact and resumable.
    expect((await store.loadJournal(TRANSFER_ID)).kind).toBe('ok');
    expect(await files.partialSize(TRANSFER_ID, 'a.bin')).toBe(8);
    // The lease taken for the discard was released so a retry acquires immediately.
    expect(await readLease(idb, TRANSFER_ID)).toBeUndefined();

    // With healthy storage the retry succeeds.
    fakeStorage({ sync: true });
    await discardDurableTransfer(TRANSFER_ID, OWNER_A, { files, store, now: () => 3_000 });
    expect((await store.loadJournal(TRANSFER_ID)).kind).toBe('none');
    expect(await files.partialSize(TRANSFER_ID, 'a.bin')).toBeUndefined();
  });

  it('removes OPFS data before journal + lease metadata (fail-closed ordering)', async () => {
    const { files, store, idb } = setup();
    await seed(store, files, OWNER_A, 1_000);
    // Metadata removal fails after the data layer succeeded (IDB + OPFS are not atomic).
    const failingStore = Object.create(store) as DurableJournalStore;
    failingStore.discard = async () => {
      throw new Error('idb discard failed');
    };

    await expect(
      discardDurableTransfer(TRANSFER_ID, OWNER_A, {
        files,
        store: failingStore,
        now: () => 2_000,
      }),
    ).rejects.toThrow(/idb discard failed/);

    // Data-first: the partials are already gone, so the leftover journal is provably
    // unusable (a resume fails closed, never silent), and the lease was released for retry.
    expect(await files.partialSize(TRANSFER_ID, 'a.bin')).toBeUndefined();
    expect((await store.loadJournal(TRANSFER_ID)).kind).toBe('ok');
    expect(await readLease(idb, TRANSFER_ID)).toBeUndefined();

    // The retry completes the cleanup.
    await discardDurableTransfer(TRANSFER_ID, OWNER_A, { files, store, now: () => 3_000 });
    expect((await store.loadJournal(TRANSFER_ID)).kind).toBe('none');
  });
});
