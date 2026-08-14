/**
 * Durable browser receive storage (V13-PR03) — the browser twin of the CLI's
 * `<out>/.sendbeam` store (apps/cli/internal/transfer/durable.go), implementing the same
 * ADR 0004 contract over OPFS data + IndexedDB metadata:
 *
 *   OPFS:  sendbeam/durable/<transferId>/<rel>.part   (verified partial data)
 *   IDB:   sendbeam-durable → journals, leases        (transactional journal + lease)
 *
 * Everything the destination touches goes through the {@link DurableFiles} and
 * {@link DurableJournalStore} interfaces so the browser backend and deterministic test
 * fakes are interchangeable. The journal contract (schema, checksum, fingerprint, block
 * granularity) is `@sendbeam/protocol`'s journal module — never forked.
 *
 * The lease is the only new browser-specific primitive: an atomic IDB test-and-set record
 * (transferId → ownerId, expiresAt) that serializes concurrent tabs, survives reloads and
 * worker death via its TTL, and is renewed by journal commits plus a bounded timer.
 */

import {
  bytesToHex,
  commitBlocks as advanceJournal,
  decodeJournal,
  encodeJournal,
  newJournal,
  sha256,
  TransferError,
  utf8,
  type Digest,
  type DurableJournal,
  type JournalDigestCheckpoint,
  type JournalIdentity,
  type Manifest,
  type ResumeSecretEnvelope,
} from '@sendbeam/protocol';

/** OPFS root namespace for durable receive data. */
export const DURABLE_ROOT = 'sendbeam/durable';
/** IndexedDB database and store names for journal metadata + leases. */
export const DURABLE_DB = 'sendbeam-durable';
export const DURABLE_JOURNALS_STORE = 'journals';
export const DURABLE_LEASES_STORE = 'leases';
/** How long a lease survives without renewal; worker death recovers after this. */
export const DURABLE_LEASE_TTL_MS = 120_000;

/** The partial-data layer: verified block storage under the OPFS durable root. */
export interface DurableFiles {
  /** Resolve (and optionally create) the per-transfer data directory. */
  dataDir(transferId: string, create: boolean): Promise<FileSystemDirectoryHandle>;
  /** The OPFS key (path under the OPFS root) for one canonical manifest path. */
  partialKey(transferId: string, relPath: string): string;
  /**
   * Probe whether sync access handles are usable in this context (dedicated workers on
   * Chromium/Firefox). Deterministic: returns false when unavailable, never throws.
   */
  probeSync(transferId: string): Promise<boolean>;
  /**
   * Open a writer for one partial. When `committedBytes > 0` the partial must exist and be
   * at least that long (fail closed otherwise), and a stale tail beyond the checkpoint is
   * truncated away so unclaimed bytes are re-transferred, never trusted.
   */
  openWriter(
    transferId: string,
    relPath: string,
    committedBytes: number,
    sync: boolean,
  ): Promise<PartialWriter>;
  /** Size of one partial file, or undefined when absent. */
  partialSize(transferId: string, relPath: string): Promise<number | undefined>;
  /** Feed the first `length` bytes of a partial into `digest` in chunks (resume re-hash). */
  readPrefix(transferId: string, relPath: string, length: number, digest: Digest): Promise<void>;
  /** Visit every chunk of a partial in order (finalize ZIP assembly). */
  readPartialChunks(
    transferId: string,
    relPath: string,
    visit: (chunk: Uint8Array) => void | Promise<void>,
  ): Promise<void>;
  /** All canonical rel paths with a `.part` file present under the transfer dir. */
  listRelPaths(transferId: string): Promise<string[]>;
  /** Open a fresh output file inside the transfer dir (ZIP finalize). */
  openOutput(
    transferId: string,
    fileName: string,
  ): Promise<{ key: string; writable: WritableFileLike }>;
  /** Remove one partial file. */
  removePartial(transferId: string, relPath: string): Promise<void>;
  /** Remove the entire per-transfer data directory (idempotent). */
  removeData(transferId: string): Promise<void>;
}

/** One open partial file. Sync writers flush on every write; async writers flush on close. */
export interface PartialWriter {
  /** Persist one verified block at `offset`. Sync path flushes to disk before returning. */
  write(offset: number, bytes: Uint8Array): Promise<void>;
  /** Final flush + close. */
  close(): Promise<void>;
  /** Close without losing data — partials are resumable and never deleted here. */
  abort(): Promise<void>;
}

/** A FileSystemWritableFileStream-shaped writer (used by the async fallback and ZIP output). */
export interface WritableFileLike {
  write(data: { type: 'write'; position: number; data: Uint8Array }): Promise<void>;
  close(): Promise<void>;
  abort?(reason?: unknown): Promise<void>;
  truncate?(size: number): Promise<void>;
}

/** Result of an atomic lease acquisition. */
export type LeaseOutcome =
  { kind: 'acquired' } | { kind: 'renewed' } | { kind: 'contended' } | { kind: 'stale-taken' };

export interface LeaseRecord {
  transferId: string;
  ownerId: string;
  expiresAt: number;
}

/** Result of loading a journal: absent, valid, or corrupt (fail closed, nothing deleted). */
export type JournalLoad =
  { kind: 'none' } | { kind: 'ok'; journal: DurableJournal } | { kind: 'corrupt'; error: string };

/** Transactional journal + lease metadata store. All writes are atomic IDB transactions. */
export interface DurableJournalStore {
  loadJournal(transferId: string): Promise<JournalLoad>;
  /** Create and persist a fresh zero-checkpoint journal (validates + encodes). */
  createJournal(
    transferId: string,
    manifest: Manifest,
    source: JournalIdentity,
    destination: JournalIdentity,
    nowMs: number,
  ): Promise<DurableJournal>;
  /**
   * Advance one file's checkpoint in a single transaction that also renews the lease.
   * The caller must already hold the lease; a lost/foreign lease aborts the transaction and
   * rejects, so two tabs can never both advance the same journal. `digestCheckpoint`
   * (V13-PR05), when given, is the serialized digest state covering exactly these blocks and
   * is persisted atomically with the checkpoint.
   */
  commitBlocks(
    journal: DurableJournal,
    fileIdx: number,
    blocks: number,
    nowMs: number,
    ownerId: string,
    digestCheckpoint?: JournalDigestCheckpoint,
  ): Promise<DurableJournal>;
  /**
   * Lease-guarded resume-secret attach (V13-PR07): add the transfer-scoped credential to
   * the journal ONLY while the caller still owns the lease, in ONE readwrite transaction
   * over journals + leases. It re-loads the CURRENT journal (never blindly overwrites a
   * stale snapshot), preserves every committed block/digest checkpoint, adds the secret
   * only if absent, preserves an existing secret exactly, renews the lease, and fails
   * closed if lease ownership was lost (another tab took over). This is deliberately the
   * ONLY way a resume credential enters a journal — no generic unguarded journal write
   * exists.
   */
  attachResumeSecret(
    transferId: string,
    envelope: ResumeSecretEnvelope,
    ownerId: string,
    nowMs: number,
  ): Promise<DurableJournal>;
  /** Atomic test-and-set acquire with TTL; stale records are taken over. */
  acquireLease(transferId: string, ownerId: string, nowMs: number): Promise<LeaseOutcome>;
  renewLease(transferId: string, ownerId: string, nowMs: number): Promise<void>;
  releaseLease(transferId: string, ownerId: string): Promise<void>;
  /** Remove the journal and lease for one transfer id, idempotently. */
  discard(transferId: string): Promise<void>;
}

/**
 * The opaque destination claim for browser journals: the OPFS storage is origin-scoped, so
 * this binds a journal to the browser storage area (mirrors the CLI's destination-location
 * identity). The origin is included for defense in depth across deployments.
 */
export async function webDestinationIdentity(origin: string): Promise<JournalIdentity> {
  const sum = await sha256(utf8(`sendbeam/destination-location\x00web:opfs:${origin}`));
  return { version: 1, value: bytesToHex(sum) };
}

// ---------------------------------------------------------------------------
// IndexedDB backend
// ---------------------------------------------------------------------------

interface IDBRequestLike<T = unknown> {
  result: T;
  error: DOMException | null;
  onsuccess: ((ev: Event) => void) | null;
  onerror: ((ev: Event) => void) | null;
}
interface IDBObjectStoreLike {
  get(key: string): IDBRequestLike<unknown>;
  put(value: unknown, key: string): IDBRequestLike;
  delete(key: string): IDBRequestLike;
  getAll(): IDBRequestLike<unknown[]>;
}
interface IDBTransactionLike {
  objectStore(name: string): IDBObjectStoreLike;
  abort(): void;
  oncomplete: ((ev: Event) => void) | null;
  onerror: ((ev: Event) => void) | null;
  onabort: ((ev: Event) => void) | null;
}
interface IDBDatabaseLike {
  objectStoreNames: { contains(name: string): boolean };
  transaction(storeNames: string[], mode: 'readonly' | 'readwrite'): IDBTransactionLike;
  close(): void;
}

/** Wrap one IDB request as a promise. */
function requestResult(r: IDBRequestLike): Promise<unknown> {
  return new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error ?? new Error('indexeddb request failed'));
  });
}

/** Resolve when a transaction completes; rejects on error or abort. */
function transactionDone(tx: IDBTransactionLike): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(new Error('indexeddb transaction failed'));
    tx.onabort = () => reject(new Error('indexeddb transaction aborted'));
  });
}

/** The browser journal/lease store over IndexedDB. */
export function indexedDbDurableStore(): DurableJournalStore {
  return new IndexedDbDurableStore();
}

class IndexedDbDurableStore implements DurableJournalStore {
  private dbPromise: Promise<IDBDatabaseLike> | undefined;

  private db(): Promise<IDBDatabaseLike> {
    if (!this.dbPromise) {
      this.dbPromise = new Promise((resolve, reject) => {
        const idb = (globalThis as { indexedDB?: IDBFactory }).indexedDB;
        if (!idb) {
          reject(new Error('IndexedDB is unavailable in this browser'));
          return;
        }
        const req = idb.open(DURABLE_DB, 1);
        req.onupgradeneeded = () => {
          const db = req.result;
          if (!db.objectStoreNames.contains(DURABLE_JOURNALS_STORE)) {
            db.createObjectStore(DURABLE_JOURNALS_STORE);
          }
          if (!db.objectStoreNames.contains(DURABLE_LEASES_STORE)) {
            db.createObjectStore(DURABLE_LEASES_STORE);
          }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error ?? new Error('open sendbeam-durable failed'));
      });
    }
    return this.dbPromise;
  }

  async loadJournal(transferId: string): Promise<JournalLoad> {
    const db = await this.db();
    const tx = db.transaction([DURABLE_JOURNALS_STORE], 'readonly');
    const value = await requestResult(tx.objectStore(DURABLE_JOURNALS_STORE).get(transferId));
    await transactionDone(tx);
    if (value === undefined) return { kind: 'none' };
    try {
      const bytes =
        value instanceof Uint8Array
          ? value
          : new Uint8Array((value as { buffer?: ArrayBuffer }).buffer ?? (value as ArrayBuffer));
      return { kind: 'ok', journal: await decodeJournal(bytes) };
    } catch (e) {
      return { kind: 'corrupt', error: e instanceof Error ? e.message : String(e) };
    }
  }

  async createJournal(
    transferId: string,
    manifest: Manifest,
    source: JournalIdentity,
    destination: JournalIdentity,
    nowMs: number,
  ): Promise<DurableJournal> {
    const journal = await newJournal(transferId, manifest, source, destination, nowMs);
    await this.putJournal(journal);
    return journal;
  }

  async commitBlocks(
    journal: DurableJournal,
    fileIdx: number,
    blocks: number,
    nowMs: number,
    ownerId: string,
    digestCheckpoint?: JournalDigestCheckpoint,
  ): Promise<DurableJournal> {
    const next = advanceJournal(journal, fileIdx, blocks, nowMs, digestCheckpoint);
    const encoded = await encodeJournal(next);
    const db = await this.db();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction([DURABLE_JOURNALS_STORE, DURABLE_LEASES_STORE], 'readwrite');
      const journals = tx.objectStore(DURABLE_JOURNALS_STORE);
      const leases = tx.objectStore(DURABLE_LEASES_STORE);
      const leaseReq = leases.get(next.transferId);
      leaseReq.onsuccess = () => {
        const lease = leaseReq.result as LeaseRecord | undefined;
        if (!lease || lease.ownerId !== ownerId) {
          // The lease is gone or owned by another receiver (expired + taken over, or the
          // journal was discarded): never advance a journal we no longer own.
          tx.abort();
          reject(
            new TransferError(
              'sink_error',
              'durable lease lost; another receiver owns this transfer — stop the duplicate receive',
            ),
          );
          return;
        }
        journals.put(encoded, next.transferId);
        leases.put(
          { transferId: next.transferId, ownerId, expiresAt: nowMs + DURABLE_LEASE_TTL_MS },
          next.transferId,
        );
      };
      leaseReq.onerror = () => {
        tx.abort();
        reject(new Error('durable lease read failed'));
      };
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(new Error('durable journal commit failed'));
      tx.onabort = () => reject(new Error('durable journal commit aborted'));
    });
    return next;
  }

  async attachResumeSecret(
    transferId: string,
    envelope: ResumeSecretEnvelope,
    ownerId: string,
    nowMs: number,
  ): Promise<DurableJournal> {
    const db = await this.db();
    // Pass 1 (readonly): load + validate the CURRENT journal (never blindly overwrite a
    // stale in-memory snapshot) and confirm the caller currently owns the lease. Async
    // decode/encode must happen OUTSIDE any IndexedDB transaction — a real IDB transaction
    // auto-commits when the event loop yields with no pending requests. The completion
    // promise is created BEFORE issuing the requests so the oncomplete handler is
    // registered before the transaction can complete.
    let current: DurableJournal;
    const loadTx = db.transaction([DURABLE_JOURNALS_STORE, DURABLE_LEASES_STORE], 'readonly');
    const loadDone = transactionDone(loadTx);
    const loadLeaseReq = loadTx.objectStore(DURABLE_LEASES_STORE).get(transferId);
    const loadJournalReq = loadTx.objectStore(DURABLE_JOURNALS_STORE).get(transferId);
    const [loadLease, storedJournal] = await Promise.all([
      requestResult(loadLeaseReq),
      requestResult(loadJournalReq),
    ]);
    await loadDone;
    const lease = loadLease as LeaseRecord | undefined;
    if (!lease || lease.ownerId !== ownerId) {
      throw new TransferError(
        'sink_error',
        'durable lease lost; another receiver owns this transfer — cannot attach the resume credential',
      );
    }
    try {
      const bytes =
        storedJournal instanceof Uint8Array
          ? storedJournal
          : new Uint8Array(
              (storedJournal as { buffer?: ArrayBuffer }).buffer ?? (storedJournal as ArrayBuffer),
            );
      current = await decodeJournal(bytes);
    } catch {
      throw new TransferError(
        'sink_error',
        `durable journal ${transferId} is unusable; cannot attach the resume credential`,
      );
    }
    if (current.transferId !== transferId) {
      throw new TransferError('sink_error', 'durable journal key mismatch');
    }
    // Preserve every committed block/digest checkpoint; add the credential only if absent;
    // preserve an existing credential exactly.
    const next: DurableJournal = {
      ...current,
      resumeSecret: current.resumeSecret ?? envelope,
    };
    const encoded = await encodeJournal(next);

    // Pass 2 (readwrite, one transaction over journals + leases): re-verify lease ownership
    // AT WRITE TIME and write journal + lease renewal atomically. If the lease was taken
    // over between the passes, the write aborts and the new owner's progress is untouched.
    return new Promise<DurableJournal>((resolve, reject) => {
      const tx = db.transaction([DURABLE_JOURNALS_STORE, DURABLE_LEASES_STORE], 'readwrite');
      const journals = tx.objectStore(DURABLE_JOURNALS_STORE);
      const leases = tx.objectStore(DURABLE_LEASES_STORE);
      const leaseReq = leases.get(transferId);
      leaseReq.onsuccess = () => {
        const leaseNow = leaseReq.result as LeaseRecord | undefined;
        if (!leaseNow || leaseNow.ownerId !== ownerId) {
          tx.abort();
          reject(
            new TransferError(
              'sink_error',
              'durable lease lost; another receiver owns this transfer — cannot attach the resume credential',
            ),
          );
          return;
        }
        journals.put(encoded, transferId);
        leases.put({ transferId, ownerId, expiresAt: nowMs + DURABLE_LEASE_TTL_MS }, transferId);
        tx.oncomplete = () => resolve(next);
      };
      leaseReq.onerror = () => {
        tx.abort();
        reject(new Error('durable lease read failed'));
      };
      tx.onerror = () => reject(new Error('durable journal attach failed'));
      tx.onabort = () => reject(new Error('durable journal attach aborted'));
    });
  }

  async acquireLease(transferId: string, ownerId: string, nowMs: number): Promise<LeaseOutcome> {
    const db = await this.db();
    return new Promise<LeaseOutcome>((resolve, reject) => {
      const tx = db.transaction([DURABLE_LEASES_STORE], 'readwrite');
      const leases = tx.objectStore(DURABLE_LEASES_STORE);
      let outcome: LeaseOutcome = { kind: 'contended' };
      const req = leases.get(transferId);
      req.onsuccess = () => {
        const lease = req.result as LeaseRecord | undefined;
        const expiresAt = nowMs + DURABLE_LEASE_TTL_MS;
        if (!lease) {
          leases.put({ transferId, ownerId, expiresAt }, transferId);
          outcome = { kind: 'acquired' };
        } else if (lease.expiresAt <= nowMs) {
          leases.put({ transferId, ownerId, expiresAt }, transferId);
          outcome = { kind: 'stale-taken' };
        } else if (lease.ownerId === ownerId) {
          leases.put({ transferId, ownerId, expiresAt }, transferId);
          outcome = { kind: 'renewed' };
        }
      };
      req.onerror = () => reject(new Error('durable lease acquire failed'));
      tx.oncomplete = () => resolve(outcome);
      tx.onerror = () => reject(new Error('durable lease acquire failed'));
      tx.onabort = () => reject(new Error('durable lease acquire aborted'));
    });
  }

  async renewLease(transferId: string, ownerId: string, nowMs: number): Promise<void> {
    const db = await this.db();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction([DURABLE_LEASES_STORE], 'readwrite');
      const leases = tx.objectStore(DURABLE_LEASES_STORE);
      const req = leases.get(transferId);
      req.onsuccess = () => {
        const lease = req.result as LeaseRecord | undefined;
        if (lease && lease.ownerId === ownerId) {
          leases.put({ transferId, ownerId, expiresAt: nowMs + DURABLE_LEASE_TTL_MS }, transferId);
        }
      };
      req.onerror = () => reject(new Error('durable lease renew failed'));
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(new Error('durable lease renew failed'));
    });
  }

  async releaseLease(transferId: string, ownerId: string): Promise<void> {
    const db = await this.db();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction([DURABLE_LEASES_STORE], 'readwrite');
      const leases = tx.objectStore(DURABLE_LEASES_STORE);
      const req = leases.get(transferId);
      req.onsuccess = () => {
        const lease = req.result as LeaseRecord | undefined;
        if (lease && lease.ownerId === ownerId) leases.delete(transferId);
      };
      req.onerror = () => reject(new Error('durable lease release failed'));
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(new Error('durable lease release failed'));
    });
  }

  async discard(transferId: string): Promise<void> {
    const db = await this.db();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction([DURABLE_JOURNALS_STORE, DURABLE_LEASES_STORE], 'readwrite');
      tx.objectStore(DURABLE_JOURNALS_STORE).delete(transferId);
      tx.objectStore(DURABLE_LEASES_STORE).delete(transferId);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(new Error('durable discard failed'));
      tx.onabort = () => reject(new Error('durable discard aborted'));
    });
  }

  private async putJournal(journal: DurableJournal): Promise<void> {
    const encoded = await encodeJournal(journal);
    const db = await this.db();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction([DURABLE_JOURNALS_STORE], 'readwrite');
      tx.objectStore(DURABLE_JOURNALS_STORE).put(encoded, journal.transferId);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(new Error('durable journal write failed'));
      tx.onabort = () => reject(new Error('durable journal write aborted'));
    });
  }
}

// ---------------------------------------------------------------------------
// OPFS backend
// ---------------------------------------------------------------------------

class SyncPartialWriter implements PartialWriter {
  constructor(private readonly handle: FileSystemSyncAccessHandle) {}
  async write(offset: number, bytes: Uint8Array): Promise<void> {
    // A sync access handle may persist only part of a buffer per call (short write). Loop
    // on the returned byte count until the whole verified block is on disk, failing closed
    // on zero/no-progress or impossible results instead of risking a torn checkpoint. The
    // durability barrier (flush) runs only after the complete block has been written.
    let written = 0;
    while (written < bytes.length) {
      const count = this.handle.write(bytes.subarray(written), { at: offset + written });
      if (count <= 0) {
        throw new TransferError(
          'sink_error',
          'sync write made no progress; failing closed rather than checkpointing a torn block',
        );
      }
      if (count > bytes.length - written) {
        throw new TransferError(
          'sink_error',
          'sync write reported an impossible byte count; failing closed',
        );
      }
      written += count;
    }
    this.handle.flush();
  }
  async close(): Promise<void> {
    // flush() before close() so the final bytes are durable even if close does not flush.
    this.handle.flush();
    this.handle.close();
  }
  async abort(): Promise<void> {
    this.handle.close();
  }
}

class AsyncPartialWriter implements PartialWriter {
  constructor(private readonly writable: WritableFileLike) {}
  async write(offset: number, bytes: Uint8Array): Promise<void> {
    await this.writable.write({ type: 'write', position: offset, data: bytes });
  }
  async close(): Promise<void> {
    await this.writable.close();
  }
  async abort(): Promise<void> {
    if (this.writable.abort) await this.writable.abort();
    else await this.writable.close();
  }
}

/** The browser OPFS partial-data layer. */
export function durableOpfsFiles(): DurableFiles {
  return new OpfsDurableFiles();
}

class OpfsDurableFiles implements DurableFiles {
  private async root(): Promise<FileSystemDirectoryHandle> {
    const storage = (navigator as Navigator & { storage?: StorageManager }).storage;
    if (!storage || typeof storage.getDirectory !== 'function') {
      throw new TransferError('sink_error', 'Origin Private File System is unavailable');
    }
    return storage.getDirectory();
  }

  async dataDir(transferId: string, create: boolean): Promise<FileSystemDirectoryHandle> {
    const root = await this.root();
    let dir = await root.getDirectoryHandle(DURABLE_ROOT.split('/')[0]!, { create });
    for (const part of DURABLE_ROOT.split('/').slice(1)) {
      dir = await dir.getDirectoryHandle(part, { create });
    }
    return dir.getDirectoryHandle(transferId, { create });
  }

  private async partialHandle(
    transferId: string,
    relPath: string,
    create: boolean,
  ): Promise<FileSystemFileHandle> {
    const dir = await this.dataDir(transferId, create);
    const parts = relPath.split('/');
    let current = dir;
    for (const part of parts.slice(0, -1)) {
      current = await current.getDirectoryHandle(part, { create });
    }
    return current.getFileHandle(`${parts.at(-1)}.part`, { create });
  }

  partialKey(transferId: string, relPath: string): string {
    return `${DURABLE_ROOT}/${transferId}/${relPath}.part`;
  }

  async probeSync(transferId: string): Promise<boolean> {
    try {
      const dir = await this.dataDir(transferId, true);
      const handle = await dir.getFileHandle('__sync-probe', { create: true });
      const sync = await handle.createSyncAccessHandle();
      sync.close();
      await dir.removeEntry('__sync-probe').catch(() => {});
      return true;
    } catch {
      return false;
    }
  }

  async openWriter(
    transferId: string,
    relPath: string,
    committedBytes: number,
    sync: boolean,
  ): Promise<PartialWriter> {
    const handle = await this.partialHandle(transferId, relPath, true);
    if (sync) {
      let syncHandle: FileSystemSyncAccessHandle | undefined;
      try {
        syncHandle = await handle.createSyncAccessHandle();
        const size = syncHandle.getSize();
        if (size < committedBytes) {
          throw new TransferError(
            'sink_error',
            `partial ${relPath} truncated (have ${size} bytes, checkpoint claims ${committedBytes})`,
          );
        }
        if (size > committedBytes) syncHandle.truncate(committedBytes);
        return new SyncPartialWriter(syncHandle);
      } catch (e) {
        try {
          syncHandle?.close();
        } catch {
          // best effort
        }
        throw e;
      }
    }
    const file = await handle.getFile().catch(() => undefined);
    const size = file?.size ?? 0;
    if (size < committedBytes) {
      throw new TransferError(
        'sink_error',
        `partial ${relPath} truncated (have ${size} bytes, checkpoint claims ${committedBytes})`,
      );
    }
    const writable = (await handle.createWritable({
      keepExistingData: size > 0,
    })) as WritableFileLike;
    if (size > committedBytes && typeof writable.truncate === 'function') {
      await writable.truncate(committedBytes);
    }
    return new AsyncPartialWriter(writable);
  }

  async partialSize(transferId: string, relPath: string): Promise<number | undefined> {
    try {
      const handle = await this.partialHandle(transferId, relPath, false);
      const file = await handle.getFile();
      return file.size;
    } catch {
      return undefined;
    }
  }

  private async readStream(
    transferId: string,
    relPath: string,
    visit: (chunk: Uint8Array) => void | Promise<void>,
  ): Promise<void> {
    const handle = await this.partialHandle(transferId, relPath, false);
    const file = await handle.getFile();
    const reader = file.stream().getReader();
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) return;
        await visit(value);
      }
    } finally {
      reader.releaseLock();
    }
  }

  async readPrefix(
    transferId: string,
    relPath: string,
    length: number,
    digest: Digest,
  ): Promise<void> {
    let remaining = length;
    await this.readStream(transferId, relPath, (chunk) => {
      if (remaining <= 0) return;
      const take = chunk.subarray(0, Math.min(chunk.length, remaining));
      digest.update(take);
      remaining -= take.length;
    });
    if (remaining > 0) {
      throw new TransferError('sink_error', `partial ${relPath} shorter than its checkpoint`);
    }
  }

  async readPartialChunks(
    transferId: string,
    relPath: string,
    visit: (chunk: Uint8Array) => void | Promise<void>,
  ): Promise<void> {
    await this.readStream(transferId, relPath, visit);
  }

  async listRelPaths(transferId: string): Promise<string[]> {
    const out: string[] = [];
    const dir = await this.dataDir(transferId, false);
    await walk(dir, '', out);
    return out.sort();
  }

  async openOutput(
    transferId: string,
    fileName: string,
  ): Promise<{ key: string; writable: WritableFileLike }> {
    const dir = await this.dataDir(transferId, true);
    const handle = await dir.getFileHandle(fileName, { create: true });
    const writable = (await handle.createWritable({
      keepExistingData: false,
    })) as WritableFileLike;
    return { key: `${DURABLE_ROOT}/${transferId}/${fileName}`, writable };
  }

  async removePartial(transferId: string, relPath: string): Promise<void> {
    const dir = await this.dataDir(transferId, false);
    const parts = relPath.split('/');
    let current = dir;
    for (const part of parts.slice(0, -1)) {
      current = await current.getDirectoryHandle(part, { create: false });
    }
    await current.removeEntry(`${parts.at(-1)}.part`).catch(() => {});
  }

  async removeData(transferId: string): Promise<void> {
    let dir: FileSystemDirectoryHandle;
    try {
      const root = await this.root();
      dir = await root.getDirectoryHandle(DURABLE_ROOT.split('/')[0]!, { create: false });
      for (const part of DURABLE_ROOT.split('/').slice(1)) {
        dir = await dir.getDirectoryHandle(part, { create: false });
      }
    } catch (e) {
      // An absent durable namespace means there is nothing to remove; any other failure
      // (storage unavailable, permissions, quota) must surface so discard never reports
      // success while durable bytes may still exist.
      if (e instanceof DOMException && e.name === 'NotFoundError') return;
      throw e;
    }
    try {
      await dir.removeEntry(transferId, { recursive: true });
    } catch (e) {
      // Idempotent repeat: the per-transfer directory is already gone.
      if (e instanceof DOMException && e.name === 'NotFoundError') return;
      throw e;
    }
  }
}

// ---------------------------------------------------------------------------
// Explicit discard: durable receive cleanup
// ---------------------------------------------------------------------------

export interface DurableCleanupDeps {
  files: DurableFiles;
  store: DurableJournalStore;
  /** Injectable clock (unix ms); defaults to Date.now (tests use a fixed clock). */
  now?(): number;
}

/**
 * Explicitly discard one transfer's durable receive state — journal, lease, and every OPFS
 * partial/output under its per-transfer namespace — idempotently and never touching any other
 * transfer.
 *
 * Ordering (data first, metadata last) is deliberate because IDB + OPFS cannot be one atomic
 * transaction; it is chosen to be fail-closed and retryable:
 *
 *  1. Acquire the transfer's lease first (test-and-set). A live lease owned by another
 *     receiver means the transfer is actively being received there, so the discard is refused
 *     rather than deleting state underneath it — a stale failure page can never destroy a live
 *     receiver. An absent, stale, or self-owned lease lets the discard proceed and guarantees
 *     exclusive ownership for the rest of the cleanup, so no receiver can start between steps.
 *  2. Remove the OPFS data while the lease is held. Because we own the lease, this cannot
 *     collide with a live receive, and a failure here aborts with the journal + partials still
 *     fully intact and resumable.
 *  3. Remove the journal + lease metadata last, only after the backing data is provably gone —
 *     a journal never survives without its data. If metadata removal fails, the journal remains
 *     but is provably unusable (partials are gone) and a repeat of the discard is safe.
 *
 * On any failure the lease taken for the discard is released so a retry can acquire
 * immediately; no state is deleted on a failure path and no success is reported unless both the
 * data and metadata are actually gone.
 */
export async function discardDurableTransfer(
  transferId: string,
  ownerId: string,
  deps: DurableCleanupDeps,
): Promise<void> {
  if (transferId === '') {
    throw new TransferError('sink_error', 'refusing to discard an empty transfer id');
  }
  const now = deps.now ?? (() => Date.now());
  const outcome = await deps.store.acquireLease(transferId, ownerId, now());
  if (outcome.kind === 'contended') {
    throw new TransferError(
      'sink_error',
      'another receiver is actively using this transfer; refusing to discard underneath it',
    );
  }
  try {
    await deps.files.removeData(transferId);
    await deps.store.discard(transferId);
  } catch (e) {
    await deps.store.releaseLease(transferId, ownerId).catch(() => {});
    throw e;
  }
}

async function walk(dir: FileSystemDirectoryHandle, prefix: string, out: string[]): Promise<void> {
  for await (const [name, handle] of dir.entries()) {
    const rel = prefix === '' ? name : `${prefix}/${name}`;
    if (handle.kind === 'directory') {
      await walk(handle as FileSystemDirectoryHandle, rel, out);
    } else if (name.endsWith('.part')) {
      out.push(rel.slice(0, -'.part'.length));
    }
  }
}
