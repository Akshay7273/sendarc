/**
 * Web sender metadata (V13-PR04) — the browser twin of the CLI's sender store
 * (apps/cli/internal/transfer/sender_state.go), implementing the same contract over
 * IndexedDB: a per-transfer record carrying the stable transfer id and the canonical
 * manifest fingerprint is durable BEFORE the manifest frame goes out (via the worker's
 * `onManifest` hook), so an interrupted send can be reopened and verified against the
 * exact source before the id is re-advertised.
 *
 * The record is stored as a structured-clone object (key = transferId) because the
 * reattachment claim may carry a native {@link FileSystemHandle}, which cannot be
 * JSON-encoded but survives both postMessage and IndexedDB structured clone. Fail-closed
 * integrity comes from a strict shape validation plus a SHA-256 checksum over the
 * canonical JSON of every JSON-safe field (the handle itself is opaque and excluded;
 * a stale/revoked handle fails at reattachment time, falling back to reselection).
 *
 * Store contract: load/put/remove one record per transferId; list() surfaces corrupt
 * records (never deletes, never treats them as absent) so the UI can offer Forget.
 */

import {
  bytesToHex,
  manifestFingerprint,
  PROTOCOL_VERSION,
  sha256,
  TransferError,
  utf8,
  type Manifest,
} from '@sendbeam/protocol';

/** IndexedDB database and store names for sender metadata. */
export const SENDER_DB = 'sendbeam-sender';
export const SENDER_RECORDS_STORE = 'records';

/** The per-transfer metadata schema this build persists and accepts. */
export const SENDER_SCHEMA_VERSION = 1 as const;

/** One file of the interrupted send, mirroring the CLI's SenderFileState fields. */
export interface SenderFileState {
  name: string;
  size: number;
  mime: string;
  lastModified: number;
}

/**
 * How a restart locates the original source. `reselection` (a plain picker selection)
 * needs the user to re-pick the source; `handle` carries the persisted File System Access
 * handle so the source can be reopened directly.
 */
export type SenderReattachment =
  | { kind: 'reselection' }
  | { kind: 'handle'; handleKind: 'file' | 'directory'; handle: FileSystemHandle };

/**
 * Sender metadata for one transfer id. The checksum is the SHA-256 (hex) of the canonical
 * JSON core (everything except `checksum` and the opaque `reattachment.handle` object).
 */
export interface SenderRecord {
  schemaVersion: 1;
  transferId: string;
  /** Canonical SHA-256 (hex) of the validated manifest — the identity to re-verify. */
  manifestFingerprint: string;
  /** Wire-protocol version the transfer ran under (mirrors the CLI + journal). */
  protocolVersion: string;
  createdAt: number;
  updatedAt: number;
  files: SenderFileState[];
  reattachment: SenderReattachment;
  checksum: string;
}

/** Result of loading one record: absent, valid, or corrupt (fail closed, nothing deleted). */
export type SenderRecordLoad =
  | { kind: 'none' }
  | { kind: 'ok'; record: SenderRecord }
  | { kind: 'corrupt'; transferId: string; error: string };

/** What {@link SenderRecordStore.list} yields: every persisted entry, never `none`. */
export type SenderRecordListEntry =
  | { kind: 'ok'; transferId: string; record: SenderRecord }
  | { kind: 'corrupt'; transferId: string; error: string };

/** Sender metadata store. All writes are atomic IDB transactions. */
export interface SenderRecordStore {
  load(transferId: string): Promise<SenderRecordLoad>;
  /** Every persisted record, with corrupt entries surfaced (never thrown, never deleted). */
  list(): Promise<SenderRecordListEntry[]>;
  /** Persist a validated record, replacing any prior record for the same transfer id. */
  put(record: SenderRecord): Promise<void>;
  /** Remove one record, idempotently. */
  remove(transferId: string): Promise<void>;
}

/** The JSON-safe core of a record — the exact bytes the checksum covers. */
function canonicalCore(record: SenderRecord): string {
  const core = {
    schemaVersion: record.schemaVersion,
    transferId: record.transferId,
    manifestFingerprint: record.manifestFingerprint,
    protocolVersion: record.protocolVersion,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    files: record.files.map((f) => ({
      name: f.name,
      size: f.size,
      mime: f.mime,
      lastModified: f.lastModified,
    })),
    reattachment:
      record.reattachment.kind === 'handle'
        ? { kind: 'handle', handleKind: record.reattachment.handleKind }
        : { kind: 'reselection' },
  };
  return JSON.stringify(core);
}

/** Compute the record checksum over the canonical JSON core (handle excluded, kind included). */
export async function senderRecordChecksum(record: SenderRecord): Promise<string> {
  return bytesToHex(await sha256(utf8(canonicalCore(record))));
}

function isLowerHex(value: unknown, length: number): value is string {
  return typeof value === 'string' && value.length === length && /^[0-9a-f]+$/.test(value);
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0;
}

function exactKeys(value: unknown, keys: readonly string[]): boolean {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const actual = Object.keys(value);
  if (actual.length !== keys.length) return false;
  for (const key of keys) if (!(key in value)) return false;
  return true;
}

/**
 * Strict fail-closed validation: exact schema version, exact key sets at every level,
 * field formats, and a self-verifying checksum. Throws on any deviation.
 */
export async function validateSenderRecord(record: unknown): Promise<SenderRecord> {
  if (
    !exactKeys(record, [
      'schemaVersion',
      'transferId',
      'manifestFingerprint',
      'protocolVersion',
      'createdAt',
      'updatedAt',
      'files',
      'reattachment',
      'checksum',
    ])
  ) {
    throw new Error('sender record: unexpected or missing fields');
  }
  const r = record as SenderRecord;
  if (r.schemaVersion !== SENDER_SCHEMA_VERSION) {
    throw new Error(`sender record: unsupported schema version ${String(r.schemaVersion)}`);
  }
  if (!isLowerHex(r.transferId, 32)) {
    throw new Error('sender record: transferId must be 32 lowercase hex characters');
  }
  if (!isLowerHex(r.manifestFingerprint, 64)) {
    throw new Error('sender record: manifestFingerprint must be 64 lowercase hex characters');
  }
  if (typeof r.protocolVersion !== 'string' || r.protocolVersion === '') {
    throw new Error('sender record: invalid protocolVersion');
  }
  if (r.protocolVersion !== PROTOCOL_VERSION) {
    throw new Error(`sender record: unsupported protocol version ${r.protocolVersion}`);
  }
  if (!isFiniteNumber(r.createdAt) || !isFiniteNumber(r.updatedAt)) {
    throw new Error('sender record: invalid timestamp');
  }
  if (!Array.isArray(r.files) || r.files.length === 0) {
    throw new Error('sender record: files must be a non-empty array');
  }
  for (const [idx, f] of r.files.entries()) {
    if (!exactKeys(f, ['name', 'size', 'mime', 'lastModified'])) {
      throw new Error(`sender record: file ${idx} has unexpected or missing fields`);
    }
    if (typeof f.name !== 'string' || f.name === '') {
      throw new Error(`sender record: file ${idx} name must be a non-empty string`);
    }
    if (!Number.isInteger(f.size) || f.size < 0) {
      throw new Error(`sender record: file ${idx} size must be a non-negative integer`);
    }
    if (typeof f.mime !== 'string') {
      throw new Error(`sender record: file ${idx} mime must be a string`);
    }
    if (!isFiniteNumber(f.lastModified)) {
      throw new Error(`sender record: file ${idx} lastModified must be a non-negative number`);
    }
  }
  if (r.reattachment.kind === 'reselection') {
    if (!exactKeys(r.reattachment, ['kind'])) {
      throw new Error('sender record: reselection reattachment has unexpected fields');
    }
  } else if (r.reattachment.kind === 'handle') {
    if (!exactKeys(r.reattachment, ['kind', 'handleKind', 'handle'])) {
      throw new Error('sender record: handle reattachment has unexpected or missing fields');
    }
    if (r.reattachment.handleKind !== 'file' && r.reattachment.handleKind !== 'directory') {
      throw new Error('sender record: unknown handle kind');
    }
    if (r.reattachment.handle === undefined || r.reattachment.handle === null) {
      throw new Error('sender record: handle reattachment must carry a handle');
    }
  } else {
    throw new Error('sender record: unknown reattachment kind');
  }
  if (!isLowerHex(r.checksum, 64)) {
    throw new Error('sender record: checksum must be 64 lowercase hex characters');
  }
  const recomputed = await senderRecordChecksum(r);
  if (recomputed !== r.checksum) {
    throw new Error('sender record: checksum mismatch');
  }
  return r;
}

/**
 * Build a fresh schema-v1 record for a validated manifest, persisting the canonical
 * source identity before the manifest frame is advertised. `nowMs` is injectable so
 * tests are deterministic.
 */
export async function newSenderRecord(
  manifest: Manifest,
  reattachment: SenderReattachment,
  nowMs: number,
): Promise<SenderRecord> {
  if (manifest.transferId === undefined) {
    throw new Error('sender record: a transfer id is required');
  }
  const record: SenderRecord = {
    schemaVersion: SENDER_SCHEMA_VERSION,
    transferId: manifest.transferId,
    manifestFingerprint: await manifestFingerprint(manifest),
    protocolVersion: PROTOCOL_VERSION,
    createdAt: nowMs,
    updatedAt: nowMs,
    files: manifest.files.map((f) => ({
      name: f.name,
      size: f.size,
      mime: f.mime,
      lastModified: f.lastModified,
    })),
    reattachment,
    checksum: '',
  };
  record.checksum = await senderRecordChecksum(record);
  return record;
}

/**
 * Verify a prior record against the manifest of a resend and refresh it (updatedAt, and
 * the reattachment claim when the caller supplies a newer one, e.g. a re-materialized
 * handle). Throws before anything is sent when the canonical source identity changed —
 * the fingerprint covers the transfer id, block geometry, and every file's name, size,
 * mime, timestamp, and content digest, so any difference means a different source.
 */
export async function refreshSenderRecord(
  prior: SenderRecord,
  manifest: Manifest,
  reattachment: SenderReattachment | undefined,
  nowMs: number,
): Promise<SenderRecord> {
  if (prior.transferId !== manifest.transferId) {
    throw new TransferError(
      'integrity',
      `sender record belongs to transfer ${prior.transferId}, not ${manifest.transferId}`,
    );
  }
  const fingerprint = await manifestFingerprint(manifest);
  if (prior.manifestFingerprint !== fingerprint) {
    throw new TransferError(
      'integrity',
      `the selected source does not match interrupted transfer ${prior.transferId}; ` +
        'resuming requires the original source, unchanged. Start a new transfer instead.',
    );
  }
  const next: SenderRecord = {
    ...prior,
    updatedAt: nowMs,
    ...(reattachment !== undefined ? { reattachment } : {}),
  };
  next.checksum = await senderRecordChecksum(next);
  return next;
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
  oncomplete: ((ev: Event) => void) | null;
  onerror: ((ev: Event) => void) | null;
  onabort: ((ev: Event) => void) | null;
}
interface IDBDatabaseLike {
  objectStoreNames: { contains(name: string): boolean };
  transaction(storeNames: string[], mode: 'readonly' | 'readwrite'): IDBTransactionLike;
  close(): void;
}

/** The value stored per key: the key rides along so list() can report corrupt ids. */
interface StoredRecord {
  transferId: string;
  record: unknown;
}

function requestResult(r: IDBRequestLike): Promise<unknown> {
  return new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error ?? new Error('indexeddb request failed'));
  });
}

function transactionDone(tx: IDBTransactionLike): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(new Error('indexeddb transaction failed'));
    tx.onabort = () => reject(new Error('indexeddb transaction aborted'));
  });
}

/** The browser sender-record store over IndexedDB. */
export function indexedDbSenderRecordStore(): SenderRecordStore {
  return new IndexedDbSenderRecordStore();
}

/**
 * The store when IndexedDB exists, else undefined: the platform cannot persist sender
 * metadata, so the send proceeds without restart/reopen support (a degraded feature,
 * never a transfer blocker — mirroring how durable receive degrades without OPFS).
 */
export function senderRecordStoreWhenAvailable(): SenderRecordStore | undefined {
  if (!(globalThis as { indexedDB?: IDBFactory }).indexedDB) return undefined;
  return new IndexedDbSenderRecordStore();
}

class IndexedDbSenderRecordStore implements SenderRecordStore {
  private dbPromise: Promise<IDBDatabaseLike> | undefined;

  private db(): Promise<IDBDatabaseLike> {
    if (!this.dbPromise) {
      this.dbPromise = new Promise((resolve, reject) => {
        const idb = (globalThis as { indexedDB?: IDBFactory }).indexedDB;
        if (!idb) {
          reject(new Error('IndexedDB is unavailable in this browser'));
          return;
        }
        const req = idb.open(SENDER_DB, 1);
        req.onupgradeneeded = () => {
          const db = req.result;
          if (!db.objectStoreNames.contains(SENDER_RECORDS_STORE)) {
            db.createObjectStore(SENDER_RECORDS_STORE);
          }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error ?? new Error('open sendbeam-sender failed'));
      });
    }
    return this.dbPromise;
  }

  async load(transferId: string): Promise<SenderRecordLoad> {
    const db = await this.db();
    const tx = db.transaction([SENDER_RECORDS_STORE], 'readonly');
    const value = await requestResult(tx.objectStore(SENDER_RECORDS_STORE).get(transferId));
    await transactionDone(tx);
    if (value === undefined) return { kind: 'none' };
    const decoded = await decodeStored(value);
    return decoded.kind === 'ok' ? { kind: 'ok', record: decoded.record } : decoded;
  }

  async list(): Promise<SenderRecordListEntry[]> {
    const db = await this.db();
    const tx = db.transaction([SENDER_RECORDS_STORE], 'readonly');
    const values = await requestResult(tx.objectStore(SENDER_RECORDS_STORE).getAll());
    await transactionDone(tx);
    const out: SenderRecordListEntry[] = [];
    for (const value of values as unknown[]) {
      out.push(await decodeStored(value));
    }
    return out;
  }

  async put(record: SenderRecord): Promise<void> {
    await validateSenderRecord(record);
    const db = await this.db();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction([SENDER_RECORDS_STORE], 'readwrite');
      tx.objectStore(SENDER_RECORDS_STORE).put(
        { transferId: record.transferId, record },
        record.transferId,
      );
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(new Error('sender record write failed'));
      tx.onabort = () => reject(new Error('sender record write aborted'));
    });
  }

  async remove(transferId: string): Promise<void> {
    const db = await this.db();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction([SENDER_RECORDS_STORE], 'readwrite');
      tx.objectStore(SENDER_RECORDS_STORE).delete(transferId);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(new Error('sender record remove failed'));
      tx.onabort = () => reject(new Error('sender record remove aborted'));
    });
  }
}

/** Strictly validate one stored value into a list entry (fail closed, nothing deleted). */
async function decodeStored(value: unknown): Promise<SenderRecordListEntry> {
  if (!exactKeys(value, ['transferId', 'record'])) {
    return { kind: 'corrupt', transferId: '', error: 'sender record envelope is malformed' };
  }
  const stored = value as StoredRecord;
  if (typeof stored.transferId !== 'string' || stored.transferId === '') {
    return { kind: 'corrupt', transferId: '', error: 'sender record has no transfer id' };
  }
  try {
    const record = await validateSenderRecord(stored.record);
    if (record.transferId !== stored.transferId) {
      throw new Error('sender record key does not match its transfer id');
    }
    return { kind: 'ok', transferId: record.transferId, record };
  } catch (e) {
    return {
      kind: 'corrupt',
      transferId: stored.transferId,
      error: e instanceof Error ? e.message : String(e),
    };
  }
}

// ---------------------------------------------------------------------------
// In-memory backend (deterministic tests)
// ---------------------------------------------------------------------------

/** A deterministic in-memory store for tests; records keep structured-clone semantics. */
export function memorySenderRecordStore(): SenderRecordStore {
  return new MemorySenderRecordStore();
}

class MemorySenderRecordStore implements SenderRecordStore {
  private readonly entries = new Map<string, unknown>();

  async load(transferId: string): Promise<SenderRecordLoad> {
    const value = this.entries.get(transferId);
    if (value === undefined) return { kind: 'none' };
    const cloned = structuredClone(value);
    const decoded = await decodeStored({ transferId, record: cloned });
    return decoded.kind === 'ok' ? { kind: 'ok', record: decoded.record } : decoded;
  }

  async list(): Promise<SenderRecordListEntry[]> {
    const out: SenderRecordListEntry[] = [];
    for (const [transferId, value] of this.entries) {
      const cloned = structuredClone(value);
      out.push(await decodeStored({ transferId, record: cloned }));
    }
    return out.sort((a, b) => a.transferId.localeCompare(b.transferId));
  }

  async put(record: SenderRecord): Promise<void> {
    await validateSenderRecord(record);
    this.entries.set(record.transferId, structuredClone(record));
  }

  async remove(transferId: string): Promise<void> {
    this.entries.delete(transferId);
  }
}
