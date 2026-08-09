/**
 * Resume metadata store. A reloaded receiver re-joins the same room, so we key one small JSON
 * sidecar per room in OPFS: it records which durable file holds the committed prefix and how far
 * that prefix reaches. The sidecar is written only after the data file is flushed, so it can lag
 * the data but never lead it — a lost update just re-receives a few blocks, never corrupts.
 *
 * The transferId lets the receiver prove the arriving manifest is the same transfer; a room reused
 * for a different file set carries a new id, the seed is ignored, and a fresh receive begins.
 */

import { TransferError } from '@sendarc/protocol';
import type { WritableFileLike } from './stream-sink.js';
import { opfsRoot } from './opfs-file.js';

/** One room's persisted resume point. Scoped to the single-file OPFS destination. */
export interface ResumeRecord {
  room: number;
  transferId: string;
  /** OPFS key of the durable file holding the committed prefix. */
  opfsKey: string;
  name: string;
  mime: string;
  size: number;
  blockSize: number;
  /** Consecutively-committed, flushed blocks — the receiver's restored high-water mark. */
  haveBlocks: number;
  updatedAt: number;
}

export interface ResumeStore {
  get(room: number): Promise<ResumeRecord | undefined>;
  put(record: ResumeRecord): Promise<void>;
  delete(room: number): Promise<void>;
  /** Every stored record, for surfacing or pruning abandoned transfers. Torn entries are skipped. */
  list(): Promise<ResumeRecord[]>;
}

const PREFIX = 'sendarc-resume-';
const SUFFIX = '.json';

function sidecarKey(room: number): string {
  return `${PREFIX}${room}${SUFFIX}`;
}

/** Narrow view of the async directory iterator, which the DOM lib does not always type. */
interface DirectoryWithValues extends FileSystemDirectoryHandle {
  values?(): AsyncIterable<FileSystemHandle>;
}

function isRecord(value: unknown): value is ResumeRecord {
  if (typeof value !== 'object' || value === null) return false;
  const r = value as Record<string, unknown>;
  return (
    typeof r.room === 'number' &&
    typeof r.transferId === 'string' &&
    typeof r.opfsKey === 'string' &&
    typeof r.name === 'string' &&
    typeof r.mime === 'string' &&
    typeof r.size === 'number' &&
    typeof r.blockSize === 'number' &&
    typeof r.haveBlocks === 'number' &&
    typeof r.updatedAt === 'number'
  );
}

async function readSidecar(
  root: FileSystemDirectoryHandle,
  key: string,
): Promise<ResumeRecord | undefined> {
  let handle: FileSystemFileHandle;
  try {
    handle = await root.getFileHandle(key, { create: false });
  } catch (err) {
    if (err instanceof DOMException && err.name === 'NotFoundError') return undefined;
    throw err;
  }
  try {
    const text = await (await handle.getFile()).text();
    const parsed: unknown = JSON.parse(text);
    return isRecord(parsed) ? parsed : undefined;
  } catch {
    // A torn or malformed sidecar is discarded; the receive falls back to a fresh start.
    return undefined;
  }
}

/** OPFS-backed resume store. Reads and writes tolerate a missing or half-written sidecar. */
export function opfsResumeStore(): ResumeStore {
  return {
    async get(room) {
      return readSidecar(await opfsRoot(), sidecarKey(room));
    },
    async put(record) {
      const root = await opfsRoot();
      const handle = await root.getFileHandle(sidecarKey(record.room), { create: true });
      const writable = (await handle.createWritable({
        keepExistingData: false,
      })) as WritableFileLike;
      const bytes = new TextEncoder().encode(JSON.stringify(record));
      try {
        await writable.write({ type: 'write', position: 0, data: bytes });
        await writable.close();
      } catch (err) {
        await writable.abort?.();
        throw new TransferError('sink_error', err instanceof Error ? err.message : String(err));
      }
    },
    async delete(room) {
      const root = await opfsRoot();
      await root.removeEntry(sidecarKey(room)).catch(() => {});
    },
    async list() {
      const root = (await opfsRoot()) as DirectoryWithValues;
      if (typeof root.values !== 'function') return [];
      const records: ResumeRecord[] = [];
      for await (const entry of root.values()) {
        if (
          entry.kind !== 'file' ||
          !entry.name.startsWith(PREFIX) ||
          !entry.name.endsWith(SUFFIX)
        ) {
          continue;
        }
        const record = await readSidecar(root, entry.name);
        if (record) records.push(record);
      }
      return records;
    },
  };
}
