/**
 * Durable, resumable OPFS file backed by a synchronous access handle. Unlike a
 * `FileSystemWritableFileStream` (which truncates on open and only commits at close), a
 * `createSyncAccessHandle` keeps existing bytes, writes straight through, and exposes read,
 * truncate, getSize, and flush — everything a reloaded receiver needs to pick a transfer back up.
 *
 * The handle type lives in the WebWorker lib, which this package deliberately omits to avoid the
 * DOM/WebWorker clash (see transfer.worker.ts), so the surface we use is declared narrowly here.
 * Sync access handles are worker-only; construct these inside the transfer worker.
 */

import { TransferError, type Sink } from '@sendarc/protocol';

/** The slice of `FileSystemSyncAccessHandle` we depend on. */
export interface SyncAccessHandleLike {
  read(buffer: Uint8Array, options?: { at?: number }): number;
  write(buffer: Uint8Array, options?: { at?: number }): number;
  truncate(newSize: number): void;
  getSize(): number;
  flush(): void;
  close(): void;
}

interface SyncFileHandleLike {
  createSyncAccessHandle(): Promise<SyncAccessHandleLike>;
}

/**
 * A block-addressed durable file. `write` positions every block explicitly (blocks arrive verified
 * and in order); `flush` forces the committed prefix to disk before its high-water mark is
 * recorded; `read`/`truncate`/`size` let a reload re-seed the whole-file digest from what survived.
 */
export class DurableOpfsFile implements Sink {
  private closed = false;
  constructor(private readonly handle: SyncAccessHandleLike) {}

  /** Bytes currently on disk. A mid-transfer prefix is always a whole number of blocks. */
  size(): number {
    return this.handle.getSize();
  }

  write(offset: number, bytes: Uint8Array): void {
    if (this.closed) throw new TransferError('sink_error', 'write after close');
    const wrote = this.handle.write(bytes, { at: offset });
    if (wrote !== bytes.length) {
      throw new TransferError('sink_error', `short OPFS write: ${wrote}/${bytes.length}`);
    }
  }

  /** Read up to `into.length` bytes starting at `offset`; returns the count actually read. */
  read(offset: number, into: Uint8Array): number {
    return this.handle.read(into, { at: offset });
  }

  /** Drop any bytes past `length`, discarding a torn tail beyond the recorded high-water mark. */
  truncate(length: number): void {
    this.handle.truncate(length);
  }

  /** Force the OS to persist prior writes. Call before recording a new high-water mark. */
  flush(): void {
    this.handle.flush();
  }

  /** Finalise a completed file: flush, then release the handle so the main thread can read it. */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.handle.flush();
    this.handle.close();
  }

  /**
   * Release the handle without a final flush; the caller discards the backing entry afterwards.
   * The exclusive lock a sync access handle holds must drop first or the removal blocks.
   */
  abort(): void {
    if (this.closed) return;
    this.closed = true;
    this.handle.close();
  }
}

/** OPFS root, or a typed failure when the origin private file system is unavailable. */
export async function opfsRoot(): Promise<FileSystemDirectoryHandle> {
  const storage = navigator.storage as StorageManager | undefined;
  if (!storage || typeof storage.getDirectory !== 'function') {
    throw new TransferError('sink_error', 'Origin Private File System is unavailable');
  }
  return storage.getDirectory();
}

/** Open (creating if absent) a durable file by OPFS key. Worker-only — needs a sync access handle. */
export async function openDurableOpfsFile(key: string): Promise<DurableOpfsFile> {
  const root = await opfsRoot();
  const handle = (await root.getFileHandle(key, { create: true })) as unknown as SyncFileHandleLike;
  if (typeof handle.createSyncAccessHandle !== 'function') {
    throw new TransferError('sink_error', 'synchronous OPFS access is unavailable');
  }
  const access = await handle.createSyncAccessHandle();
  return new DurableOpfsFile(access);
}
