import {
  TransferError,
  normalizeTransferPath,
  type Destination,
  type FileEntry,
  type Manifest,
  type Sink,
} from '@sendarc/protocol';
import { streamSink, type WritableFileLike } from './stream-sink.js';
import { opfsRoot, openDurableOpfsFile, type DurableOpfsFile } from './opfs-file.js';
import type { ReceiveDestinationSpec } from './wire.js';

export type DestinationOutput =
  { kind: 'opfs'; key: string; name: string; mime: string } | { kind: 'direct' };

export interface BrowserDestination extends Destination {
  result(): DestinationOutput | undefined;
}

/** Select a concrete destination only after the authenticated manifest is available. */
export function createBrowserDestination(spec: ReceiveDestinationSpec): BrowserDestination {
  let inner: BrowserDestination | undefined;
  const get = (): BrowserDestination => {
    if (!inner) throw new TransferError('sink_error', 'destination used before manifest');
    return inner;
  };
  return {
    async prepare(manifest) {
      if (spec.kind === 'direct-file') inner = new DirectFileDestination(spec.handle);
      else if (spec.kind === 'direct-directory')
        inner = new DirectDirectoryDestination(spec.handle);
      else if (manifest.files.length === 1 && !manifest.files[0]!.name.includes('/')) {
        inner = new OpfsFileDestination();
      } else {
        inner = new ArchiveDestination();
      }
      await inner.prepare(manifest);
    },
    open: (file) => get().open(file),
    close: () => get().close(),
    abort: (reason) => get().abort(reason),
    result: () => inner?.result(),
  };
}

class DirectFileDestination implements BrowserDestination {
  private sink: Sink | undefined;
  constructor(private readonly handle: FileSystemFileHandle) {}
  prepare(manifest: Manifest): void {
    if (manifest.files.length !== 1 || manifest.files[0]!.name.includes('/')) {
      throw new TransferError('sink_error', 'the selected file destination accepts one file only');
    }
  }
  async open(): Promise<Sink> {
    if (this.sink) throw new TransferError('sink_error', 'destination file opened twice');
    const writable = (await this.handle.createWritable({
      keepExistingData: false,
    })) as WritableFileLike;
    return (this.sink = streamSink(writable));
  }
  close(): void {}
  async abort(reason?: string): Promise<void> {
    await this.sink?.abort(reason);
  }
  result(): DestinationOutput {
    return { kind: 'direct' };
  }
}

class DirectDirectoryDestination implements BrowserDestination {
  private readonly opened: Sink[] = [];
  private readonly created: string[][] = [];
  constructor(private readonly root: FileSystemDirectoryHandle) {}
  prepare(): void {}
  async open(file: FileEntry): Promise<Sink> {
    const parts = normalizeTransferPath(file.name).split('/');
    let directory = this.root;
    for (const part of parts.slice(0, -1)) {
      directory = await directory.getDirectoryHandle(part, { create: true });
    }
    const leaf = parts.at(-1)!;
    try {
      await directory.getFileHandle(leaf);
      throw new TransferError('sink_error', `destination already contains ${file.name}`);
    } catch (err) {
      if (err instanceof TransferError) throw err;
      if (!(err instanceof DOMException) || err.name !== 'NotFoundError') throw err;
    }
    const handle = await directory.getFileHandle(leaf, { create: true });
    const writable = (await handle.createWritable({ keepExistingData: false })) as WritableFileLike;
    const sink = streamSink(writable);
    this.opened.push(sink);
    this.created.push(parts);
    return sink;
  }
  close(): void {}
  async abort(reason?: string): Promise<void> {
    await Promise.allSettled(this.opened.map((sink) => sink.abort(reason)));
    for (const parts of [...this.created].reverse()) {
      let directory = this.root;
      try {
        for (const part of parts.slice(0, -1)) {
          directory = await directory.getDirectoryHandle(part);
        }
        await directory.removeEntry(parts.at(-1)!);
      } catch {
        // Best effort after the first transfer failure.
      }
    }
  }
  result(): DestinationOutput {
    return { kind: 'direct' };
  }
}

/**
 * Single-file OPFS receive backed by a durable sync-access handle. Unlike a writable stream (which
 * truncates on open and only commits at close), the handle keeps existing bytes, writes straight
 * through, and can read its committed prefix back — the substrate a reloaded receiver resumes from.
 * A fresh unique key names an empty file per transfer, so this stays behaviour-identical to the
 * writable-stream path until a resume seed is threaded in.
 */
class OpfsFileDestination implements BrowserDestination {
  private key = '';
  private outputName = '';
  private mime = '';
  private sink: DurableOpfsFile | undefined;
  async prepare(manifest: Manifest): Promise<void> {
    await ensureQuota(manifest.totalSize);
    const file = manifest.files[0]!;
    this.outputName = file.name;
    this.mime = file.mime;
    this.key = uniqueKey(file.name);
  }
  async open(): Promise<Sink> {
    if (this.sink) throw new TransferError('sink_error', 'OPFS destination state');
    return (this.sink = await openDurableOpfsFile(this.key));
  }
  close(): void {}
  async abort(): Promise<void> {
    // Drop the handle's exclusive lock before removing the entry, or the removal blocks.
    this.sink?.abort();
    if (this.key) await (await opfsRoot()).removeEntry(this.key).catch(() => {});
  }
  result(): DestinationOutput {
    return { kind: 'opfs', key: this.key, name: this.outputName, mime: this.mime };
  }
}

interface ZipEntry {
  name: Uint8Array;
  crc: number;
  size: number;
  offset: number;
}

/** Streaming, store-only ZIP destination used when direct directory access is unavailable. */
export class ArchiveDestination implements BrowserDestination {
  private root: FileSystemDirectoryHandle | undefined;
  private writable: WritableFileLike | undefined;
  private key = '';
  private name = 'sendarc-files.zip';
  private position = 0;
  private readonly entries: ZipEntry[] = [];
  private active: ArchiveEntrySink | undefined;

  async prepare(manifest: Manifest): Promise<void> {
    const namesSize = manifest.files.reduce(
      (total, file) => total + new TextEncoder().encode(file.name).length * 2 + 92,
      22,
    );
    const archiveSize = manifest.totalSize + namesSize;
    if (archiveSize > 0xffffffff || manifest.files.some((file) => file.size > 0xffffffff)) {
      throw new TransferError('sink_error', 'ZIP fallback is limited to 4 GiB; choose a folder');
    }
    await ensureQuota(archiveSize);
    const top = manifest.files[0]!.name.split('/')[0]!;
    if (manifest.files.every((file) => file.name.startsWith(`${top}/`))) this.name = `${top}.zip`;
    this.key = uniqueKey(this.name);
    this.root = await opfsRoot();
    const handle = await this.root.getFileHandle(this.key, { create: true });
    this.writable = (await handle.createWritable({ keepExistingData: false })) as WritableFileLike;
  }

  async open(file: FileEntry): Promise<Sink> {
    if (!this.writable || this.active) throw new TransferError('sink_error', 'ZIP entry state');
    const name = new TextEncoder().encode(normalizeTransferPath(file.name));
    const offset = this.position;
    await this.append(localHeader(name));
    const entry = new ArchiveEntrySink(this, name, offset, file.size);
    this.active = entry;
    return entry;
  }

  async close(): Promise<void> {
    if (!this.writable || this.active)
      throw new TransferError('sink_error', 'ZIP not ready to close');
    const centralOffset = this.position;
    for (const entry of this.entries) await this.append(centralHeader(entry));
    const centralSize = this.position - centralOffset;
    await this.append(endOfCentralDirectory(this.entries.length, centralSize, centralOffset));
    await this.writable.close();
  }

  async abort(reason?: string): Promise<void> {
    await this.writable?.abort?.(reason);
    if (this.root && this.key) await this.root.removeEntry(this.key).catch(() => {});
  }

  result(): DestinationOutput {
    return { kind: 'opfs', key: this.key, name: this.name, mime: 'application/zip' };
  }

  async append(bytes: Uint8Array): Promise<void> {
    if (!this.writable) throw new TransferError('sink_error', 'ZIP writer unavailable');
    await this.writable.write({ type: 'write', position: this.position, data: bytes });
    this.position += bytes.length;
  }

  finishEntry(entry: ZipEntry): void {
    this.entries.push(entry);
    this.active = undefined;
  }
}

class ArchiveEntrySink implements Sink {
  private offset = 0;
  private crc = 0xffffffff;
  private closed = false;
  constructor(
    private readonly archive: ArchiveDestination,
    private readonly name: Uint8Array,
    private readonly localOffset: number,
    private readonly expectedSize: number,
  ) {}
  async write(offset: number, bytes: Uint8Array): Promise<void> {
    if (this.closed || offset !== this.offset)
      throw new TransferError('sink_error', 'ZIP write order');
    await this.archive.append(bytes);
    this.crc = crc32Update(this.crc, bytes);
    this.offset += bytes.length;
  }
  async close(): Promise<void> {
    if (this.closed || this.offset !== this.expectedSize) {
      throw new TransferError('sink_error', 'ZIP entry size mismatch');
    }
    this.closed = true;
    const crc = (this.crc ^ 0xffffffff) >>> 0;
    await this.archive.append(dataDescriptor(crc, this.offset));
    this.archive.finishEntry({ name: this.name, crc, size: this.offset, offset: this.localOffset });
  }
  abort(): void {
    this.closed = true;
  }
}

async function ensureQuota(required: number): Promise<void> {
  const storage = navigator.storage as StorageManager | undefined;
  if (!storage) throw new TransferError('sink_error', 'browser storage is unavailable');
  const estimate = await storage.estimate();
  if (estimate.quota === undefined) return;
  const available = Math.max(0, estimate.quota - (estimate.usage ?? 0));
  if (available < required) {
    throw new TransferError('quota', `need ${required} bytes but only ${available} are available`);
  }
}

function uniqueKey(name: string): string {
  const base = name.replace(/^.*\//, '').replace(/[^\p{L}\p{N}._-]+/gu, '_') || 'download';
  return `sendarc-${crypto.randomUUID()}-${base}`;
}

/**
 * Open a completed OPFS output without truncating or removing its backing entry.
 * Chromium-backed File snapshots become unreadable when that entry is removed, so the UI owns
 * cleanup and keeps it alive for as long as the download link is visible.
 */
export async function readOpfsOutput(key: string, name: string, mime: string): Promise<File> {
  const root = await opfsRoot();
  const handle = await root.getFileHandle(key, { create: false });
  const file = await handle.getFile();
  return new File([file], name, {
    type: mime || file.type,
    lastModified: file.lastModified,
  });
}

/** Remove an OPFS result once its download link is no longer exposed. */
export async function removeOpfsOutput(key: string): Promise<void> {
  const root = await opfsRoot();
  await root.removeEntry(key).catch(() => {});
}

const crcTable = Array.from({ length: 256 }, (_, value) => {
  let crc = value;
  for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  return crc >>> 0;
});

function crc32Update(crc: number, bytes: Uint8Array): number {
  for (const byte of bytes) crc = (crc >>> 8) ^ crcTable[(crc ^ byte) & 0xff]!;
  return crc >>> 0;
}

function record(size: number, write: (view: DataView) => void): Uint8Array {
  const out = new Uint8Array(size);
  write(new DataView(out.buffer));
  return out;
}

function localHeader(name: Uint8Array): Uint8Array {
  const header = record(30, (v) => {
    v.setUint32(0, 0x04034b50, true);
    v.setUint16(4, 20, true);
    v.setUint16(6, 0x0808, true);
    v.setUint16(26, name.length, true);
  });
  return join(header, name);
}

function dataDescriptor(crc: number, size: number): Uint8Array {
  return record(16, (v) => {
    v.setUint32(0, 0x08074b50, true);
    v.setUint32(4, crc, true);
    v.setUint32(8, size, true);
    v.setUint32(12, size, true);
  });
}

function centralHeader(entry: ZipEntry): Uint8Array {
  const header = record(46, (v) => {
    v.setUint32(0, 0x02014b50, true);
    v.setUint16(4, 20, true);
    v.setUint16(6, 20, true);
    v.setUint16(8, 0x0808, true);
    v.setUint32(16, entry.crc, true);
    v.setUint32(20, entry.size, true);
    v.setUint32(24, entry.size, true);
    v.setUint16(28, entry.name.length, true);
    v.setUint32(42, entry.offset, true);
  });
  return join(header, entry.name);
}

function endOfCentralDirectory(count: number, size: number, offset: number): Uint8Array {
  return record(22, (v) => {
    v.setUint32(0, 0x06054b50, true);
    v.setUint16(8, count, true);
    v.setUint16(10, count, true);
    v.setUint32(12, size, true);
    v.setUint32(16, offset, true);
  });
}

function join(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
