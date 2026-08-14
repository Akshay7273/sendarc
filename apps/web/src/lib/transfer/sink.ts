import {
  TransferError,
  normalizeTransferPath,
  type Destination,
  type FileEntry,
  type Manifest,
  type Sink,
} from '@sendbeam/protocol';
import { streamSink, type WritableFileLike } from './stream-sink.js';
import { DurableDestination, type DurableMeta } from './durable-destination.js';
import { durableOpfsFiles, indexedDbDurableStore } from './durable-store.js';
import {
  centralHeader,
  crc32Update,
  dataDescriptor,
  endOfCentralDirectory,
  localHeader,
  type ZipEntry,
} from './zip.js';
import type { ReceiveDestinationSpec } from './wire.js';
import type { Sha256DigestFactory } from './digest.js';

export type DestinationOutput =
  { kind: 'opfs'; key: string; name: string; mime: string } | { kind: 'direct' };

export interface BrowserDestination extends Destination {
  result(): DestinationOutput | undefined;
  /** Durable-receive metadata the host needs for lease release and Keep/Discard. */
  durableMeta?(): DurableMeta | undefined;
  /** Resume seed a reloaded receiver applies after the authenticated manifest arrives. */
  resumeStateFor?(manifest: Manifest): import('@sendbeam/protocol').ReceiverResumeState | undefined;
  /**
   * Persist the transfer-scoped resume credential into the receive journal (V13-PR07),
   * after the authenticated manifest validated and bound to it. `resumeRoot` is the
   * transient root derived by the main thread — never the session master.
   */
  attachResumeSecret?(manifest: Manifest, resumeRoot: Uint8Array): Promise<void>;
}

/**
 * Select a concrete destination only after the authenticated manifest is available. `auto`
 * destinations whose manifest opted into resumption (carries a transfer id) route to the
 * durable receive store; everything else keeps the fresh-key download behavior.
 */
export function createBrowserDestination(
  spec: ReceiveDestinationSpec,
  createDigest?: Sha256DigestFactory,
): BrowserDestination {
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
      else if (manifest.transferId !== undefined) {
        if (!createDigest) {
          throw new TransferError('sink_error', 'durable receive requires a digest factory');
        }
        inner = new DurableDestination({
          createDigest,
          files: durableOpfsFiles(),
          store: indexedDbDurableStore(),
        });
      } else if (manifest.files.length === 1 && !manifest.files[0]!.name.includes('/')) {
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
    durableMeta: () => inner?.durableMeta?.(),
    attachResumeSecret: (manifest, resumeRoot) => {
      const target = get();
      if (!target.attachResumeSecret) {
        throw new TransferError('sink_error', 'destination does not support resume credentials');
      }
      return target.attachResumeSecret(manifest, resumeRoot);
    },
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

class OpfsFileDestination implements BrowserDestination {
  private root: FileSystemDirectoryHandle | undefined;
  private key = '';
  private outputName = '';
  private mime = '';
  private sink: Sink | undefined;
  async prepare(manifest: Manifest): Promise<void> {
    await ensureQuota(manifest.totalSize);
    const file = manifest.files[0]!;
    this.root = await opfsRoot();
    this.outputName = file.name;
    this.mime = file.mime;
    this.key = uniqueKey(file.name);
  }
  async open(): Promise<Sink> {
    if (!this.root || this.sink) throw new TransferError('sink_error', 'OPFS destination state');
    const handle = await this.root.getFileHandle(this.key, { create: true });
    const writable = (await handle.createWritable({ keepExistingData: false })) as WritableFileLike;
    return (this.sink = streamSink(writable));
  }
  close(): void {}
  async abort(reason?: string): Promise<void> {
    await this.sink?.abort(reason);
    if (this.root && this.key) await this.root.removeEntry(this.key).catch(() => {});
  }
  result(): DestinationOutput {
    return { kind: 'opfs', key: this.key, name: this.outputName, mime: this.mime };
  }
}

/** Streaming, store-only ZIP destination used when direct directory access is unavailable. */
export class ArchiveDestination implements BrowserDestination {
  private root: FileSystemDirectoryHandle | undefined;
  private writable: WritableFileLike | undefined;
  private key = '';
  private name = 'sendbeam-files.zip';
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

export async function ensureQuota(required: number): Promise<void> {
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
  return `sendbeam-${crypto.randomUUID()}-${base}`;
}

/**
 * Resolve a '/'-separated key under the OPFS root to a file handle, walking directory
 * components so durable-receive keys (`sendbeam/durable/<id>/<rel>.part`) resolve too.
 */
export async function opfsFileHandle(
  root: FileSystemDirectoryHandle,
  key: string,
  create: boolean,
): Promise<FileSystemFileHandle> {
  const parts = key.split('/');
  const leaf = parts.at(-1)!;
  let directory = root;
  for (const part of parts.slice(0, -1)) {
    directory = await directory.getDirectoryHandle(part, { create });
  }
  return directory.getFileHandle(leaf, { create });
}

/**
 * Open a completed OPFS output without truncating or removing its backing entry.
 * Chromium-backed File snapshots become unreadable when that entry is removed, so the UI owns
 * cleanup and keeps it alive for as long as the download link is visible.
 */
export async function readOpfsOutput(key: string, name: string, mime: string): Promise<File> {
  const root = await opfsRoot();
  const handle = await opfsFileHandle(root, key, false);
  const file = await handle.getFile();
  return new File([file], name, {
    type: mime || file.type,
    lastModified: file.lastModified,
  });
}

/** Remove an OPFS result once its download link is no longer exposed. */
export async function removeOpfsOutput(key: string): Promise<void> {
  const root = await opfsRoot();
  const parts = key.split('/');
  const leaf = parts.at(-1)!;
  let directory = root;
  for (const part of parts.slice(0, -1)) {
    try {
      directory = await directory.getDirectoryHandle(part, { create: false });
    } catch {
      return; // nothing to remove
    }
  }
  await directory.removeEntry(leaf).catch(() => {});
}

export async function opfsRoot(): Promise<FileSystemDirectoryHandle> {
  const storage = navigator.storage as StorageManager | undefined;
  if (!storage || typeof storage.getDirectory !== 'function') {
    throw new TransferError('sink_error', 'Origin Private File System is unavailable');
  }
  return storage.getDirectory();
}
