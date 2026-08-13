import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  FrameType,
  TransferError,
  bytesToHex,
  commitBlocks as advanceJournal,
  decodeJournal,
  encodeJournal,
  newJournal,
  sha256,
  type Digest,
  type DurableJournal,
  type Manifest,
} from '@sendbeam/protocol';
import { createSha256DigestFactory } from './digest.js';
import { DurableDestination } from './durable-destination.js';
import {
  DURABLE_LEASE_TTL_MS,
  webDestinationIdentity,
  type DurableFiles,
  type DurableJournalStore,
  type JournalLoad,
  type LeaseOutcome,
  type LeaseRecord,
  type PartialWriter,
  type WritableFileLike,
} from './durable-store.js';

// ---------------------------------------------------------------------------
// In-memory store + files fakes sharing an event log so tests can assert the
// flush-before-commit ordering deterministically (no sleeps).
// ---------------------------------------------------------------------------

const TRANSFER_ID = 'a'.repeat(32);
const IDENTITY = { version: 1, value: '0'.repeat(64) };

class MemoryStore implements DurableJournalStore {
  journals = new Map<string, Uint8Array>();
  leases = new Map<string, LeaseRecord>();
  /** Shared ordering log: 'flush' (files) and 'commit:<blocks>' (store). */
  events: string[] = [];
  /** Fault hooks. */
  failCommit = false;
  failCreate = false;

  async loadJournal(transferId: string): Promise<JournalLoad> {
    const bytes = this.journals.get(transferId);
    if (bytes === undefined) return { kind: 'none' };
    try {
      return { kind: 'ok', journal: await decodeJournal(bytes) };
    } catch (e) {
      return { kind: 'corrupt', error: e instanceof Error ? e.message : String(e) };
    }
  }

  async createJournal(
    transferId: string,
    manifest: Manifest,
    source: { version: number; value: string },
    destination: { version: number; value: string },
    nowMs: number,
  ): Promise<DurableJournal> {
    if (this.failCreate) throw new Error('create journal failed');
    const journal = await newJournal(transferId, manifest, source, destination, nowMs);
    this.journals.set(transferId, await encodeJournal(journal));
    return journal;
  }

  async commitBlocks(
    journal: DurableJournal,
    fileIdx: number,
    blocks: number,
    nowMs: number,
    ownerId: string,
  ): Promise<DurableJournal> {
    if (this.failCommit) throw new Error('journal commit failed');
    const lease = this.leases.get(journal.transferId);
    if (!lease || lease.ownerId !== ownerId) {
      throw new TransferError(
        'sink_error',
        'durable lease lost; another receiver owns this transfer',
      );
    }
    const next = advanceJournal(journal, fileIdx, blocks, nowMs);
    this.journals.set(next.transferId, await encodeJournal(next));
    this.leases.set(next.transferId, {
      ...lease,
      expiresAt: nowMs + DURABLE_LEASE_TTL_MS,
    });
    this.events.push(`commit:${fileIdx}:${blocks}`);
    return next;
  }

  async acquireLease(transferId: string, ownerId: string, nowMs: number): Promise<LeaseOutcome> {
    const lease = this.leases.get(transferId);
    const expiresAt = nowMs + DURABLE_LEASE_TTL_MS;
    if (!lease) {
      this.leases.set(transferId, { transferId, ownerId, expiresAt });
      return { kind: 'acquired' };
    }
    if (lease.expiresAt <= nowMs) {
      this.leases.set(transferId, { transferId, ownerId, expiresAt });
      return { kind: 'stale-taken' };
    }
    if (lease.ownerId === ownerId) {
      this.leases.set(transferId, { transferId, ownerId, expiresAt });
      return { kind: 'renewed' };
    }
    return { kind: 'contended' };
  }

  async renewLease(transferId: string, ownerId: string, nowMs: number): Promise<void> {
    const lease = this.leases.get(transferId);
    if (lease && lease.ownerId === ownerId) {
      this.leases.set(transferId, { ...lease, expiresAt: nowMs + DURABLE_LEASE_TTL_MS });
    }
  }

  async releaseLease(transferId: string, ownerId: string): Promise<void> {
    const lease = this.leases.get(transferId);
    if (lease && lease.ownerId === ownerId) this.leases.delete(transferId);
  }

  async discard(transferId: string): Promise<void> {
    this.journals.delete(transferId);
    this.leases.delete(transferId);
  }
}

class MemoryFiles implements DurableFiles {
  /** relPath → partial bytes. Shared across destination instances (same browser storage). */
  data = new Map<string, Uint8Array>();
  /** Outputs written by openOutput (ZIP finalize), key → bytes. */
  outputs = new Map<string, Uint8Array>();
  syncAvailable = true;
  /** Fault hook: writer.write throws a QuotaExceededError. */
  quotaOnWrite = false;
  events: string[] = [];

  async dataDir(): Promise<FileSystemDirectoryHandle> {
    throw new Error('dataDir is not used by the in-memory files fake');
  }
  async probeSync(): Promise<boolean> {
    return this.syncAvailable;
  }
  partialKey(transferId: string, relPath: string): string {
    return `sendbeam/durable/${transferId}/${relPath}.part`;
  }
  async openWriter(
    transferId: string,
    relPath: string,
    committedBytes: number,
    sync: boolean,
  ): Promise<PartialWriter> {
    const existing = this.data.get(relPath) ?? new Uint8Array();
    if (existing.length < committedBytes) {
      throw new TransferError(
        'sink_error',
        `partial ${relPath} truncated (have ${existing.length} bytes, checkpoint claims ${committedBytes})`,
      );
    }
    return new MemoryWriter(this, transferId, relPath, existing.slice(0, committedBytes), sync);
  }
  async partialSize(_transferId: string, relPath: string): Promise<number | undefined> {
    return this.data.get(relPath)?.length;
  }
  async readPrefix(
    _transferId: string,
    relPath: string,
    length: number,
    digest: Digest,
  ): Promise<void> {
    const bytes = this.data.get(relPath) ?? new Uint8Array();
    if (bytes.length < length) {
      throw new TransferError('sink_error', `partial ${relPath} shorter than its checkpoint`);
    }
    digest.update(bytes.slice(0, length));
  }
  async readPartialChunks(
    _transferId: string,
    relPath: string,
    visit: (chunk: Uint8Array) => void | Promise<void>,
  ): Promise<void> {
    const bytes = this.data.get(relPath);
    if (!bytes) throw new TransferError('sink_error', `partial ${relPath} missing at finalize`);
    for (let i = 0; i < bytes.length; i += 64) {
      await visit(bytes.slice(i, i + 64));
    }
  }
  async listRelPaths(): Promise<string[]> {
    return [...this.data.keys()].sort();
  }
  async openOutput(
    transferId: string,
    fileName: string,
  ): Promise<{ key: string; writable: WritableFileLike }> {
    const key = `sendbeam/durable/${transferId}/${fileName}`;
    return {
      key,
      writable: new OutputWritable(this.outputs, key),
    };
  }
  async removePartial(_transferId: string, relPath: string): Promise<void> {
    this.data.delete(relPath);
  }
  async removeData(): Promise<void> {
    this.data.clear();
  }
}

class MemoryWriter implements PartialWriter {
  private readonly base: Uint8Array;
  constructor(
    private readonly files: MemoryFiles,
    private readonly transferId: string,
    private readonly rel: string,
    base: Uint8Array,
    private readonly sync: boolean,
  ) {
    this.base = base.slice();
    this.files.data.set(rel, this.base);
  }
  async write(offset: number, bytes: Uint8Array): Promise<void> {
    if (this.files.quotaOnWrite) {
      throw new DOMException('storage quota exceeded', 'QuotaExceededError');
    }
    const current = this.files.data.get(this.rel) ?? this.base;
    const end = offset + bytes.length;
    const grown = new Uint8Array(Math.max(end, current.length));
    grown.set(current);
    grown.set(bytes, offset);
    this.files.data.set(this.rel, grown);
    if (this.sync) this.files.events.push('flush');
  }
  async close(): Promise<void> {
    this.files.events.push('close');
  }
  async abort(): Promise<void> {
    this.files.events.push('abort');
  }
}

class OutputWritable implements WritableFileLike {
  bytes = new Uint8Array();
  closed = false;
  constructor(
    private readonly outputs: Map<string, Uint8Array>,
    private readonly key: string,
  ) {}
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
    this.outputs.set(this.key, this.bytes);
  }
  async abort(): Promise<void> {
    this.outputs.delete(this.key);
  }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function manifest(names: Array<[string, number]>): Manifest {
  return {
    type: FrameType.Manifest,
    transferId: TRANSFER_ID,
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

interface Harness {
  store: MemoryStore;
  files: MemoryFiles;
  makeDestination: (overrides?: Partial<{ now: () => number }>) => DurableDestination;
  digest: () => Digest;
  advance: (ms: number) => void;
}

async function harness(): Promise<Harness> {
  const store = new MemoryStore();
  const files = new MemoryFiles();
  store.events = files.events;
  const digestFactory = await createSha256DigestFactory();
  let clock = 1_000;
  const now = () => clock;
  const makeDestination = (overrides: Partial<{ now: () => number }> = {}): DurableDestination =>
    new DurableDestination({
      createDigest: () => digestFactory(),
      files,
      store,
      now,
      renewMs: 0,
      ensureSpace: async () => {},
      ...overrides,
    });
  return {
    store,
    files,
    makeDestination,
    digest: () => digestFactory(),
    advance: (ms) => {
      clock += ms;
    },
  };
}

/** Write `blocks` blocks of the given sizes through a destination sink. */
function committed(journal: DurableJournal | undefined, fileIdx: number): number {
  return journal?.files[fileIdx]?.committedBlocks ?? -1;
}

/** Split a fresh transfer's verified data into a per-file partial map for a fake journal. */
async function journalFor(
  store: MemoryStore,
  files: MemoryFiles,
  names: Array<[string, number]>,
  committedPerFile: number[],
): Promise<DurableJournal> {
  // The destination binds journals to the browser storage location; journals the tests
  // fabricate must carry the same claim or prepare rejects them as foreign.
  const destination = await webDestinationIdentity('web');
  return newJournal(TRANSFER_ID, manifest(names), IDENTITY, destination, 1_000).then(async (j) => {
    for (let i = 0; i < names.length; i++) {
      const f = j.files[i]!;
      const rel = names[i]![0];
      // Persisted bytes mirror the checkpoint claim: one full block per committed count.
      const bytes = new Uint8Array(f.blockSize * committedPerFile[i]!);
      for (let b = 0; b < committedPerFile[i]!; b++) {
        bytes.set(
          new Uint8Array(f.blockSize).map((_, k) => (b * f.blockSize + k + 1) & 0xff),
          b * f.blockSize,
        );
      }
      files.data.set(rel, bytes);
    }
    const advanced = committedPerFile.reduce((acc, count, i) => {
      return count === 0 ? acc : advanceJournal(acc, i, count, 2_000);
    }, j);
    store.journals.set(TRANSFER_ID, await encodeJournal(advanced));
    store.leases.set(TRANSFER_ID, {
      transferId: TRANSFER_ID,
      ownerId: 'x'.repeat(16),
      expiresAt: 1_000 + DURABLE_LEASE_TTL_MS,
    });
    return advanced;
  });
}

function hasSignature(bytes: Uint8Array, signature: number): boolean {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let idx = 0; idx <= bytes.length - 4; idx++) {
    if (view.getUint32(idx, true) === signature) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('DurableDestination', () => {
  it('fresh receive: writes → flush → checkpoint per block, then finalize removes the journal', async () => {
    const h = await harness();
    const d = h.makeDestination();
    const m = manifest([['a.bin', 24]]);
    await d.prepare(m);
    expect(d.durableMeta()).toMatchObject({
      transferId: TRANSFER_ID,
      resumed: false,
      totalBytes: 24,
      committedBytes: 0,
    });

    const sink = await d.open(m.files[0]!);
    await sink.write(0, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
    expect(h.store.events).toEqual(['flush', 'commit:0:1']);

    await sink.write(8, new Uint8Array([9, 10, 11, 12, 13, 14, 15, 16]));
    await sink.write(16, new Uint8Array([17, 18, 19, 20, 21, 22, 23, 24]));
    await sink.close();
    expect(h.store.events.at(-1)).toBe('close');

    // Journal advanced ahead of nothing: committed equals written.
    const loaded = await h.store.loadJournal(TRANSFER_ID);
    expect(loaded.kind).toBe('ok');
    if (loaded.kind !== 'ok') return;
    expect(committed(loaded.journal, 0)).toBe(3);

    await d.close();
    // Finalize removed journal + lease; the verified partial is the deliverable.
    expect((await h.store.loadJournal(TRANSFER_ID)).kind).toBe('none');
    expect(h.files.data.get('a.bin')).toEqual(
      new Uint8Array([
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
      ]),
    );
    expect(d.result()).toMatchObject({
      kind: 'opfs',
      key: `sendbeam/durable/${TRANSFER_ID}/a.bin.part`,
      name: 'a.bin',
    });
  });

  it('flushed data is never advertised when the journal commit fails', async () => {
    const h = await harness();
    const d = h.makeDestination();
    const m = manifest([['a.bin', 16]]);
    await d.prepare(m);
    const sink = await d.open(m.files[0]!);
    await sink.write(0, new Uint8Array(8));
    h.store.failCommit = true;
    await expect(sink.write(8, new Uint8Array(8))).rejects.toThrow(/commit failed/);
    h.store.failCommit = false;

    const loaded = await h.store.loadJournal(TRANSFER_ID);
    expect(loaded.kind).toBe('ok');
    if (loaded.kind !== 'ok') return;
    // The checkpoint stays at block 1: flushed-but-uncommitted block 2 is never advertised.
    expect(committed(loaded.journal, 0)).toBe(1);
    expect(h.files.data.get('a.bin')?.length).toBe(16);
  });

  it('reload + resume from a committed checkpoint rehashes the persisted prefix', async () => {
    const h = await harness();
    const first = h.makeDestination();
    const m = manifest([['a.bin', 24]]);
    await first.prepare(m);
    const sink = await first.open(m.files[0]!);
    await sink.write(0, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
    await sink.write(8, new Uint8Array([9, 10, 11, 12, 13, 14, 15, 16]));
    // Tab crash: the first destination is abandoned (lease lives on via its TTL).

    // Reloaded receiver in the same room: same storage, expired lease → stale takeover.
    h.advance(DURABLE_LEASE_TTL_MS + 1);
    const second = h.makeDestination();
    await second.prepare(m);
    expect(second.durableMeta()?.resumed).toBe(true);

    const resume = second.resumeStateFor();
    expect(resume?.transferId).toBe(TRANSFER_ID);
    const file = resume?.files.get(0);
    expect(file?.haveBlocks).toBe(2);
    const expectedPrefix = bytesToHex(
      await sha256(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])),
    );
    expect(await file?.seedDigest.hexDigest()).toBe(expectedPrefix);

    // The receiver streams only the missing block; the sink resumes at the checkpoint.
    const resumedSink = await second.open(m.files[0]!);
    await resumedSink.write(16, new Uint8Array([17, 18, 19, 20, 21, 22, 23, 24]));
    await resumedSink.close();
    await second.close();
    expect((await h.store.loadJournal(TRANSFER_ID)).kind).toBe('none');
    expect(second.result()?.kind).toBe('opfs');
    expect(h.files.data.get('a.bin')).toEqual(
      new Uint8Array([
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
      ]),
    );
  });

  it('stale tail beyond the checkpoint is truncated and re-transferred on resume', async () => {
    const h = await harness();
    await journalFor(h.store, h.files, [['a.bin', 24]], [1]);
    // Simulate a crash between write and journal commit: durable data beyond the checkpoint.
    h.files.data.set('a.bin', new Uint8Array(16).fill(9));

    h.advance(DURABLE_LEASE_TTL_MS + 1);
    const d = h.makeDestination();
    const m = manifest([['a.bin', 24]]);
    await d.prepare(m);
    expect(d.resumeStateFor()?.files.get(0)?.haveBlocks).toBe(1);
    const sink = await d.open(m.files[0]!);
    // The stale tail was dropped: the writer starts from the authoritative checkpoint.
    expect(h.files.data.get('a.bin')?.length).toBe(8);
    await sink.write(8, new Uint8Array(8).fill(1));
    await sink.write(16, new Uint8Array(8).fill(2));
    await sink.close();
    await d.close();
  });

  it('fails closed on missing or truncated partials at resume (never guessed, never deleted)', async () => {
    const h = await harness();
    await journalFor(h.store, h.files, [['a.bin', 24]], [2]);
    h.files.data.delete('a.bin'); // evicted

    h.advance(DURABLE_LEASE_TTL_MS + 1);
    const d = h.makeDestination();
    await expect(d.prepare(manifest([['a.bin', 24]]))).rejects.toThrow(/missing or truncated/);
    // Nothing was deleted.
    expect((await h.store.loadJournal(TRANSFER_ID)).kind).toBe('ok');

    // Truncated variant.
    await journalFor(h.store, h.files, [['a.bin', 24]], [2]);
    h.files.data.set('a.bin', new Uint8Array(4));
    h.advance(DURABLE_LEASE_TTL_MS + 1);
    const d2 = h.makeDestination();
    await expect(d2.prepare(manifest([['a.bin', 24]]))).rejects.toThrow(/missing or truncated/);
  });

  it('concurrent tabs: the second receiver fails closed while the lease is held', async () => {
    const h = await harness();
    const first = h.makeDestination();
    const m = manifest([['a.bin', 8]]);
    await first.prepare(m);

    const second = h.makeDestination();
    await expect(second.prepare(m)).rejects.toThrow(/another window is already receiving/);
    // The first receiver still owns the lease and can keep writing.
    const sink = await first.open(m.files[0]!);
    await sink.write(0, new Uint8Array(8));
    const loaded = await h.store.loadJournal(TRANSFER_ID);
    expect(loaded.kind).toBe('ok');
    if (loaded.kind !== 'ok') return;
    expect(committed(loaded.journal, 0)).toBe(1);
  });

  it('Keep on abort: journal and partials survive, lease is released for an immediate retry', async () => {
    const h = await harness();
    const d = h.makeDestination();
    const m = manifest([['a.bin', 16]]);
    await d.prepare(m);
    const sink = await d.open(m.files[0]!);
    await sink.write(0, new Uint8Array(8));
    await d.abort();

    expect((await h.store.loadJournal(TRANSFER_ID)).kind).toBe('ok');
    expect(h.files.data.get('a.bin')?.length).toBe(8);
    expect(h.store.leases.has(TRANSFER_ID)).toBe(false);

    // A retry (same or another tab) acquires immediately and resumes from the checkpoint.
    const retry = h.makeDestination();
    await retry.prepare(m);
    expect(retry.durableMeta()?.resumed).toBe(true);
    await retry.abort();
  });

  it('rejects a corrupt journal and keeps it for explicit discard', async () => {
    const h = await harness();
    h.store.journals.set(TRANSFER_ID, new Uint8Array([9, 9, 9]));
    const d = h.makeDestination();
    await expect(d.prepare(manifest([['a.bin', 8]]))).rejects.toThrow(/unusable/);
    expect((await h.store.loadJournal(TRANSFER_ID)).kind).toBe('corrupt');
  });

  it('rejects a journal whose fingerprint does not match the authenticated manifest', async () => {
    const h = await harness();
    await journalFor(h.store, h.files, [['a.bin', 8]], [0]);
    const other = manifest([['different.bin', 8]]);
    h.advance(DURABLE_LEASE_TTL_MS + 1);
    const d = h.makeDestination();
    await expect(d.prepare(other)).rejects.toThrow(/does not match the authenticated manifest/);
  });

  it('fails closed on quota preflight and converts write-time quota exhaustion', async () => {
    const h = await harness();
    const m = manifest([['a.bin', 16]]);

    const low = new DurableDestination({
      createDigest: () => h.digest(),
      files: h.files,
      store: h.store,
      now: () => 1_000,
      renewMs: 0,
      ensureSpace: async () => {
        throw new TransferError('quota', 'need 16 bytes but only 4 are available');
      },
    });
    await expect(low.prepare(m)).rejects.toMatchObject({ reason: 'quota' });
    // The failed preflight left the lease held (prepare failed after acquiring); the real
    // flow's abort releases it, mirror that here so the next attempt can acquire.
    await low.abort();

    const d = h.makeDestination();
    await d.prepare(m);
    h.files.quotaOnWrite = true;
    const sink = await d.open(m.files[0]!);
    await expect(sink.write(0, new Uint8Array(8))).rejects.toMatchObject({ reason: 'quota' });
    // Fail closed: no checkpoint advanced, nothing deleted.
    const loaded = await h.store.loadJournal(TRANSFER_ID);
    expect(loaded.kind).toBe('ok');
    if (loaded.kind !== 'ok') return;
    expect(committed(loaded.journal, 0)).toBe(0);
    expect(h.files.data.get('a.bin')?.length ?? 0).toBe(0);
  });

  it('multi-file finalize builds a valid ZIP from the partials and removes the journal + partials', async () => {
    const h = await harness();
    const d = h.makeDestination();
    const m = manifest([
      ['folder/a.bin', 10],
      ['folder/empty.txt', 0],
    ]);
    await d.prepare(m);
    const first = await d.open(m.files[0]!);
    await first.write(0, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
    await first.write(8, new Uint8Array([9, 10]));
    await first.close();
    const second = await d.open(m.files[1]!);
    await second.close();
    await d.close();

    const zipBytes = h.files.outputs.get(`sendbeam/durable/${TRANSFER_ID}/__receive.zip`);
    expect(zipBytes).toBeDefined();
    const view = new DataView(zipBytes!.buffer);
    expect(view.getUint32(0, true)).toBe(0x04034b50);
    expect(view.getUint32(zipBytes!.length - 22, true)).toBe(0x06054b50);
    expect(hasSignature(zipBytes!, 0x02014b50)).toBe(true);

    expect((await h.store.loadJournal(TRANSFER_ID)).kind).toBe('none');
    expect(h.files.data.size).toBe(0); // consumed partials removed
    expect(d.result()).toMatchObject({ kind: 'opfs', name: 'folder.zip', mime: 'application/zip' });

    const dir = mkdtempSync(join(tmpdir(), 'sendbeam-durable-zip-'));
    try {
      const path = join(dir, 'folder.zip');
      writeFileSync(path, zipBytes!);
      expect(execFileSync('unzip', ['-t', path], { encoding: 'utf8' })).toContain('No errors');
      expect(execFileSync('unzip', ['-p', path, 'folder/a.bin'])).toEqual(
        Buffer.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('finalize refuses to remove the journal when a file is not fully committed', async () => {
    const h = await harness();
    const d = h.makeDestination();
    const m = manifest([['a.bin', 16]]);
    await d.prepare(m);
    const sink = await d.open(m.files[0]!);
    await sink.write(0, new Uint8Array(8));
    // Only 1 of 2 blocks committed: close() must fail closed and keep everything.
    await expect(d.close()).rejects.toThrow(/not fully committed/);
    expect((await h.store.loadJournal(TRANSFER_ID)).kind).toBe('ok');
    expect(h.files.data.get('a.bin')?.length).toBe(8);
  });

  it('idempotent discard removes the journal and lease without touching others', async () => {
    const h = await harness();
    const d = h.makeDestination();
    const m = manifest([['a.bin', 8]]);
    await d.prepare(m);
    const sink = await d.open(m.files[0]!);
    await sink.write(0, new Uint8Array(8));
    await d.abort();

    await h.store.discard(TRANSFER_ID);
    await h.store.discard(TRANSFER_ID); // idempotent
    expect((await h.store.loadJournal(TRANSFER_ID)).kind).toBe('none');
    expect(h.store.leases.has(TRANSFER_ID)).toBe(false);

    // A different transfer is untouched.
    const otherId = 'b'.repeat(32);
    const otherManifest: Manifest = {
      ...manifest([['x', 1]]),
      transferId: otherId,
    };
    h.store.journals.set(
      otherId,
      await encodeJournal(await newJournal(otherId, otherManifest, IDENTITY, IDENTITY, 1)),
    );
    await h.store.discard(TRANSFER_ID);
    expect((await h.store.loadJournal(otherId)).kind).toBe('ok');
  });

  it('async fallback advances the journal only at file close (honest granularity)', async () => {
    const h = await harness();
    h.files.syncAvailable = false;
    const d = h.makeDestination();
    const m = manifest([['a.bin', 16]]);
    await d.prepare(m);

    const sink = await d.open(m.files[0]!);
    await sink.write(0, new Uint8Array(8));
    // No per-block checkpoint on the async path: the stream cannot flush per block.
    let loaded = await h.store.loadJournal(TRANSFER_ID);
    expect(loaded.kind).toBe('ok');
    if (loaded.kind !== 'ok') return;
    expect(committed(loaded.journal, 0)).toBe(0);

    await sink.write(8, new Uint8Array(8));
    await sink.close();
    loaded = await h.store.loadJournal(TRANSFER_ID);
    expect(loaded.kind).toBe('ok');
    if (loaded.kind !== 'ok') return;
    // The close flushed the stream; only now does the whole file checkpoint.
    expect(committed(loaded.journal, 0)).toBe(2);
    await d.close();
    expect((await h.store.loadJournal(TRANSFER_ID)).kind).toBe('none');
  });

  it('never serializes secret material in the journal', async () => {
    const h = await harness();
    const d = h.makeDestination();
    const m = manifest([['a.bin', 8]]);
    await d.prepare(m);
    const sink = await d.open(m.files[0]!);
    await sink.write(0, new Uint8Array(8));
    const stored = h.store.journals.get(TRANSFER_ID)!;
    const text = new TextDecoder().decode(stored);
    const obj = JSON.parse(text) as Record<string, unknown>;
    // The schema has exactly the journal contract keys — no invite code, session master
    // key, directional keys, or AEAD counters can appear as fields.
    expect(Object.keys(obj).sort()).toEqual(
      [
        'blockSize',
        'checksum',
        'createdAt',
        'destinationIdentity',
        'files',
        'manifestFingerprint',
        'protocolVersion',
        'resumeVersion',
        'schemaVersion',
        'sourceIdentity',
        'transferId',
        'updatedAt',
      ].sort(),
    );
    for (const secret of ['invite', 'master', 'sendDir', 'recvDir', 'counter', 'o2j', 'j2o']) {
      expect(text.toLowerCase()).not.toContain(secret);
    }
    await d.abort();
  });
});
