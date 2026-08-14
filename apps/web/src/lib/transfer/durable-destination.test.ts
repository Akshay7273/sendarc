import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  DIGEST_CHECKPOINT_FORMAT_HASH_WASM,
  FRAME_VERSION,
  FrameType,
  TransferError,
  TransferReceiver,
  bytesToHex,
  commitBlocks as advanceJournal,
  decodeJournal,
  deriveTransferKeys,
  encodeControl,
  encodeJournal,
  newJournal,
  seal,
  sha256,
  type Digest,
  type DigestState,
  type DigestStateSink,
  type DurableJournal,
  type FrameHeaderInput,
  type JournalDigestCheckpoint,
  type Manifest,
  type ResumeSecretEnvelope,
} from '@sendbeam/protocol';
import { createSha256DigestFactory, type Sha256DigestFactory } from './digest.js';
import { DurableDestination } from './durable-destination.js';
import { createBrowserDestination } from './sink.js';
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
  failDiscard = false;
  failAttach = false;

  async loadJournal(transferId: string): Promise<JournalLoad> {
    const bytes = this.journals.get(transferId);
    if (bytes === undefined) return { kind: 'none' };
    try {
      return { kind: 'ok', journal: await decodeJournal(bytes) };
    } catch (e) {
      return { kind: 'corrupt', error: e instanceof Error ? e.message : String(e) };
    }
  }

  async listJournals(): Promise<
    Array<{
      transferId: string;
      kind: 'ok' | 'corrupt';
      journal?: DurableJournal;
      error?: string;
    }>
  > {
    const out: Array<{
      transferId: string;
      kind: 'ok' | 'corrupt';
      journal?: DurableJournal;
      error?: string;
    }> = [];
    for (const [transferId, bytes] of this.journals) {
      try {
        out.push({ transferId, kind: 'ok', journal: await decodeJournal(bytes) });
      } catch (e) {
        out.push({
          transferId,
          kind: 'corrupt',
          error: e instanceof Error ? e.message : String(e),
        });
      }
    }
    return out;
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
    digestCheckpoint?: JournalDigestCheckpoint,
  ): Promise<DurableJournal> {
    if (this.failCommit) throw new Error('journal commit failed');
    const lease = this.leases.get(journal.transferId);
    if (!lease || lease.ownerId !== ownerId) {
      throw new TransferError(
        'sink_error',
        'durable lease lost; another receiver owns this transfer',
      );
    }
    const next = advanceJournal(journal, fileIdx, blocks, nowMs, digestCheckpoint);
    this.journals.set(next.transferId, await encodeJournal(next));
    this.leases.set(next.transferId, {
      ...lease,
      expiresAt: nowMs + DURABLE_LEASE_TTL_MS,
    });
    this.events.push(`commit:${fileIdx}:${blocks}`);
    return next;
  }

  async attachResumeSecret(
    transferId: string,
    envelope: ResumeSecretEnvelope,
    ownerId: string,
    nowMs: number,
  ): Promise<DurableJournal> {
    if (this.failAttach) throw new Error('journal attach failed');
    const lease = this.leases.get(transferId);
    if (!lease || lease.ownerId !== ownerId) {
      throw new TransferError(
        'sink_error',
        'durable lease lost; another receiver owns this transfer — cannot attach the resume credential',
      );
    }
    const bytes = this.journals.get(transferId);
    if (bytes === undefined) {
      throw new TransferError(
        'sink_error',
        'durable journal missing; cannot attach the resume credential',
      );
    }
    const current = await decodeJournal(bytes);
    const next: DurableJournal = {
      ...current,
      resumeSecret: current.resumeSecret ?? envelope,
    };
    this.journals.set(transferId, await encodeJournal(next));
    this.leases.set(transferId, {
      ...lease,
      expiresAt: nowMs + DURABLE_LEASE_TTL_MS,
    });
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
    if (this.failDiscard) throw new Error('discard failed');
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
  /** Fault hook: openOutput throws (ZIP finalization failure). */
  failOutput = false;
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
    if (this.failOutput) throw new Error('output write failed');
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
  digest: Sha256DigestFactory;
  now: () => number;
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
      createDigest: digestFactory,
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
    digest: digestFactory,
    now,
    advance: (ms) => {
      clock += ms;
    },
  };
}

/** Write `blocks` blocks of the given sizes through a destination sink. */
function committed(journal: DurableJournal | undefined, fileIdx: number): number {
  return journal?.files[fileIdx]?.committedBlocks ?? -1;
}

/**
 * V13-PR08: arm an explicit authenticated-resume attempt the way the driver does — the
 * user pre-selects the interrupted journal (expectResumeFor) and the resume preamble runs
 * to mutual success (authorizeResume) strictly before `prepare` may reuse its progress.
 * Tests that exercise the reload-resume mechanics call this before a resumed prepare.
 */
function armAuth(d: DurableDestination): DurableDestination {
  d.expectResumeFor(TRANSFER_ID);
  d.authorizeResume();
  return d;
}

/** Serialized digest state covering exactly `bytes` — what the receiver feeds before each write. */
function digestStateFor(h: Harness, bytes: Uint8Array): Uint8Array {
  const d = h.digest();
  d.update(bytes);
  return (d as unknown as DigestState).saveState();
}

/** Split a fresh transfer's verified data into a per-file partial map for a fake journal. */
async function journalFor(
  store: MemoryStore,
  files: MemoryFiles,
  names: Array<[string, number]>,
  committedPerFile: number[],
  m: Manifest = manifest(names),
): Promise<DurableJournal> {
  // The destination binds journals to the browser storage location; journals the tests
  // fabricate must carry the same claim or prepare rejects them as foreign.
  const destination = await webDestinationIdentity('web');
  return newJournal(TRANSFER_ID, m, IDENTITY, destination, 1_000).then(async (j) => {
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

/** Attach a digest checkpoint to a fabricated journal and persist it. */
async function journalWithCheckpoint(
  store: MemoryStore,
  journal: DurableJournal,
  cp: JournalDigestCheckpoint,
): Promise<void> {
  const advanced = advanceJournal(journal, 0, cp.committedBlocks, 3_000, cp);
  store.journals.set(TRANSFER_ID, await encodeJournal(advanced));
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
    // The driver arms an authenticated-resume attempt before prepare reuses the checkpoint.
    h.advance(DURABLE_LEASE_TTL_MS + 1);
    const second = armAuth(h.makeDestination());
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

  it('commits a digest checkpoint per block and resumes by restoring it (V13-PR05)', async () => {
    const h = await harness();
    const first = h.makeDestination();
    const m = manifest([['a.bin', 24]]);
    await first.prepare(m);
    const sink = await first.open(m.files[0]!);
    // The receiver seam (V13-PR05): digest state is fed before each write and persisted
    // atomically with the resulting checkpoint.
    (sink as unknown as DigestStateSink).setDigestState(
      digestStateFor(h, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])),
    );
    await sink.write(0, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
    (sink as unknown as DigestStateSink).setDigestState(
      digestStateFor(h, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])),
    );
    await sink.write(8, new Uint8Array([9, 10, 11, 12, 13, 14, 15, 16]));
    // Tab crash: the first destination is abandoned without close.

    const loaded = await h.store.loadJournal(TRANSFER_ID);
    expect(loaded.kind).toBe('ok');
    if (loaded.kind !== 'ok') return;
    const cp = loaded.journal.files[0]!.digestCheckpoint;
    expect(cp?.format).toBe(DIGEST_CHECKPOINT_FORMAT_HASH_WASM);
    expect(cp?.committedBlocks).toBe(2);
    expect(cp?.committedBytes).toBe(16);
    expect(cp?.state).toMatch(/^[0-9a-f]{232}$/); // 116-byte hash-wasm state

    h.advance(DURABLE_LEASE_TTL_MS + 1);
    const second = armAuth(h.makeDestination());
    await second.prepare(m);
    expect(second.durableMeta()?.resumed).toBe(true);

    // The restored digest covers the bytes the state was saved from. Corrupting the
    // persisted prefix on disk must NOT change the seed: restore skips the re-hash.
    const persisted = h.files.data.get('a.bin')!;
    persisted[0]! ^= 0xff;
    const file = second.resumeStateFor()?.files.get(0);
    expect(file?.haveBlocks).toBe(2);
    const expected = await sha256(
      new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
    );
    expect(await file?.seedDigest.hexDigest()).toBe(bytesToHex(expected));
  });

  it('falls back to rehashing the persisted prefix when the checkpoint cannot be restored (V13-PR05)', async () => {
    const h = await harness();
    const m = manifest([['a.bin', 24]]);
    const j = await journalFor(h.store, h.files, [['a.bin', 24]], [2]);
    // A checkpoint from a foreign runtime: well-formed, but not this runtime's format.
    const foreign: JournalDigestCheckpoint = {
      format: 'sha256-go-v1',
      committedBlocks: 2,
      committedBytes: 16,
      state: '00'.repeat(108), // Go stdlib state size, plausible shape
    };
    await journalWithCheckpoint(h.store, j, foreign);

    h.advance(DURABLE_LEASE_TTL_MS + 1);
    const d = armAuth(h.makeDestination());
    await d.prepare(m);
    const file = d.resumeStateFor()?.files.get(0);
    expect(file?.haveBlocks).toBe(2);
    // Re-hashed from the persisted partial: byte b*8+k+1 (journalFor's deterministic data).
    const persisted = new Uint8Array(16).map((_, k) => (k + 1) & 0xff);
    expect(await file?.seedDigest.hexDigest()).toBe(bytesToHex(await sha256(persisted)));

    // Undecodable state (wrong length): restore throws, correctness-first re-hash takes over.
    const undecodable: JournalDigestCheckpoint = {
      format: DIGEST_CHECKPOINT_FORMAT_HASH_WASM,
      committedBlocks: 2,
      committedBytes: 16,
      state: '00'.repeat(58), // 58 bytes, not the 116 the wasm expects
    };
    const j2 = await journalFor(h.store, h.files, [['b.bin', 24]], [2]);
    await journalWithCheckpoint(h.store, j2, undecodable);
    h.advance(DURABLE_LEASE_TTL_MS + 1);
    const d2 = armAuth(h.makeDestination());
    await d2.prepare(manifest([['b.bin', 24]]));
    const file2 = d2.resumeStateFor()?.files.get(0);
    expect(await file2?.seedDigest.hexDigest()).toBe(bytesToHex(await sha256(persisted)));
  });

  it('a lying digest checkpoint seeds the digest but whole-file verification still guards the receive (V13-PR05)', async () => {
    const h = await harness();
    const j = await journalFor(h.store, h.files, [['a.bin', 24]], [2]);
    // A real hash-wasm state that covers 16 zero bytes — not the persisted prefix.
    const make = await createSha256DigestFactory();
    const lying = make();
    lying.update(new Uint8Array(16));
    const state = (lying as unknown as DigestState).saveState();
    const cp: JournalDigestCheckpoint = {
      format: DIGEST_CHECKPOINT_FORMAT_HASH_WASM,
      committedBlocks: 2,
      committedBytes: 16,
      state: bytesToHex(state),
    };
    await journalWithCheckpoint(h.store, j, cp);

    h.advance(DURABLE_LEASE_TTL_MS + 1);
    const d = armAuth(h.makeDestination());
    await d.prepare(manifest([['a.bin', 24]]));
    const file = d.resumeStateFor()?.files.get(0);
    // The seed covers the checkpointed state's bytes — trusted, never guessed. The
    // receiver's mandatory final whole-file digest is what rejects a wrong state.
    const seedHex = await file?.seedDigest.hexDigest();
    expect(seedHex).toBe(bytesToHex(await sha256(new Uint8Array(16))));
    expect(seedHex).not.toBe(
      bytesToHex(await sha256(new Uint8Array(16).map((_, k) => (k + 1) & 0xff))),
    );
  });

  it('multi-file resume: fallback seeds from one factory stay isolated while live (V13-PR05)', async () => {
    const h = await harness();
    // Old v1 journal: no digest checkpoints anywhere — every seed must be re-hashed.
    await journalFor(
      h.store,
      h.files,
      [
        ['a.bin', 24],
        ['b.bin', 16],
      ],
      [2, 1],
    );
    // Distinct persisted content for the second file (journalFor's default pattern is shared).
    const bPrefix = new Uint8Array(8).map((_, k) => (k + 101) & 0xff);
    h.files.data.set('b.bin', bPrefix);

    h.advance(DURABLE_LEASE_TTL_MS + 1);
    const d = armAuth(h.makeDestination());
    await d.prepare(
      manifest([
        ['a.bin', 24],
        ['b.bin', 16],
      ]),
    );
    const files = d.resumeStateFor()!.files;
    const a = files.get(0)!.seedDigest;
    const b = files.get(1)!.seedDigest;

    // The receiver feeds files interleaved while every seed stays live; each digest
    // must cover exactly its own prefix. (Before the fix, a shared hasher aliased them.)
    a.update(new Uint8Array([17, 18, 19, 20, 21, 22, 23, 24]));
    b.update(new Uint8Array([109, 110, 111, 112, 113, 114, 115, 116]));
    expect(await a.hexDigest()).toBe(
      bytesToHex(await sha256(new Uint8Array(24).map((_, k) => (k + 1) & 0xff))),
    );
    expect(await b.hexDigest()).toBe(
      bytesToHex(
        await sha256(new Uint8Array([...bPrefix, 109, 110, 111, 112, 113, 114, 115, 116])),
      ),
    );
    // Digesting one must not deinitialize the other's stream.
    expect(await a.hexDigest()).toBe(
      bytesToHex(await sha256(new Uint8Array(24).map((_, k) => (k + 1) & 0xff))),
    );
    expect(await b.hexDigest()).toBe(
      bytesToHex(
        await sha256(new Uint8Array([...bPrefix, 109, 110, 111, 112, 113, 114, 115, 116])),
      ),
    );
  });

  it('multi-file resume: a restored checkpoint and a fallback seed stay isolated (V13-PR05)', async () => {
    const h = await harness();
    const j = await journalFor(
      h.store,
      h.files,
      [
        ['a.bin', 24],
        ['b.bin', 24],
      ],
      [2, 1],
    );
    const aBytes = new Uint8Array(16).map((_, k) => (k + 1) & 0xff);
    await journalWithCheckpoint(h.store, j, {
      format: DIGEST_CHECKPOINT_FORMAT_HASH_WASM,
      committedBlocks: 2,
      committedBytes: 16,
      state: bytesToHex(digestStateFor(h, aBytes)),
    });
    // Corrupt a.bin on disk: the restored seed must ignore it (restore skips the re-hash).
    h.files.data.set('a.bin', new Uint8Array(16).fill(0xff));

    h.advance(DURABLE_LEASE_TTL_MS + 1);
    const d = armAuth(h.makeDestination());
    await d.prepare(
      manifest([
        ['a.bin', 24],
        ['b.bin', 24],
      ]),
    );
    const files = d.resumeStateFor()!.files;
    const a = files.get(0)!.seedDigest;
    const b = files.get(1)!.seedDigest;
    expect(await a.hexDigest()).toBe(bytesToHex(await sha256(aBytes)));
    expect(await b.hexDigest()).toBe(
      bytesToHex(await sha256(new Uint8Array(8).map((_, k) => (k + 1) & 0xff))),
    );
    // Interleaved continuation of both remains independent.
    a.update(new Uint8Array([17, 18, 19, 20, 21, 22, 23, 24]));
    b.update(new Uint8Array([9, 10, 11, 12, 13, 14, 15, 16]));
    b.update(new Uint8Array([17, 18, 19, 20, 21, 22, 23, 24]));
    expect(await a.hexDigest()).toBe(
      bytesToHex(await sha256(new Uint8Array(24).map((_, k) => (k + 1) & 0xff))),
    );
    expect(await b.hexDigest()).toBe(
      bytesToHex(await sha256(new Uint8Array(24).map((_, k) => (k + 1) & 0xff))),
    );
  });

  it('multi-file resume: foreign-format checkpoint falls back alongside a plain rehash (V13-PR05)', async () => {
    const h = await harness();
    const j = await journalFor(
      h.store,
      h.files,
      [
        ['a.bin', 24],
        ['b.bin', 24],
      ],
      [2, 1],
    );
    await journalWithCheckpoint(h.store, j, {
      format: 'sha256-go-v1',
      committedBlocks: 2,
      committedBytes: 16,
      state: '00'.repeat(108),
    });

    h.advance(DURABLE_LEASE_TTL_MS + 1);
    const d = armAuth(h.makeDestination());
    await d.prepare(
      manifest([
        ['a.bin', 24],
        ['b.bin', 24],
      ]),
    );
    const files = d.resumeStateFor()!.files;
    const a = files.get(0)!.seedDigest;
    const b = files.get(1)!.seedDigest;
    // Both re-hash from the persisted prefix, but stay independent while live.
    const aBytes = new Uint8Array(16).map((_, k) => (k + 1) & 0xff);
    const bBytes = new Uint8Array(8).map((_, k) => (k + 1) & 0xff);
    expect(await a.hexDigest()).toBe(bytesToHex(await sha256(aBytes)));
    expect(await b.hexDigest()).toBe(bytesToHex(await sha256(bBytes)));
    a.update(new Uint8Array([17, 18, 19, 20, 21, 22, 23, 24]));
    b.update(new Uint8Array([9, 10, 11, 12, 13, 14, 15, 16]));
    b.update(new Uint8Array([17, 18, 19, 20, 21, 22, 23, 24]));
    expect(await a.hexDigest()).toBe(
      bytesToHex(await sha256(new Uint8Array(24).map((_, k) => (k + 1) & 0xff))),
    );
    expect(await b.hexDigest()).toBe(
      bytesToHex(await sha256(new Uint8Array(24).map((_, k) => (k + 1) & 0xff))),
    );
  });

  it('resume covers fully committed files and skips seeds for not-yet-started ones (matches the Go driver)', async () => {
    const h = await harness();
    // a.bin fully committed (3/3), b.bin not started (0/3), c.bin partially committed (1/3).
    await journalFor(
      h.store,
      h.files,
      [
        ['a.bin', 24],
        ['b.bin', 24],
        ['c.bin', 24],
      ],
      [3, 0, 1],
    );

    h.advance(DURABLE_LEASE_TTL_MS + 1);
    const d = armAuth(h.makeDestination());
    await d.prepare(
      manifest([
        ['a.bin', 24],
        ['b.bin', 24],
        ['c.bin', 24],
      ]),
    );
    const files = d.resumeStateFor()!.files;
    // Fully committed: the seed covers the whole file (verified at finish). Not started: the
    // seed still covers it at haveBlocks 0 (complete coverage, V13-PR06) so the receiver's
    // exact file-set validation passes and the file restarts fresh — like the Go driver.
    expect(files.get(0)!.haveBlocks).toBe(3);
    expect(await files.get(0)!.seedDigest.hexDigest()).toBe(
      bytesToHex(await sha256(new Uint8Array(24).map((_, k) => (k + 1) & 0xff))),
    );
    expect(files.get(1)!.haveBlocks).toBe(0);
    expect(files.get(2)!.haveBlocks).toBe(1);
    // Every manifest file is covered.
    expect(files.size).toBe(3);
  });

  it('final resumed transfer streams only missing blocks and verifies every file (V13-PR05)', async () => {
    const h = await harness();
    const whole = new Uint8Array(24).map((_, k) => (k + 1) & 0xff);
    const small = new Uint8Array(8).map((_, k) => (k + 1) & 0xff);
    const files = [
      { name: 'a.bin', size: 24, data: whole },
      { name: 'b.bin', size: 24, data: whole },
      { name: 'c.bin', size: 24, data: whole },
      { name: 'd.bin', size: 8, data: small },
    ];
    const digests = await Promise.all(files.map(async (f) => bytesToHex(await sha256(f.data))));
    const m: Manifest = {
      type: FrameType.Manifest,
      transferId: TRANSFER_ID,
      files: files.map((f, idx) => ({
        idx,
        name: f.name,
        size: f.size,
        mime: 'application/octet-stream',
        lastModified: 0,
        blockSize: 8,
        blocks: Math.ceil(f.size / 8),
        fileDigest: digests[idx]!,
      })),
      totalSize: files.reduce((total, f) => total + f.size, 0),
    };
    const j = await journalFor(
      h.store,
      h.files,
      files.map((f) => [f.name, f.size]),
      [3, 2, 1, 0],
      m,
    );
    // a.bin: valid wasm checkpoint (restored). b.bin: foreign-format checkpoint (rehash).
    // c.bin: old journal, no checkpoint (rehash). d.bin: not started (no seed).
    let advanced = advanceJournal(j, 0, 3, 3_000, {
      format: DIGEST_CHECKPOINT_FORMAT_HASH_WASM,
      committedBlocks: 3,
      committedBytes: 24,
      state: bytesToHex(digestStateFor(h, whole)),
    });
    advanced = advanceJournal(advanced, 1, 2, 3_000, {
      format: 'sha256-go-v1',
      committedBlocks: 2,
      committedBytes: 16,
      state: '00'.repeat(108),
    });
    h.store.journals.set(TRANSFER_ID, await encodeJournal(advanced));

    h.advance(DURABLE_LEASE_TTL_MS + 1);
    const d = armAuth(h.makeDestination());

    const keys = await deriveTransferKeys(new Uint8Array(32).fill(7));
    const frames: Uint8Array[] = [];
    let ctr = 0;
    const push = async (header: FrameHeaderInput, payload: Uint8Array) => {
      frames.push(await seal(keys.o2j, ctr++, header, payload));
    };
    const ctrl = (type: FrameType, msg: Parameters<typeof encodeControl>[0]) =>
      push(
        { version: FRAME_VERSION, type, flags: 0, fileIdx: 0, blockIdx: 0, frameOff: 0 },
        encodeControl(msg),
      );
    await ctrl(FrameType.Manifest, m);
    // The sender learned the high-water marks from the ResumeState control: it sends only
    // the blocks the receiver lacks, in file order — b.bin 2, c.bin 1..2, d.bin 0.
    // a.bin streams nothing.
    for (const [fileIdx, startBlock] of [
      [1, 2],
      [2, 1],
      [3, 0],
    ] as Array<[number, number]>) {
      const f = files[fileIdx]!;
      for (let blk = startBlock; blk * 8 < f.size; blk++) {
        const start = blk * 8;
        const end = Math.min(start + 8, f.size);
        const block = f.data.subarray(start, end);
        for (let off = 0; off < block.length; off += 4) {
          const frag = block.subarray(off, Math.min(off + 4, block.length));
          const last = off + frag.length === block.length;
          await push(
            {
              version: FRAME_VERSION,
              type: FrameType.BlockData,
              flags: last ? 1 : 0,
              fileIdx,
              blockIdx: blk,
              frameOff: off,
            },
            frag,
          );
        }
        await ctrl(FrameType.BlockHash, {
          type: FrameType.BlockHash,
          fileIdx,
          blockIdx: blk,
          sha256: bytesToHex(await sha256(block)),
        });
      }
    }
    // One-shot terminal Complete carrying the canonical file-set completion digest.
    await ctrl(FrameType.Complete, {
      type: FrameType.Complete,
      fileDigest: bytesToHex(await sha256(new TextEncoder().encode(digests.join('\n')))),
    });

    const receiverOpts: ConstructorParameters<typeof TransferReceiver>[0] = {
      send: () => void Promise.resolve(),
      sendDir: keys.j2o,
      recvDir: keys.o2j,
      sendCounterStart: 0,
      recvCounterStart: 0,
      createDigest: h.digest,
      destination: d,
      onManifestSet: async () => {
        const state = d.resumeStateFor();
        if (state) receiverOpts.resume = state;
      },
    };
    const receiver = new TransferReceiver(receiverOpts);
    for (const f of frames) receiver.handle(f);
    const result = await receiver.done;

    // Every file verified end-to-end; the durable store finalized (journal + lease gone).
    expect(result.digests).toEqual(digests);
    expect((await h.store.loadJournal(TRANSFER_ID)).kind).toBe('none');
    const zipBytes = h.files.outputs.get(`sendbeam/durable/${TRANSFER_ID}/__receive.zip`);
    expect(zipBytes).toBeDefined();
    const dir = mkdtempSync(join(tmpdir(), 'sendbeam-durable-resume-'));
    try {
      const path = join(dir, 'resume.zip');
      writeFileSync(path, zipBytes!);
      expect(execFileSync('unzip', ['-t', path], { encoding: 'utf8' })).toContain('No errors');
      for (const f of files) {
        expect(execFileSync('unzip', ['-p', path, f.name])).toEqual(Buffer.from(f.data));
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('stale tail beyond the checkpoint is truncated and re-transferred on resume', async () => {
    const h = await harness();
    await journalFor(h.store, h.files, [['a.bin', 24]], [1]);
    // Simulate a crash between write and journal commit: durable data beyond the checkpoint.
    h.files.data.set('a.bin', new Uint8Array(16).fill(9));

    h.advance(DURABLE_LEASE_TTL_MS + 1);
    const d = armAuth(h.makeDestination());
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
    const d = armAuth(h.makeDestination());
    await expect(d.prepare(manifest([['a.bin', 24]]))).rejects.toThrow(/missing or truncated/);
    // Nothing was deleted.
    expect((await h.store.loadJournal(TRANSFER_ID)).kind).toBe('ok');

    // Truncated variant.
    await journalFor(h.store, h.files, [['a.bin', 24]], [2]);
    h.files.data.set('a.bin', new Uint8Array(4));
    h.advance(DURABLE_LEASE_TTL_MS + 1);
    const d2 = armAuth(h.makeDestination());
    await expect(d2.prepare(manifest([['a.bin', 24]]))).rejects.toThrow(/missing or truncated/);
  });

  it('fresh session cannot skip verified blocks merely because transferId + fingerprint match (V13-PR08)', async () => {
    const h = await harness();
    // An interrupted transfer leaves a journal with verified committed progress.
    await journalFor(h.store, h.files, [['a.bin', 24]], [2]);
    h.advance(DURABLE_LEASE_TTL_MS + 1);

    // A FRESH session (no resumeAttempt, no preamble) presents the SAME transferId and
    // the SAME manifest fingerprint. The gate must fail closed: nothing received, nothing
    // deleted, the journal untouched — old verified progress is never reused.
    const fresh = h.makeDestination();
    await expect(fresh.prepare(manifest([['a.bin', 24]]))).rejects.toThrow(
      /requires authenticated resume/,
    );
    expect((await h.store.loadJournal(TRANSFER_ID)).kind).toBe('ok');
    expect(h.files.data.get('a.bin')?.length).toBe(16); // verified prefix intact
    expect(fresh.durableMeta()?.resumed).toBe(true);

    // The gate does NOT fire for a genuinely fresh transfer (no journal for that id): a
    // brand-new id is a fresh sender, and its fresh journal has no verified progress at
    // risk — matching the driver's fresh-path semantics.
    const otherId = 'b'.repeat(32);
    const freshM: Manifest = { ...manifest([['a.bin', 24]]), transferId: otherId };
    const freshTransfer = h.makeDestination();
    await freshTransfer.prepare(freshM);
    expect(freshTransfer.durableMeta()?.resumed).toBe(false);
    await freshTransfer.abort();
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

    // A retry (same or another tab) acquires immediately and resumes from the checkpoint;
    // the driver arms an authenticated-resume attempt for the interrupted journal.
    const retry = armAuth(h.makeDestination());
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
      createDigest: h.digest,
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

    const d = armAuth(h.makeDestination());
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

  it('attaches the transfer-scoped resume credential once the manifest is bound to the journal (V13-PR07)', async () => {
    const h = await harness();
    const d = h.makeDestination();
    const m = manifest([['a.bin', 8]]);
    await d.prepare(m);
    const resumeRoot = new Uint8Array(32).fill(7);
    await d.attachResumeSecret(m, resumeRoot);
    const stored = h.store.journals.get(TRANSFER_ID)!;
    const obj = JSON.parse(new TextDecoder().decode(stored)) as { resumeSecret?: unknown };
    expect(obj.resumeSecret).toBeDefined();
    const envelope = obj.resumeSecret as { version: number; value: string };
    expect(envelope.version).toBe(1);
    expect(envelope.value).toMatch(/^[0-9a-f]{64}$/);
    // Re-attaching after the original-session credential is persisted never replaces it.
    const before = JSON.parse(new TextDecoder().decode(h.store.journals.get(TRANSFER_ID)!));
    await d.attachResumeSecret(m, new Uint8Array(32).fill(9));
    const after = JSON.parse(new TextDecoder().decode(h.store.journals.get(TRANSFER_ID)!));
    expect(after.resumeSecret).toEqual(before.resumeSecret);
    await d.abort();
  });

  it('never fabricates a credential for a resumed (pre-existing) journal, but a fresh journal gets one (BLOCKER 1)', async () => {
    const h = await harness();
    const m = manifest([['a.bin', 8]]);
    // Session 1: a fresh journal is created for this transfer (no credential yet).
    const first = h.makeDestination();
    await first.prepare(m);
    expect(first.durableMeta()?.resumed).toBe(false);
    await first.abort();

    // Session 2: a later receive loads the journal as existing/resumed state and attaches
    // with a DIFFERENT resume root. It must leave the journal without a credential. The
    // driver arms an authenticated-resume attempt before prepare may reuse the journal.
    const second = armAuth(h.makeDestination());
    await second.prepare(m);
    expect(second.durableMeta()?.resumed).toBe(true);
    await second.attachResumeSecret(m, new Uint8Array(32).fill(0x42));
    const loaded = await h.store.loadJournal(TRANSFER_ID);
    expect(loaded.kind).toBe('ok');
    if (loaded.kind !== 'ok') return;
    expect(loaded.journal.resumeSecret).toBeUndefined();
    await second.abort();

    // Session 3: a fresh journal (created in THIS session) MAY receive the credential.
    const fresh = h.makeDestination();
    const freshId = 'b'.repeat(32);
    const fm = { ...m, transferId: freshId };
    await fresh.prepare(fm);
    await fresh.attachResumeSecret(fm, new Uint8Array(32).fill(0x42));
    const freshLoaded = await h.store.loadJournal(freshId);
    expect(freshLoaded.kind).toBe('ok');
    if (freshLoaded.kind !== 'ok') return;
    expect(freshLoaded.journal.resumeSecret).toBeDefined();
    await fresh.abort();
  });

  it('refuses to attach a resume credential to a journal that does not match the manifest (V13-PR07)', async () => {
    const h = await harness();
    const d = h.makeDestination();
    const m = manifest([['a.bin', 8]]);
    await d.prepare(m);
    const other = manifest([['b.bin', 8]]);
    await expect(d.attachResumeSecret(other, new Uint8Array(32).fill(7))).rejects.toThrow(
      /does not match the authenticated manifest/,
    );
    // Nothing was persisted.
    const obj = JSON.parse(new TextDecoder().decode(h.store.journals.get(TRANSFER_ID)!)) as {
      resumeSecret?: unknown;
    };
    expect(obj.resumeSecret).toBeUndefined();
    await d.abort();
  });

  it('finalize failure keeps journal + partials and releases the lease for an immediate retry', async () => {
    const h = await harness();
    const d = h.makeDestination();
    const m = manifest([
      ['folder/a.bin', 10],
      ['folder/b.bin', 10],
    ]);
    await d.prepare(m);
    const a = await d.open(m.files[0]!);
    await a.write(0, new Uint8Array(8));
    await a.write(8, new Uint8Array([9, 10]));
    await a.close();
    const b = await d.open(m.files[1]!);
    await b.write(0, new Uint8Array(8));
    await b.write(8, new Uint8Array([9, 10]));
    await b.close();

    // ZIP assembly fails: finalize must fail closed.
    h.files.failOutput = true;
    await expect(d.close()).rejects.toThrow(/output write failed/);
    h.files.failOutput = false;

    // Journal + recoverable partials remain usable (no journal removed prematurely).
    expect((await h.store.loadJournal(TRANSFER_ID)).kind).toBe('ok');
    expect(h.files.data.size).toBe(2);
    // The active lease was released promptly instead of lingering for the 120s stale TTL.
    expect(h.store.leases.has(TRANSFER_ID)).toBe(false);

    // A retry acquires immediately and finalizes successfully (authenticated resume armed
    // by the driver for the interrupted journal).
    const retry = armAuth(h.makeDestination());
    await retry.prepare(m);
    expect(retry.durableMeta()?.resumed).toBe(true);
    const ra = await retry.open(m.files[0]!);
    await ra.close();
    const rb = await retry.open(m.files[1]!);
    await rb.close();
    await retry.close();
    expect((await h.store.loadJournal(TRANSFER_ID)).kind).toBe('none');
    expect(h.files.outputs.has(`sendbeam/durable/${TRANSFER_ID}/__receive.zip`)).toBe(true);
  });

  it('failed metadata cleanup after a successful ZIP keeps journal + partials and releases the lease', async () => {
    const h = await harness();
    const d = h.makeDestination();
    const m = manifest([
      ['folder/a.bin', 10],
      ['folder/b.bin', 10],
    ]);
    await d.prepare(m);
    const a = await d.open(m.files[0]!);
    await a.write(0, new Uint8Array(8));
    await a.write(8, new Uint8Array([9, 10]));
    await a.close();
    const b = await d.open(m.files[1]!);
    await b.write(0, new Uint8Array(8));
    await b.write(8, new Uint8Array([9, 10]));
    await b.close();

    h.store.failDiscard = true;
    await expect(d.close()).rejects.toThrow(/discard failed/);
    h.store.failDiscard = false;

    // The journal was not removed, the partials were not consumed, and the lease is free.
    expect((await h.store.loadJournal(TRANSFER_ID)).kind).toBe('ok');
    expect(h.files.data.size).toBe(2);
    expect(h.store.leases.has(TRANSFER_ID)).toBe(false);

    // Immediate retry acquires and completes finalization idempotently (authenticated
    // resume armed by the driver for the interrupted journal).
    const retry = armAuth(h.makeDestination());
    await retry.prepare(m);
    expect(retry.durableMeta()?.resumed).toBe(true);
    const ra = await retry.open(m.files[0]!);
    await ra.close();
    const rb = await retry.open(m.files[1]!);
    await rb.close();
    await retry.close();
    expect((await h.store.loadJournal(TRANSFER_ID)).kind).toBe('none');
  });

  it('failed single-file finalize keeps the partial and releases the lease; success removes resume metadata', async () => {
    const h = await harness();
    const d = h.makeDestination();
    const m = manifest([['a.bin', 8]]);
    await d.prepare(m);
    const sink = await d.open(m.files[0]!);
    await sink.write(0, new Uint8Array(8));
    await sink.close();

    h.store.failDiscard = true;
    await expect(d.close()).rejects.toThrow(/discard failed/);
    h.store.failDiscard = false;

    // Partial data remains recoverable and the journal is intact.
    expect(h.files.data.get('a.bin')).toEqual(new Uint8Array(8));
    expect((await h.store.loadJournal(TRANSFER_ID)).kind).toBe('ok');
    expect(h.store.leases.has(TRANSFER_ID)).toBe(false);

    // Immediate retry: acquire, finalize, and the resume metadata (journal + lease) is gone.
    // (Authenticated resume armed by the driver for the interrupted journal.)
    const retry = armAuth(h.makeDestination());
    await retry.prepare(m);
    expect(retry.durableMeta()?.resumed).toBe(true);
    const resumed = await retry.open(m.files[0]!);
    await resumed.close();
    await retry.close();
    expect((await h.store.loadJournal(TRANSFER_ID)).kind).toBe('none');
    expect(h.store.leases.has(TRANSFER_ID)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// createBrowserDestination wrapper (V13-PR08 Blocker 1): the wrapper must retain the
// pre-manifest resume-auth state (expected interrupted journal id + session authorization)
// and apply it to the lazily-constructed inner DurableDestination strictly before
// prepare(), or the auth gate is silently dropped and an existing journal's verified
// progress could be reused unauthenticated.
// ---------------------------------------------------------------------------

describe('createBrowserDestination wrapper (V13-PR08 Blocker 1)', () => {
  it('existing journal + expected id + NO auth refuses progress and keeps everything', async () => {
    const h = await harness();
    const m = manifest([['a.bin', 24]]);
    await journalFor(h.store, h.files, [['a.bin', 24]], [2], m);
    h.advance(DURABLE_LEASE_TTL_MS + 1); // stale lease → takeover, so the auth gate is what refuses
    const wrapper = createBrowserDestination({ kind: 'auto' }, h.digest, {
      files: h.files,
      store: h.store,
      now: h.now,
      renewMs: 0,
      ensureSpace: async () => {},
    });
    wrapper.expectResumeFor?.(TRANSFER_ID);
    await expect(wrapper.prepare(m)).rejects.toThrow(/not authenticated/);
    // Nothing was received or deleted: journal + partials survive the refusal. The lease
    // acquired during prepare is released by the fail-closed gate so a later authenticated
    // attempt can acquire it immediately (never lingering for the stale TTL).
    expect((await h.store.loadJournal(TRANSFER_ID)).kind).toBe('ok');
    expect(h.files.data.get('a.bin')?.length).toBe(16);
    expect(h.store.leases.has(TRANSFER_ID)).toBe(false);
  });

  it('existing journal + successful auth state reuses the checkpoint', async () => {
    const h = await harness();
    const m = manifest([['a.bin', 24]]);
    await journalFor(h.store, h.files, [['a.bin', 24]], [2], m);
    h.advance(DURABLE_LEASE_TTL_MS + 1);
    const wrapper = createBrowserDestination({ kind: 'auto' }, h.digest, {
      files: h.files,
      store: h.store,
      now: h.now,
      renewMs: 0,
      ensureSpace: async () => {},
    });
    wrapper.expectResumeFor?.(TRANSFER_ID);
    wrapper.authorizeResume?.();
    await wrapper.prepare(m);
    expect(wrapper.durableMeta?.()?.resumed).toBe(true);
    // The authenticated checkpoint surfaces immediately: haveBlocks 2, seed digest covering
    // the persisted prefix — before any new block arrives.
    const resume = wrapper.resumeStateFor?.(m);
    expect(resume?.transferId).toBe(TRANSFER_ID);
    expect(resume?.files.get(0)?.haveBlocks).toBe(2);
  });

  it('wrong expected transfer id refuses reuse of that journal', async () => {
    const h = await harness();
    const m = manifest([['a.bin', 24]]);
    await journalFor(h.store, h.files, [['a.bin', 24]], [2], m);
    h.advance(DURABLE_LEASE_TTL_MS + 1);
    const wrapper = createBrowserDestination({ kind: 'auto' }, h.digest, {
      files: h.files,
      store: h.store,
      now: h.now,
      renewMs: 0,
      ensureSpace: async () => {},
    });
    // The user selected a DIFFERENT interrupted transfer; authorization for it must not
    // authorize this journal's progress.
    wrapper.expectResumeFor?.('f'.repeat(32));
    wrapper.authorizeResume?.();
    // The session authenticated continuity with the SELECTED journal only; this journal's
    // verified progress is never reused.
    await expect(wrapper.prepare(m)).rejects.toThrow(/requires authenticated resume/);
    expect((await h.store.loadJournal(TRANSFER_ID)).kind).toBe('ok');
  });

  it('fresh journal remains ordinary — no auth, no resume state, resume hooks inert', async () => {
    const h = await harness();
    const m = manifest([['a.bin', 24]]);
    const wrapper = createBrowserDestination({ kind: 'auto' }, h.digest, {
      files: h.files,
      store: h.store,
      now: h.now,
      renewMs: 0,
      ensureSpace: async () => {},
    });
    // No resume attempt armed: a fresh receive must not need authorization or a seed.
    await wrapper.prepare(m);
    expect(wrapper.durableMeta?.()?.resumed).toBe(false);
    expect(wrapper.resumeStateFor?.(m)).toBeUndefined();
    expect((await h.store.loadJournal(TRANSFER_ID)).kind).toBe('ok');
  });

  it('authorization cannot leak to another destination/transfer', async () => {
    const h = await harness();
    const m = manifest([['a.bin', 24]]);
    await journalFor(h.store, h.files, [['a.bin', 24]], [2], m);
    h.advance(DURABLE_LEASE_TTL_MS + 1);
    const authorized = createBrowserDestination({ kind: 'auto' }, h.digest, {
      files: h.files,
      store: h.store,
      now: h.now,
      renewMs: 0,
      ensureSpace: async () => {},
    });
    authorized.expectResumeFor?.(TRANSFER_ID);
    authorized.authorizeResume?.();
    await authorized.prepare(m); // this session authenticated → reuses the checkpoint
    // Let the authorized session's lease lapse (its renew timer is disabled).
    h.advance(DURABLE_LEASE_TTL_MS + 1);
    // A SECOND wrapper for the same journal, in a fresh (unauthorized) session, must still
    // refuse — authorization is per-destination/session, never global storage state.
    const fresh = createBrowserDestination({ kind: 'auto' }, h.digest, {
      files: h.files,
      store: h.store,
      now: h.now,
      renewMs: 0,
      ensureSpace: async () => {},
    });
    fresh.expectResumeFor?.(TRANSFER_ID);
    await expect(fresh.prepare(m)).rejects.toThrow(/not authenticated/);
  });

  it('an armed journal resume cannot silently target a direct-file or direct-directory save', async () => {
    const h = await harness();
    const m = manifest([['a.bin', 24]]);
    const fileWrapper = createBrowserDestination(
      { kind: 'direct-file', handle: {} as FileSystemFileHandle },
      h.digest,
    );
    fileWrapper.expectResumeFor?.(TRANSFER_ID);
    await expect(fileWrapper.prepare(m)).rejects.toThrow(/cannot target a single-file save/);
    const dirWrapper = createBrowserDestination(
      { kind: 'direct-directory', handle: {} as FileSystemDirectoryHandle },
      h.digest,
    );
    dirWrapper.expectResumeFor?.(TRANSFER_ID);
    await expect(dirWrapper.prepare(m)).rejects.toThrow(/cannot target a folder save/);
    // Nothing was written or deleted.
    expect(h.store.journals.size).toBe(0);
    expect(h.files.data.size).toBe(0);
  });
});
