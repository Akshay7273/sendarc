/**
 * Browser durable receive destination (V13-PR03) — the browser twin of the CLI's
 * DurableDestination (apps/cli/internal/transfer/durable.go). It runs inside the transfer
 * worker so it can use `FileSystemSyncAccessHandle` where supported; verified blocks land in
 * OPFS partials, each checkpoint advances only after the data is flushed, and the journal
 * (IndexedDB) is the single source of resumable progress.
 *
 * Durability ordering (ADR 0004): verify (wire layer) → write → flush → atomic journal
 * checkpoint → the wire ack. `Sink.write` resolves only after write+flush+commit, so the
 * receiver's ack always follows a committed checkpoint.
 *
 * The async fallback (browsers without sync access handles) is honest about its limits: the
 * stream can only be flushed at close, so a file's checkpoint advances only after its whole
 * stream is closed — never block-by-block.
 */

import {
  DIGEST_CHECKPOINT_FORMAT_HASH_WASM,
  RESUME_AUTH_VERSION,
  TransferError,
  bytesToHex,
  deriveResumeSecret,
  encodeResumeSecretEnvelope,
  hexToBytes,
  manifestFingerprint,
  normalizeTransferPath,
  sha256,
  utf8,
  type Digest,
  type DigestStateSink,
  type DurableJournal,
  type FileEntry,
  type JournalDigestCheckpoint,
  type JournalIdentity,
  type Manifest,
  type ReceiverResumeFile,
  type ReceiverResumeState,
  type Sink,
} from '@sendbeam/protocol';
import type { BrowserDestination, DestinationOutput } from './sink.js';
import type {
  DurableFiles,
  DurableJournalStore,
  PartialWriter,
  WritableFileLike,
} from './durable-store.js';
import { webDestinationIdentity } from './durable-store.js';
import type { Sha256DigestFactory } from './digest.js';
import {
  centralHeader,
  crc32Update,
  dataDescriptor,
  endOfCentralDirectory,
  localHeader,
  type ZipEntry,
} from './zip.js';

/** Metadata the host needs for lease release and the Keep/Discard failure surface. */
export interface DurableMeta {
  transferId: string;
  ownerId: string;
  resumed: boolean;
  committedBytes: number;
  totalBytes: number;
}

export interface DurableDestinationOptions {
  createDigest: Sha256DigestFactory;
  files: DurableFiles;
  store: DurableJournalStore;
  /** Injectable clock (unix ms); tests use a fixed clock with no sleeps. */
  now?(): number;
  /** Lease-renewal timer interval; 0 disables the timer (tests). Default 30s. */
  renewMs?: number;
  /** Quota preflight; defaults to a navigator.storage.estimate check. */
  ensureSpace?(requiredBytes: number): Promise<void>;
}

const DURABLE_LEASE_RENEW_MS = 30_000;
/** Files whose manifest path collides with the browser storage namespace fail closed. */
const STORAGE_NAMESPACE = 'sendbeam';

export class DurableDestination implements BrowserDestination {
  private readonly createDigest: Sha256DigestFactory;
  private readonly files: DurableFiles;
  private readonly store: DurableJournalStore;
  private readonly now: () => number;
  private readonly renewMs: number;
  private readonly ensureSpace: (requiredBytes: number) => Promise<void>;
  private readonly ownerId = randomOwnerId();

  private prepared = false;
  private closed = false;
  private aborted = false;
  private manifest: Manifest | undefined;
  private journal: DurableJournal | undefined;
  private transferId = '';
  private resumed = false;
  // V13-PR08: an explicit authenticated-resume attempt pre-selects its interrupted journal;
  // until resume-auth succeeds in THIS session, that journal's progress is never trusted.
  private expectResume = '';
  private resumeAuthorized = false;
  private sync = true;
  private readonly sinks = new Map<number, DurableFileSink>();
  private renewTimer: ReturnType<typeof setInterval> | undefined;
  private resumeState: ReceiverResumeState | undefined;
  private output: DestinationOutput | undefined;

  constructor(options: DurableDestinationOptions) {
    this.createDigest = options.createDigest;
    this.files = options.files;
    this.store = options.store;
    this.now = options.now ?? (() => Date.now());
    this.renewMs = options.renewMs ?? DURABLE_LEASE_RENEW_MS;
    this.ensureSpace =
      options.ensureSpace ?? ((required: number) => ensureSpaceInBrowser(required));
  }

  /**
   * V13-PR08: mark this receive as an explicit authenticated-resume attempt for the
   * interrupted journal `transferId` (the user pre-selected it locally). Until resume-auth
   * succeeds in this session, the journal's verified progress is never reused.
   */
  expectResumeFor(transferId: string): void {
    this.expectResume = transferId;
  }

  /**
   * V13-PR08: records that mutual resume-auth completed in THIS session; only then may the
   * pre-selected interrupted journal's verified progress be reused. A fresh receive without
   * a pre-selected journal never needs it.
   */
  authorizeResume(): void {
    this.resumeAuthorized = true;
  }

  /** Revalidate the manifest, load/create the journal, acquire the lease, build the resume seed. */
  async prepare(manifest: Manifest): Promise<void> {
    if (this.prepared) throw new TransferError('sink_error', 'durable destination prepared twice');
    this.prepared = true;
    if (manifest.transferId === undefined) {
      throw new TransferError(
        'sink_error',
        'durable destination requires a manifest with a transfer id',
      );
    }
    for (const file of manifest.files) {
      if (file.name === STORAGE_NAMESPACE || file.name.startsWith(`${STORAGE_NAMESPACE}/`)) {
        throw new TransferError(
          'sink_error',
          `manifest path ${file.name} collides with the ${STORAGE_NAMESPACE} storage area`,
        );
      }
    }
    this.manifest = manifest;
    this.transferId = manifest.transferId;

    const loaded = await this.store.loadJournal(this.transferId);
    if (loaded.kind === 'corrupt') {
      throw new TransferError(
        'sink_error',
        `durable journal for ${this.transferId} is unusable (${loaded.error}); nothing was deleted — discard it to reset`,
      );
    }
    if (loaded.kind === 'none') {
      const destination = await webDestinationIdentity(origin());
      const source = await unboundSourceIdentity();
      const journal = await this.store.createJournal(
        this.transferId,
        manifest,
        source,
        destination,
        this.now(),
      );
      this.journal = journal;
    } else {
      const journal = loaded.journal;
      // Revalidate every user-editable claim against the authenticated manifest (ADR 0004 §3).
      const fingerprint = await manifestFingerprint(manifest);
      if (journal.manifestFingerprint !== fingerprint) {
        throw new TransferError(
          'sink_error',
          `journal ${this.transferId} does not match the authenticated manifest; refusing to guess — discard it`,
        );
      }
      const destination = await webDestinationIdentity(origin());
      if (
        journal.destinationIdentity.version !== destination.version ||
        journal.destinationIdentity.value !== destination.value
      ) {
        throw new TransferError(
          'sink_error',
          'journal was created for a different destination; refusing to resume — discard it',
        );
      }
      this.journal = journal;
      this.resumed = true;
    }

    // Atomic test-and-set lease: concurrent tabs and stale holders fail closed; an expired
    // lease is taken over deterministically. Checked BEFORE the resume-auth gate so a live
    // concurrent receiver reports the true conflict instead of a misleading auth error; both
    // paths fail closed and never reuse verified progress.
    const lease = await this.store.acquireLease(this.transferId, this.ownerId, this.now());
    if (lease.kind === 'contended') {
      throw new TransferError(
        'sink_error',
        'another window is already receiving this transfer; close it before retrying',
      );
    }

    // V13-PR08 (review Blocker 2): an interrupted journal's verified progress may be reused
    // ONLY for the journal THIS session authenticated a resume for. Successful auth for A
    // must never authorize an existing journal B, and authorization with NO selected
    // journal authorizes NOTHING. A fresh rendezvous authenticates the NEW session only;
    // it does not prove continuity with the original transfer peer. Failing closed here is
    // what makes a fresh session unable to skip old blocks merely because the transfer id +
    // fingerprint match. A fresh journal created this session has no verified progress at
    // risk and is never gated.
    const authorizedForThisJournal =
      this.resumeAuthorized && this.expectResume !== '' && this.expectResume === this.transferId;
    if (this.resumed && !authorizedForThisJournal) {
      // The lease acquired above must not linger for a stale TTL after a fail-closed gate;
      // release it so a later authenticated resume attempt can acquire immediately.
      await this.store.releaseLease(this.transferId, this.ownerId).catch(() => {});
      if (this.expectResume !== '' && this.expectResume === this.transferId) {
        throw new TransferError(
          'sink_error',
          `resume of ${this.transferId} was not authenticated in this session; refusing to reuse its verified progress — nothing was received or deleted. Start an authenticated resume so both peers authenticate first`,
        );
      }
      if (this.resumeAuthorized && this.expectResume !== '') {
        throw new TransferError(
          'sink_error',
          `this session authenticated resume for ${this.expectResume}, not ${this.transferId}; refusing to reuse ${this.transferId}'s verified progress — nothing was received or deleted. Start an authenticated resume for that transfer instead`,
        );
      }
      if (this.resumeAuthorized) {
        throw new TransferError(
          'sink_error',
          `this session authorized resume without selecting an interrupted journal; refusing to reuse ${this.transferId}'s verified progress — nothing was received or deleted`,
        );
      }
      throw new TransferError(
        'sink_error',
        `transfer ${this.transferId} has verified partial data kept from an interrupted transfer; resuming it requires authenticated resume — nothing was received or deleted`,
      );
    }

    if (this.resumed) {
      await this.buildResumeState();
    }

    // Decide the write path once: sync access handles in this worker context, else the
    // honest async fallback that only checkpoints at file close.
    this.sync = await this.files.probeSync(this.transferId);

    const total = manifest.totalSize;
    const committed = this.committedBytesTotal();
    await this.ensureSpace(Math.max(0, total - committed));

    if (this.renewMs > 0) {
      this.renewTimer = setInterval(() => {
        void this.store.renewLease(this.transferId, this.ownerId, this.now()).catch(() => {});
      }, this.renewMs);
    }
  }

  /** The resume seed the wire receiver applies after the manifest matches the journal. */
  resumeStateFor(): ReceiverResumeState | undefined {
    return this.resumeState;
  }

  /**
   * Derive the transfer-scoped resume credential from the original session resume root and
   * persist it into the receive journal (V13-PR07). Runs only after the authenticated
   * manifest validated and bound to the journal.
   *
   * Provenance (V13-PR07 security review, Blocker 1): the credential may be derived only
   * for a journal created during THIS manifest/session (`prepare` did not load one). A
   * journal loaded as existing/resumed state must NEVER receive a credential fabricated
   * from a later session master: an existing credential is preserved exactly, a missing one
   * stays missing.
   */
  async attachResumeSecret(manifest: Manifest, resumeRoot: Uint8Array): Promise<void> {
    const journal = this.journal;
    if (!journal || manifest.transferId !== journal.transferId) {
      throw new TransferError(
        'sink_error',
        `no journal for ${manifest.transferId ?? '(no transfer id)'}; refusing to attach a resume credential`,
      );
    }
    const fingerprint = await manifestFingerprint(manifest);
    // The binding is validated FIRST so a manifest that does not match the journal fails
    // closed even when a credential is already persisted (fail-closed ordering).
    if (journal.manifestFingerprint !== fingerprint) {
      throw new TransferError(
        'sink_error',
        `journal ${journal.transferId} does not match the authenticated manifest; refusing to attach a resume credential`,
      );
    }
    if (journal.resumeSecret !== undefined) {
      return; // original-session credential already persisted; never replace it
    }
    if (this.resumed) {
      // The journal predates this session (loaded, not created): a missing credential stays
      // missing — never fabricated from a later session master. Old partials are never
      // deleted and the journal remains usable for its existing capabilities.
      return;
    }
    const secret = await deriveResumeSecret(
      resumeRoot,
      RESUME_AUTH_VERSION,
      journal.transferId,
      fingerprint,
    );
    // The lease-guarded store operation is a compare-and-swap: it snapshots the current
    // journal, then in one readwrite transaction verifies lease ownership and byte-compares
    // the live journal against that snapshot before writing, so newer committed progress
    // under the same owner is never overwritten and a lost lease fails closed.
    this.journal = await this.store.attachResumeSecret(
      journal.transferId,
      encodeResumeSecretEnvelope(secret),
      this.ownerId,
      this.now(),
    );
  }

  async open(file: FileEntry): Promise<Sink> {
    if (this.closed || this.aborted) {
      throw new TransferError('sink_error', 'durable destination is closed');
    }
    const journal = this.journal;
    const manifest = this.manifest;
    if (!journal || !manifest) {
      throw new TransferError('sink_error', 'durable destination opened before prepare');
    }
    const state = journal.files[file.idx];
    if (!state) throw new TransferError('sink_error', `no journal entry for file ${file.idx}`);
    const rel = normalizeTransferPath(file.name);
    const committedBytes = Math.min(state.committedBlocks * state.blockSize, state.size);
    const writer = await this.files.openWriter(this.transferId, rel, committedBytes, this.sync);
    const sink = new DurableFileSink({
      destination: this,
      fileIdx: file.idx,
      writer,
      sync: this.sync,
      blockSize: state.blockSize,
      blocks: state.blocks,
      startBlocks: state.committedBlocks,
    });
    this.sinks.set(file.idx, sink);
    return sink;
  }

  /**
   * Finalize — runs only after the wire receiver verified the whole transfer. The journal
   * (and lease) are removed only after the deliverable is fully produced; any failure keeps
   * every partial and the journal intact for retry or explicit discard, and releases the lease
   * promptly so a retry can acquire immediately instead of waiting out the stale TTL.
   */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.clearRenew();
    if (this.aborted) return;
    const journal = this.journal;
    const manifest = this.manifest;
    if (!journal || !manifest) return;
    try {
      // Whole-transfer verification already happened (the receiver calls close() after
      // onComplete); double-check no checkpoint lags so finalization is never partial.
      for (let i = 0; i < journal.files.length; i++) {
        const f = journal.files[i]!;
        if (f.committedBlocks !== f.blocks) {
          throw new TransferError('sink_error', `file ${i} not fully committed at finalize`);
        }
      }
      if (manifest.files.length === 1) {
        // The verified partial IS the deliverable; the host reads it and cleans it up.
        // The journal is removed only after whole-transfer verification, then the output is
        // advertised — never before.
        const file = manifest.files[0]!;
        const key = this.files.partialKey(this.transferId, normalizeTransferPath(file.name));
        await this.store.discard(this.transferId);
        this.output = { kind: 'opfs', key, name: file.name, mime: file.mime };
        return;
      }
      // Multi-file: assemble a store-only ZIP from the verified partials, then remove the
      // journal and the consumed partials — never before the ZIP is fully written and closed.
      const zip = await this.buildZip();
      await this.store.discard(this.transferId);
      // Best-effort cleanup: the ZIP is the verified deliverable, so leftover partials after a
      // removal failure are harmless orphans rather than a reason to fail a done transfer.
      for (const file of manifest.files) {
        await this.files
          .removePartial(this.transferId, normalizeTransferPath(file.name))
          .catch(() => {});
      }
      this.output = { kind: 'opfs', key: zip.key, name: zip.name, mime: 'application/zip' };
    } catch (e) {
      // Finalization failed. The journal + recoverable partials must stay usable (they are the
      // only resumable copy) and the active lease is released promptly rather than forcing the
      // 120s stale TTL, so a retry — same or another tab — acquires immediately. Any still-open
      // writers are aborted so no handles survive a failed finalize. Nothing is deleted on a
      // failure path and no output is advertised.
      await this.releaseLease();
      for (const sink of this.sinks.values()) {
        await sink.abort().catch(() => {});
      }
      throw e;
    }
  }

  /**
   * Abort deliberately KEEPS the journal and partials at their last durable checkpoint (they
   * are the only resumable copy; ADR 0004 §8) and releases the lease so a retry — same or
   * other tab — can acquire it immediately instead of waiting out the TTL.
   */
  async abort(): Promise<void> {
    if (this.aborted) return;
    this.aborted = true;
    this.clearRenew();
    for (const sink of this.sinks.values()) {
      await sink.abort().catch(() => {});
    }
    if (!this.closed) await this.releaseLease();
  }

  result(): DestinationOutput | undefined {
    return this.output;
  }

  durableMeta(): DurableMeta | undefined {
    if (!this.journal) return undefined;
    return {
      transferId: this.transferId,
      ownerId: this.ownerId,
      resumed: this.resumed,
      committedBytes: this.committedBytesTotal(),
      totalBytes: this.manifest?.totalSize ?? 0,
    };
  }

  // -------------------------------------------------------------------------

  private committedBytesTotal(): number {
    const journal = this.journal;
    if (!journal) return 0;
    let total = 0;
    for (const file of journal.files) {
      total += Math.min(file.committedBlocks * file.blockSize, file.size);
    }
    return total;
  }

  /**
   * Advance one file's checkpoint after its data is flushed; the only journal mutation.
   * `digestState` (V13-PR05), when non-null, is the serialized digest state covering
   * exactly these blocks and is persisted atomically with the checkpoint; a null state
   * clears the file's stale checkpoint (it could not cover the new high-water mark).
   */
  async commitBlocks(
    fileIdx: number,
    blocks: number,
    digestState: Uint8Array | null,
  ): Promise<void> {
    const journal = this.journal;
    if (!journal) throw new TransferError('sink_error', 'durable destination is not prepared');
    let checkpoint: JournalDigestCheckpoint | undefined;
    if (digestState) {
      const state = journal.files[fileIdx]!;
      checkpoint = {
        format: DIGEST_CHECKPOINT_FORMAT_HASH_WASM,
        committedBlocks: blocks,
        committedBytes: Math.min(blocks * state.blockSize, state.size),
        state: bytesToHex(digestState),
      };
    }
    this.journal = await this.store.commitBlocks(
      journal,
      fileIdx,
      blocks,
      this.now(),
      this.ownerId,
      checkpoint,
    );
  }

  /**
   * Fail-closed resume seed: partials must back every checkpoint. The digest is restored
   * from the checkpointed state when this runtime produced it and it decodes (V13-PR05);
   * otherwise correctness-first — the persisted prefix is re-hashed. Final whole-file
   * verification is mandatory in every path, so an unrestorable or wrong state can never
   * corrupt: it would fail verification.
   */
  private async buildResumeState(): Promise<void> {
    const journal = this.journal!;
    const files = new Map<number, ReceiverResumeFile>();
    for (let i = 0; i < journal.files.length; i++) {
      const state = journal.files[i]!;
      const committed = Math.min(state.committedBlocks * state.blockSize, state.size);
      if (state.committedBlocks === 0) {
        // Nothing persisted: the file restarts from zero. The seed still includes an entry
        // so the receiver's exact file-set validation (V13-PR06) sees complete coverage.
        files.set(i, { haveBlocks: 0, seedDigest: this.createDigest() });
        continue;
      }
      const size = await this.files.partialSize(this.transferId, normalizeTransferPath(state.name));
      if (size === undefined || size < committed) {
        throw new TransferError(
          'sink_error',
          `journal ${this.transferId} file ${state.name}: partial data missing or truncated; refusing to resume — discard it`,
        );
      }
      let digest: Digest;
      let restored = false;
      const cp = state.digestCheckpoint;
      if (cp && cp.format === DIGEST_CHECKPOINT_FORMAT_HASH_WASM) {
        try {
          digest = this.createDigest.restore(hexToBytes(cp.state));
          restored = true;
        } catch {
          digest = this.createDigest();
        }
      } else {
        digest = this.createDigest();
      }
      if (!restored && state.committedBlocks > 0) {
        await this.files.readPrefix(
          this.transferId,
          normalizeTransferPath(state.name),
          committed,
          digest,
        );
      }
      files.set(i, { haveBlocks: state.committedBlocks, seedDigest: digest });
    }
    this.resumeState = {
      transferId: this.transferId,
      // The wire receiver re-binds the seed against the authenticated manifest's canonical
      // fingerprint before advertising any of it (V13-PR06).
      manifestFingerprint: journal.manifestFingerprint,
      files,
    };
  }

  private async buildZip(): Promise<{ key: string; name: string }> {
    const manifest = this.manifest!;
    const journal = this.journal!;
    const name = zipName(manifest);
    const { key, writable } = await this.files.openOutput(this.transferId, '__receive.zip');
    let position = 0;
    const entries: ZipEntry[] = [];
    try {
      for (const file of manifest.files) {
        const rel = normalizeTransferPath(file.name);
        const entryName = new TextEncoder().encode(rel);
        const offset = position;
        await writeAt(writable, position, localHeader(entryName));
        position += 30 + entryName.length;
        let crc = 0xffffffff;
        let size = 0;
        await this.files.readPartialChunks(this.transferId, rel, async (chunk) => {
          await writeAt(writable, position, chunk);
          position += chunk.length;
          crc = crc32Update(crc, chunk);
          size += chunk.length;
        });
        const expected = journal.files[file.idx]!.size;
        if (size !== expected) {
          throw new TransferError(
            'sink_error',
            `partial ${rel} size mismatch at finalize (have ${size}, want ${expected})`,
          );
        }
        await writeAt(writable, position, dataDescriptor((crc ^ 0xffffffff) >>> 0, size));
        position += 16;
        entries.push({ name: entryName, crc: (crc ^ 0xffffffff) >>> 0, size, offset });
      }
      const centralOffset = position;
      for (const entry of entries) {
        const header = centralHeader(entry);
        await writeAt(writable, position, header);
        position += header.length;
      }
      const centralSize = position - centralOffset;
      await writeAt(
        writable,
        position,
        endOfCentralDirectory(entries.length, centralSize, centralOffset),
      );
      await writable.close();
    } catch (e) {
      await writable.abort?.().catch(() => {});
      throw e;
    }
    return { key, name };
  }

  private clearRenew(): void {
    if (this.renewTimer !== undefined) {
      clearInterval(this.renewTimer);
      this.renewTimer = undefined;
    }
  }

  /** Owner-bound lease release (no-op when not prepared or already released); best-effort. */
  private async releaseLease(): Promise<void> {
    if (this.prepared && this.transferId !== '') {
      await this.store.releaseLease(this.transferId, this.ownerId).catch(() => {});
    }
  }
}

interface DurableFileSinkOptions {
  destination: DurableDestination;
  fileIdx: number;
  writer: PartialWriter;
  sync: boolean;
  blockSize: number;
  blocks: number;
  /** Checkpoint already claimed by the journal when this sink opened (resume baseline). */
  startBlocks: number;
}

/** One file's sink: write → flush → journal checkpoint, in that order, before resolving. */
class DurableFileSink implements Sink, DigestStateSink {
  private readonly destination: DurableDestination;
  private readonly fileIdx: number;
  private readonly writer: PartialWriter;
  private readonly sync: boolean;
  private readonly blocks: number;
  private readonly startBlocks: number;
  private written = 0;
  private closed = false;
  private pendingDigestState: Uint8Array | null = null;

  constructor(options: DurableFileSinkOptions) {
    this.destination = options.destination;
    this.fileIdx = options.fileIdx;
    this.writer = options.writer;
    this.sync = options.sync;
    this.blocks = options.blocks;
    this.startBlocks = options.startBlocks;
  }

  /**
   * Implements DigestStateSink (V13-PR05): remembers the serialized digest state covering
   * exactly the blocks the next write (or close, on the async path) checkpoints, so it is
   * persisted atomically with the checkpoint. A null state clears it. The receiver calls
   * this before each write, so a stale state is impossible: every commit consumes the
   * state that was set for exactly its blocks.
   */
  setDigestState(state: Uint8Array | null): void {
    this.pendingDigestState = state;
  }

  async write(offset: number, bytes: Uint8Array): Promise<void> {
    if (this.closed) throw new TransferError('sink_error', 'write after sink close');
    try {
      await this.writer.write(offset, bytes);
    } catch (e) {
      throw asQuotaOrSinkError(e);
    }
    this.written++;
    if (this.sync) {
      // Sync path: the data is flushed; advance the checkpoint before the wire ack.
      const state = this.pendingDigestState;
      this.pendingDigestState = null;
      await this.destination.commitBlocks(this.fileIdx, this.startBlocks + this.written, state);
    }
    // Async path: the stream only flushes at close, so the checkpoint advances there; the
    // latest pending state covers the whole file by then (the digest accumulates).
  }

  async close(): Promise<void> {
    if (this.closed) return;
    try {
      await this.writer.close();
    } catch (e) {
      throw asQuotaOrSinkError(e);
    }
    this.closed = true;
    if (!this.sync) {
      // The stream closed (flush barrier); the whole file is now durable and checkpoints.
      const state = this.pendingDigestState;
      this.pendingDigestState = null;
      await this.destination.commitBlocks(this.fileIdx, this.blocks, state);
    }
  }

  async abort(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    await this.writer.abort().catch(() => {});
  }
}

async function writeAt(w: WritableFileLike, position: number, data: Uint8Array): Promise<void> {
  await w.write({ type: 'write', position, data });
}

function zipName(manifest: Manifest): string {
  const top = manifest.files[0]!.name.split('/')[0]!;
  if (manifest.files.every((file) => file.name.startsWith(`${top}/`))) return `${top}.zip`;
  return 'sendbeam-files.zip';
}

/** Wrap a storage failure as a TransferError, mapping quota exhaustion to the quota reason. */
function asQuotaOrSinkError(e: unknown): TransferError {
  if (e instanceof TransferError) return e;
  if (e instanceof DOMException && e.name === 'QuotaExceededError') {
    return new TransferError(
      'quota',
      'browser storage quota exhausted; partial data is kept and resumable',
    );
  }
  return new TransferError('sink_error', e instanceof Error ? e.message : String(e));
}

/** Default quota preflight over navigator.storage.estimate; no-op when unavailable. */
async function ensureSpaceInBrowser(requiredBytes: number): Promise<void> {
  const storage = (navigator as Navigator & { storage?: StorageManager }).storage;
  if (!storage || typeof storage.estimate !== 'function') return;
  const estimate = await storage.estimate();
  if (estimate.quota === undefined) return;
  const available = Math.max(0, estimate.quota - (estimate.usage ?? 0));
  if (available < requiredBytes) {
    throw new TransferError(
      'quota',
      `need ${requiredBytes} bytes but only ${available} are available`,
    );
  }
}

function origin(): string {
  try {
    return globalThis.location?.origin ?? 'web';
  } catch {
    return 'web';
  }
}

function randomOwnerId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

/** The PR02/PR03 source claim: peer identity binding is PR07, so the envelope is honest. */
async function unboundSourceIdentity(): Promise<JournalIdentity> {
  const sum = await sha256(utf8('sendbeam/source-unbound-v1'));
  return { version: 1, value: bytesToHex(sum) };
}
