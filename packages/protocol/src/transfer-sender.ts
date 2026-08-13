/**
 * Sending half of the transport-agnostic transfer engine.
 *
 * The source is read once for the canonical digest and once for data. During the data pass the
 * sender retains only the bounded window of unacknowledged plaintext blocks. A block leaves that
 * window only after the receiver confirms it was verified and written to its sink. Missing blocks
 * are resealed with fresh AEAD counters; integrity failures remain terminal.
 */

import { FrameReplayError, openSequenced, seal, type FrameHeaderInput } from './aead.js';
import type { DirectionalKey } from './keyschedule.js';
import { FrameType, type ControlOp, type Fail, type Manifest } from './transfer.js';
import {
  DEFAULT_BLOCK_BYTES,
  DEFAULT_FRAME_BYTES,
  DEFAULT_INFLIGHT_BLOCKS,
  FRAME_VERSION,
} from './constants.js';
import { sha256 } from './webcrypto.js';
import { bytesToHex } from './bytes.js';
import { TransferError, type Digest, type FileSource } from './transfer-ports.js';
import { reChunk } from './transfer-chunker.js';
import { decodeControl, encodeControl } from './transfer-messages.js';
import { validateManifest } from './safe-path.js';
import { completionDigest } from './transfer-set.js';

/** Header flag: this frame is the last of its block. */
export const FRAME_FLAG_LAST_IN_BLOCK = 0x01;

export type TransferRunState = 'running' | 'paused' | 'canceled';

export interface TransferSenderOptions {
  /** One file (compatibility shorthand). Exactly one of file/files must be supplied. */
  file?: FileSource;
  /** Ordered file set with canonical relative paths in each source's meta.name. */
  files?: readonly FileSource[];
  send(frame: Uint8Array): void | Promise<void>;
  sendDir: DirectionalKey;
  recvDir: DirectionalKey;
  sendCounterStart: number;
  recvCounterStart: number;
  createDigest(): Digest;
  /**
   * A stable transfer id (hex) advertised in the manifest so a reloaded receiver can prove it is
   * resuming *this* transfer. Supply it when the caller controls the id across attempts; otherwise
   * {@link newTransferId} mints one. Either enables the resume handshake: the manifest carries the
   * id and the sender waits for the receiver's `resume_state` before streaming, restarting each
   * file at the acknowledged high-water mark.
   */
  transferId?: string;
  /** Mint a fresh transfer id when {@link transferId} is not supplied. */
  newTransferId?(): string;
  blockSize?: number;
  frameSize?: number;
  window?: number;
  /** Milliseconds without an acknowledgement before a block is resent. */
  ackTimeoutMs?: number;
  /** Retransmissions allowed per block after its initial send. */
  maxRetries?: number;
  /**
   * How long to wait for the receiver's Done after Complete before failing with
   * retry exhaustion. A dead peer otherwise stalls `run` forever.
   */
  doneTimeoutMs?: number;
  /** Reports bytes acknowledged after verify-and-sink. */
  onProgress?(acknowledgedBytes: number): void;
  /** Reports verified progress for the active file plus aggregate acknowledged bytes. */
  onFileProgress?(fileIdx: number, fileBytes: number, acknowledgedBytes: number): void;
  onManifest?(manifest: Manifest): void;
  onStateChange?(state: TransferRunState): void;
}

interface InflightBlock {
  readonly bytes: Uint8Array;
  retries: number;
  timer: ReturnType<typeof setTimeout> | undefined;
}

const DEFAULT_ACK_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_DONE_TIMEOUT_MS = 30_000;

export class TransferSender {
  private readonly o: TransferSenderOptions;
  private readonly blockSize: number;
  private readonly frameSize: number;
  private readonly window: number;
  private readonly ackTimeoutMs: number;
  private readonly maxRetries: number;
  private readonly files: readonly FileSource[];

  private sendCounter: number;
  private recvCounter: number;
  private acknowledged = 0;
  private paused = false;
  private completeSent = false;
  /** The canonical digest carried by the one-shot Complete control, kept so a path change
   *  before settlement can retransmit Complete (the receiver settles then ignores duplicates). */
  private completeDigest: string | undefined;
  private activeFileIdx = -1;
  private activeFileAcknowledged = 0;
  /** The validated manifest, kept so a path change before any acknowledgment can retransmit it. */
  private manifest: Manifest | undefined;

  /** Set when a transfer id is advertised: the manifest carries it and a resume handshake runs. */
  private readonly transferId: string | undefined;
  /** Per-file high-water marks the receiver reported; each file restarts at its value. */
  private readonly resumePlan = new Map<number, number>();
  /** Resolves when the receiver's `resume_state` has been validated (resume mode only). */
  private resolveResumeReady!: () => void;
  private rejectResumeReady!: (e: Error) => void;
  private readonly resumeReady: Promise<void>;
  private resumeSettled = false;

  private readonly inflight = new Map<number, InflightBlock>();
  private readonly retryQueue: number[] = [];
  private readonly retryQueued = new Set<number>();
  private waiters: Array<() => void> = [];

  private resolveDone!: () => void;
  private rejectDone!: (e: Error) => void;
  private readonly done: Promise<void>;
  private inbound: Promise<void> = Promise.resolve();
  private outbound: Promise<void> = Promise.resolve();
  private settled = false;

  constructor(opts: TransferSenderOptions) {
    this.o = opts;
    if ((opts.file === undefined) === (opts.files === undefined)) {
      throw new Error('exactly one of file or files is required');
    }
    this.files = opts.files ?? [opts.file!];
    if (this.files.length === 0) throw new Error('at least one file is required');
    this.blockSize = opts.blockSize ?? DEFAULT_BLOCK_BYTES;
    this.frameSize = opts.frameSize ?? DEFAULT_FRAME_BYTES;
    this.window = opts.window ?? DEFAULT_INFLIGHT_BLOCKS;
    this.ackTimeoutMs = opts.ackTimeoutMs ?? DEFAULT_ACK_TIMEOUT_MS;
    this.maxRetries = opts.maxRetries ?? DEFAULT_MAX_RETRIES;
    this.sendCounter = opts.sendCounterStart;
    this.recvCounter = opts.recvCounterStart;
    this.transferId = opts.transferId ?? opts.newTransferId?.();
    this.done = new Promise<void>((res, rej) => {
      this.resolveDone = res;
      this.rejectDone = rej;
    });
    this.done.catch(() => {});
    this.resumeReady = new Promise<void>((res, rej) => {
      this.resolveResumeReady = res;
      this.rejectResumeReady = rej;
    });
    this.resumeReady.catch(() => {});
  }

  /**
   * Drive the complete send. The returned digest is reported only after every block is
   * acknowledged and the receiver confirms the whole-file digest.
   */
  async run(): Promise<string> {
    try {
      return await this.drive();
    } catch (e) {
      const err = e instanceof Error ? e : new Error(String(e));
      this.fail(err);
      throw err;
    }
  }

  /** Feed one inbound encrypted control frame from the receiver. */
  handle(frame: Uint8Array): Promise<void> {
    this.inbound = this.inbound
      .then(() => this.processInbound(frame))
      .catch((e: unknown) => {
        this.fail(e instanceof Error ? e : new Error(String(e)));
      });
    return this.inbound;
  }

  /** Retransmit every unacknowledged block after the host selects a new ordered byte path. */
  transportChanged(): void {
    if (this.settled) return;
    for (const [blockIdx, state] of this.inflight) {
      state.retries = 0;
      this.queueRetry(blockIdx);
    }
    if (this.manifest !== undefined && this.acknowledged === 0) {
      // The manifest may have been lost in the cutover; it is outside the block
      // retransmit window. The receiver ignores identical duplicates and stray
      // pre-manifest data, so resending it lets the transfer continue.
      void this.sendControl(FrameType.Manifest, this.manifest).catch((e: unknown) =>
        this.fail(e instanceof Error ? e : new Error(String(e))),
      );
    }
    if (this.completeSent && this.completeDigest !== undefined) {
      // Complete is a one-shot frame: sending it does not wait for an ack, so a cutover that
      // tears the old path down right after it was written can starve it from the receiver.
      // The receiver settles on Complete (then ignores a duplicate) and sends Done, so
      // retransmitting it on the new path preserves the v1.1 terminal-Complete recovery.
      void this.sendControl(FrameType.Complete, {
        type: FrameType.Complete,
        fileDigest: this.completeDigest,
      }).catch((e: unknown) => this.fail(e instanceof Error ? e : new Error(String(e))));
    }
  }

  /** Pause locally and ask the peer to reflect the paused state. */
  pause(): void {
    if (this.settled || this.paused) return;
    this.setPaused(true);
    void this.sendControl(FrameType.Control, { type: FrameType.Control, op: 'pause' }).catch(
      (e: unknown) => this.fail(e instanceof Error ? e : new Error(String(e))),
    );
  }

  /** Resume locally and notify the peer. */
  resume(): void {
    if (this.settled || !this.paused) return;
    this.setPaused(false);
    void this.sendControl(FrameType.Control, { type: FrameType.Control, op: 'resume' }).catch(
      (e: unknown) => this.fail(e instanceof Error ? e : new Error(String(e))),
    );
  }

  /** Best-effort peer notification followed by terminal local cancellation. */
  cancel(reason = 'canceled'): void {
    if (this.settled) return;
    const err = new TransferError('canceled', reason);
    void this.sendControl(FrameType.Control, { type: FrameType.Control, op: 'cancel' })
      .catch(() => {})
      .finally(() => this.fail(err));
  }

  private async drive(): Promise<string> {
    const entries = [];
    let totalSize = 0;
    for (const [idx, source] of this.files.entries()) {
      const digest = this.o.createDigest();
      for await (const chunk of source.stream()) digest.update(chunk);
      const { meta } = source;
      totalSize += meta.size;
      entries.push({
        idx,
        name: meta.name,
        size: meta.size,
        mime: meta.mime,
        lastModified: meta.lastModified,
        blockSize: this.blockSize,
        blocks: Math.ceil(meta.size / this.blockSize),
        fileDigest: await digest.hexDigest(),
      });
    }
    const manifest = validateManifest({
      type: FrameType.Manifest,
      ...(this.transferId !== undefined ? { transferId: this.transferId } : {}),
      files: entries,
      totalSize,
    });
    const transferDigest = await completionDigest(manifest.files);
    this.o.onManifest?.(manifest);
    await this.sendControl(FrameType.Manifest, manifest);
    this.manifest = manifest;

    // A transfer id opts into resumption: the receiver answers the manifest with a resume_state
    // carrying each file's high-water mark (all zero on a first attempt). Wait for it before
    // streaming so skipped blocks are never sent. Fresh transfers never take this branch.
    if (this.transferId !== undefined) {
      await this.resumeReady;
    }

    for (const [fileIdx, source] of this.files.entries()) {
      this.activeFileIdx = fileIdx;
      const file = manifest.files[fileIdx]!;
      const haveBlocks = Math.min(this.resumePlan.get(fileIdx) ?? 0, file.blocks);
      // Bytes the receiver already holds count as acknowledged up front so progress is continuous
      // across a resume. Only the final block may be partial, so a full prefix is haveBlocks blocks.
      const committed = haveBlocks >= file.blocks ? file.size : haveBlocks * this.blockSize;
      this.activeFileAcknowledged = committed;
      this.acknowledged += committed;
      // Asking reChunk for block-sized pieces yields one retained buffer per logical block. The
      // block is then split into transport-sized frames by sendBlock. Blocks the receiver already
      // holds are read past (the source is streamed for the digest regardless) but never sent.
      for await (const piece of reChunk(source.stream(), this.blockSize, this.blockSize)) {
        if (piece.blockIdx < haveBlocks) continue;
        await this.beforeNewBlock();
        await this.propagateSettlement();
        const bytes = piece.payload.slice();
        this.inflight.set(piece.blockIdx, { bytes, retries: 0, timer: undefined });
        await this.sendBlock(piece.blockIdx, bytes);
        this.armTimeout(piece.blockIdx);
      }
      while (this.inflight.size > 0) {
        await this.propagateSettlement();
        await this.serviceRetriesOrWait();
      }
      this.o.onFileProgress?.(fileIdx, this.activeFileAcknowledged, this.acknowledged);
    }

    this.completeSent = true;
    this.completeDigest = transferDigest;
    await this.sendControl(FrameType.Complete, {
      type: FrameType.Complete,
      fileDigest: transferDigest,
    });
    await this.waitForDone();
    return transferDigest;
  }

  private async waitForDone(): Promise<void> {
    const timeoutMs = this.o.doneTimeoutMs ?? DEFAULT_DONE_TIMEOUT_MS;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([
        this.done,
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => {
            reject(new TransferError('retry_exhausted', 'receiver did not send done in time'));
          }, timeoutMs);
        }),
      ]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  private async processInbound(frame: Uint8Array): Promise<void> {
    if (this.settled) return;
    let opened;
    try {
      opened = await openSequenced(this.o.recvDir, this.recvCounter, frame);
      this.recvCounter = opened.counter + 1;
    } catch (e) {
      if (e instanceof FrameReplayError) return;
      throw new TransferError(
        'integrity',
        e instanceof Error ? e.message : 'unable to authenticate control frame',
      );
    }
    const msg = decodeControl(opened.plaintext);
    if (opened.header.type !== msg.type) {
      throw new TransferError('integrity', 'control frame header/payload type mismatch');
    }
    switch (msg.type) {
      case FrameType.Ack: {
        if (msg.fileIdx < this.activeFileIdx) return;
        if (msg.fileIdx !== this.activeFileIdx) {
          throw new TransferError('integrity', 'ack for unknown file');
        }
        const state = this.inflight.get(msg.blockIdx);
        if (!state) return; // duplicate acknowledgement
        if (state.timer) clearTimeout(state.timer);
        this.inflight.delete(msg.blockIdx);
        this.retryQueued.delete(msg.blockIdx);
        this.acknowledged += state.bytes.length;
        this.activeFileAcknowledged += state.bytes.length;
        this.o.onProgress?.(this.acknowledged);
        this.o.onFileProgress?.(this.activeFileIdx, this.activeFileAcknowledged, this.acknowledged);
        this.wake();
        return;
      }
      case FrameType.Nack:
        if (msg.fileIdx < this.activeFileIdx) return;
        if (msg.fileIdx !== this.activeFileIdx) {
          throw new TransferError('integrity', 'nack for unknown file');
        }
        this.queueRetry(msg.blockIdx);
        return;
      case FrameType.ResumeState: {
        if (this.transferId === undefined) {
          throw new TransferError('integrity', 'unexpected resume_state');
        }
        if (this.resumeSettled) {
          throw new TransferError('integrity', 'duplicate resume_state');
        }
        if (msg.transferId !== this.transferId) {
          throw new TransferError('integrity', 'resume_state transfer id mismatch');
        }
        for (const entry of msg.files) {
          const file = this.files[entry.idx];
          const blocks = file ? Math.ceil(file.meta.size / this.blockSize) : -1;
          if (blocks < 0 || this.resumePlan.has(entry.idx)) {
            throw new TransferError('integrity', 'resume_state references an unknown file');
          }
          if (entry.haveBlocks < 0 || entry.haveBlocks > blocks) {
            throw new TransferError('integrity', 'resume_state haveBlocks out of range');
          }
          this.resumePlan.set(entry.idx, entry.haveBlocks);
        }
        this.resumeSettled = true;
        this.resolveResumeReady();
        return;
      }
      case FrameType.Control:
        this.applyRemoteControl(msg.op);
        return;
      case FrameType.Done:
        if (!this.completeSent) {
          throw new TransferError('integrity', 'done before complete was sent');
        }
        // Done is authoritative: the receiver only sends it after verifying the
        // whole-file digest. A non-empty inflight window here means acks were lost
        // during a path cutover, so settle instead of failing a healthy transfer.
        this.settle();
        return;
      case FrameType.Fail:
        this.fail(new TransferError(msg.reason, `receiver failed: ${msg.reason}`));
        return;
      default:
        throw new TransferError('integrity', `unexpected sender-inbound type ${msg.type}`);
    }
  }

  private applyRemoteControl(op: ControlOp): void {
    switch (op) {
      case 'pause':
        this.setPaused(true);
        return;
      case 'resume':
        this.setPaused(false);
        return;
      case 'cancel':
        this.o.onStateChange?.('canceled');
        this.fail(new TransferError('canceled', 'peer canceled the transfer'));
    }
  }

  private setPaused(paused: boolean): void {
    if (this.paused === paused || this.settled) return;
    this.paused = paused;
    for (const [blockIdx, state] of this.inflight) {
      if (state.timer) clearTimeout(state.timer);
      state.timer = undefined;
      if (!paused) this.armTimeout(blockIdx);
    }
    this.o.onStateChange?.(paused ? 'paused' : 'running');
    this.wake();
  }

  private async beforeNewBlock(): Promise<void> {
    while (!this.settled) {
      if (this.paused) {
        await this.wait();
        continue;
      }
      if (this.retryQueue.length > 0) {
        await this.resendNext();
        continue;
      }
      if (this.inflight.size < this.window) return;
      await this.wait();
    }
  }

  private async serviceRetriesOrWait(): Promise<void> {
    if (this.paused || this.retryQueue.length === 0) {
      await this.wait();
      return;
    }
    await this.resendNext();
  }

  private queueRetry(blockIdx: number): void {
    const state = this.inflight.get(blockIdx);
    if (!state || this.retryQueued.has(blockIdx)) return;
    if (state.timer) clearTimeout(state.timer);
    state.timer = undefined;
    this.retryQueued.add(blockIdx);
    this.retryQueue.push(blockIdx);
    this.wake();
  }

  private async resendNext(): Promise<void> {
    const blockIdx = this.retryQueue.shift();
    if (blockIdx === undefined) return;
    this.retryQueued.delete(blockIdx);
    const state = this.inflight.get(blockIdx);
    if (!state) return;
    if (state.retries >= this.maxRetries) {
      const err = new TransferError('retry_exhausted', `block ${blockIdx} remained unacknowledged`);
      await this.bestEffortFail(err.reason);
      this.fail(err);
      return;
    }
    state.retries++;
    await this.sendBlock(blockIdx, state.bytes);
    this.armTimeout(blockIdx);
  }

  private armTimeout(blockIdx: number): void {
    const state = this.inflight.get(blockIdx);
    if (!state || this.paused || this.ackTimeoutMs <= 0) return;
    if (state.timer) clearTimeout(state.timer);
    state.timer = setTimeout(() => this.queueRetry(blockIdx), this.ackTimeoutMs);
  }

  private async sendBlock(blockIdx: number, bytes: Uint8Array): Promise<void> {
    for (let off = 0; off < bytes.length; off += this.frameSize) {
      const end = Math.min(off + this.frameSize, bytes.length);
      await this.sendFrame(
        {
          version: FRAME_VERSION,
          type: FrameType.BlockData,
          flags: end === bytes.length ? FRAME_FLAG_LAST_IN_BLOCK : 0,
          fileIdx: this.activeFileIdx,
          blockIdx,
          frameOff: off,
        },
        bytes.subarray(off, end),
      );
    }
    await this.sendControl(FrameType.BlockHash, {
      type: FrameType.BlockHash,
      fileIdx: this.activeFileIdx,
      blockIdx,
      sha256: bytesToHex(await sha256(bytes)),
    });
  }

  private async sendControl(
    type: FrameType,
    msg: Parameters<typeof encodeControl>[0],
  ): Promise<void> {
    await this.sendFrame(
      { version: FRAME_VERSION, type, flags: 0, fileIdx: 0, blockIdx: 0, frameOff: 0 },
      encodeControl(msg),
    );
  }

  /** Serialize sealing so external controls can never race the data path for a nonce. */
  private sendFrame(header: FrameHeaderInput, payload: Uint8Array): Promise<void> {
    const task = this.outbound.then(async () => {
      const frame = await seal(this.o.sendDir, this.sendCounter++, header, payload);
      await this.o.send(frame);
    });
    this.outbound = task.catch(() => {});
    return task;
  }

  private async bestEffortFail(reason: Fail['reason']): Promise<void> {
    try {
      await this.sendControl(FrameType.Fail, { type: FrameType.Fail, reason });
    } catch {
      // The transport may already be unavailable.
    }
  }

  private wait(): Promise<void> {
    if (this.settled) return Promise.resolve();
    return new Promise<void>((resolve) => this.waiters.push(resolve));
  }

  private wake(): void {
    const waiters = this.waiters;
    this.waiters = [];
    for (const resolve of waiters) resolve();
  }

  private async propagateSettlement(): Promise<void> {
    if (this.settled) await this.done;
  }

  private clearTimers(): void {
    for (const state of this.inflight.values()) {
      if (state.timer) clearTimeout(state.timer);
    }
  }

  private settle(): void {
    if (this.settled) return;
    this.settled = true;
    this.clearTimers();
    this.resolveDone();
    this.wake();
  }

  private fail(err: Error): void {
    if (this.settled) return;
    this.settled = true;
    this.clearTimers();
    this.rejectResumeReady(err);
    this.rejectDone(err);
    this.wake();
  }
}
