/**
 * Sending half of the transport-agnostic transfer engine.
 *
 * The source is read once for the canonical digest and once for data. During the data pass the
 * sender retains only the bounded window of unacknowledged plaintext blocks. A block leaves that
 * window only after the receiver confirms it was verified and written to its sink. Missing blocks
 * are resealed with fresh AEAD counters; integrity failures remain terminal.
 */

import { open, seal, type FrameHeaderInput } from './aead.js';
import type { DirectionalKey } from './keyschedule.js';
import { FrameType, type ControlOp, type Fail } from './transfer.js';
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

/** Header flag: this frame is the last of its block. */
export const FRAME_FLAG_LAST_IN_BLOCK = 0x01;

export type TransferRunState = 'running' | 'paused' | 'canceled';

export interface TransferSenderOptions {
  file: FileSource;
  send(frame: Uint8Array): void | Promise<void>;
  sendDir: DirectionalKey;
  recvDir: DirectionalKey;
  sendCounterStart: number;
  recvCounterStart: number;
  createDigest(): Digest;
  blockSize?: number;
  frameSize?: number;
  window?: number;
  /** Milliseconds without an acknowledgement before a block is resent. */
  ackTimeoutMs?: number;
  /** Retransmissions allowed per block after its initial send. */
  maxRetries?: number;
  /** Reports bytes acknowledged after verify-and-sink. */
  onProgress?(acknowledgedBytes: number): void;
  onStateChange?(state: TransferRunState): void;
}

interface InflightBlock {
  readonly bytes: Uint8Array;
  retries: number;
  timer: ReturnType<typeof setTimeout> | undefined;
}

const DEFAULT_ACK_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_RETRIES = 3;

export class TransferSender {
  private readonly o: TransferSenderOptions;
  private readonly blockSize: number;
  private readonly frameSize: number;
  private readonly window: number;
  private readonly ackTimeoutMs: number;
  private readonly maxRetries: number;

  private sendCounter: number;
  private recvCounter: number;
  private acknowledged = 0;
  private paused = false;
  private completeSent = false;

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
    this.blockSize = opts.blockSize ?? DEFAULT_BLOCK_BYTES;
    this.frameSize = opts.frameSize ?? DEFAULT_FRAME_BYTES;
    this.window = opts.window ?? DEFAULT_INFLIGHT_BLOCKS;
    this.ackTimeoutMs = opts.ackTimeoutMs ?? DEFAULT_ACK_TIMEOUT_MS;
    this.maxRetries = opts.maxRetries ?? DEFAULT_MAX_RETRIES;
    this.sendCounter = opts.sendCounterStart;
    this.recvCounter = opts.recvCounterStart;
    this.done = new Promise<void>((res, rej) => {
      this.resolveDone = res;
      this.rejectDone = rej;
    });
    this.done.catch(() => {});
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
  handle(frame: Uint8Array): void {
    this.inbound = this.inbound
      .then(() => this.processInbound(frame))
      .catch((e: unknown) => {
        this.fail(e instanceof Error ? e : new Error(String(e)));
      });
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
    const { meta } = this.o.file;

    const digest = this.o.createDigest();
    for await (const chunk of this.o.file.stream()) digest.update(chunk);
    const fileDigest = await digest.hexDigest();

    const blocks = Math.ceil(meta.size / this.blockSize);
    const manifest = validateManifest({
      type: FrameType.Manifest,
      files: [
        {
          idx: 0,
          name: meta.name,
          size: meta.size,
          mime: meta.mime,
          lastModified: meta.lastModified,
          blockSize: this.blockSize,
          blocks,
          fileDigest,
        },
      ],
      totalSize: meta.size,
    });
    await this.sendControl(FrameType.Manifest, manifest);

    // Asking reChunk for block-sized pieces yields one retained buffer per logical block. The
    // block is then split into transport-sized frames by sendBlock.
    for await (const piece of reChunk(this.o.file.stream(), this.blockSize, this.blockSize)) {
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

    this.completeSent = true;
    await this.sendControl(FrameType.Complete, { type: FrameType.Complete, fileDigest });
    await this.done;
    return fileDigest;
  }

  private async processInbound(frame: Uint8Array): Promise<void> {
    if (this.settled) return;
    let opened;
    try {
      opened = await open(this.o.recvDir, this.recvCounter++, frame);
    } catch (e) {
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
        if (msg.fileIdx !== 0) throw new TransferError('integrity', 'ack for unknown file');
        const state = this.inflight.get(msg.blockIdx);
        if (!state) return; // duplicate acknowledgement
        if (state.timer) clearTimeout(state.timer);
        this.inflight.delete(msg.blockIdx);
        this.retryQueued.delete(msg.blockIdx);
        this.acknowledged += state.bytes.length;
        this.o.onProgress?.(this.acknowledged);
        this.wake();
        return;
      }
      case FrameType.Nack:
        if (msg.fileIdx !== 0) throw new TransferError('integrity', 'nack for unknown file');
        this.queueRetry(msg.blockIdx);
        return;
      case FrameType.Control:
        this.applyRemoteControl(msg.op);
        return;
      case FrameType.Done:
        if (!this.completeSent || this.inflight.size !== 0) {
          throw new TransferError('integrity', 'done before every block was acknowledged');
        }
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
          fileIdx: 0,
          blockIdx,
          frameOff: off,
        },
        bytes.subarray(off, end),
      );
    }
    await this.sendControl(FrameType.BlockHash, {
      type: FrameType.BlockHash,
      fileIdx: 0,
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
    this.rejectDone(err);
    this.wake();
  }
}
