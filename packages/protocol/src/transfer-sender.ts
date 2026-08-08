/**
 * TransferSender — the sending half of the transport-agnostic transfer engine (design §5).
 * It streams the file without ever buffering it whole:
 *   Pass 1  read the file once → whole-file streaming digest → manifest (with fileDigest).
 *   Pass 2  re-chunk into `block_data` frames; at each block boundary send `block_hash`.
 *   Finish  send `complete{fileDigest}`; resolve when the receiver returns `done`.
 * Outbound frames are AES-GCM sealed with a per-direction counter that continues from M1
 * (never reset). The sender never runs more than `window` blocks ahead of the receiver's
 * `block_recv` signal, bounding the outbound queue.
 */

import { seal, open, type FrameHeaderInput } from './aead.js';
import type { DirectionalKey } from './keyschedule.js';
import { FrameType } from './transfer.js';
import {
  DEFAULT_BLOCK_BYTES,
  DEFAULT_FRAME_BYTES,
  DEFAULT_INFLIGHT_BLOCKS,
  FRAME_VERSION,
} from './constants.js';
import { sha256 } from './webcrypto.js';
import { bytesToHex, concatBytes } from './bytes.js';
import { TransferError, type Digest, type FileSource } from './transfer-ports.js';
import { reChunk } from './transfer-chunker.js';
import { decodeControl, encodeControl } from './transfer-messages.js';

/** Header flag: this frame is the last of its block. */
export const FRAME_FLAG_LAST_IN_BLOCK = 0x01;

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
  onProgress?(sentBytes: number): void;
}

export class TransferSender {
  private readonly o: TransferSenderOptions;
  private readonly blockSize: number;
  private readonly frameSize: number;
  private readonly window: number;

  private sendCounter: number;
  private recvCounter: number;
  private sent = 0;

  private lastRecvBlock = -1;
  private windowWaiters: Array<() => void> = [];

  private resolveDone!: () => void;
  private rejectDone!: (e: Error) => void;
  private readonly done: Promise<void>;
  private inbound: Promise<void> = Promise.resolve();
  private settled = false;

  constructor(opts: TransferSenderOptions) {
    this.o = opts;
    this.blockSize = opts.blockSize ?? DEFAULT_BLOCK_BYTES;
    this.frameSize = opts.frameSize ?? DEFAULT_FRAME_BYTES;
    this.window = opts.window ?? DEFAULT_INFLIGHT_BLOCKS;
    this.sendCounter = opts.sendCounterStart;
    this.recvCounter = opts.recvCounterStart;
    this.done = new Promise<void>((res, rej) => {
      this.resolveDone = res;
      this.rejectDone = rej;
    });
    this.done.catch(() => {});
  }

  /** Drive the whole send. Resolves when the receiver confirms `done`, rejects on `fail`. */
  async run(): Promise<void> {
    const { meta } = this.o.file;

    // Pass 1: whole-file digest (streamed; the file is never held).
    const digest = this.o.createDigest();
    for await (const chunk of this.o.file.stream()) digest.update(chunk);
    const fileDigest = await digest.hexDigest();

    const blocks = Math.ceil(meta.size / this.blockSize); // 0 for an empty file
    await this.sendControl(FrameType.Manifest, {
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

    // Pass 2: block data + per-block hash, gated to the in-flight window.
    let blockParts: Uint8Array[] = [];
    for await (const piece of reChunk(this.o.file.stream(), this.blockSize, this.frameSize)) {
      await this.gate(piece.blockIdx);
      if (this.settled) return this.done; // aborted by an inbound fail
      await this.sendFrame(
        {
          version: FRAME_VERSION,
          type: FrameType.BlockData,
          flags: piece.lastInBlock ? FRAME_FLAG_LAST_IN_BLOCK : 0,
          fileIdx: 0,
          blockIdx: piece.blockIdx,
          frameOff: piece.frameOff,
        },
        piece.payload,
      );
      this.sent += piece.payload.length;
      this.o.onProgress?.(this.sent);
      blockParts.push(piece.payload.slice());
      if (piece.lastInBlock) {
        const blockBytes = concatBytes(...blockParts);
        blockParts = [];
        const hashHex = bytesToHex(await sha256(blockBytes));
        await this.sendControl(FrameType.BlockHash, {
          type: FrameType.BlockHash,
          fileIdx: 0,
          blockIdx: piece.blockIdx,
          sha256: hashHex,
        });
      }
    }

    await this.sendControl(FrameType.Complete, { type: FrameType.Complete, fileDigest });
    return this.done;
  }

  /** Feed one inbound frame from the receiver (block_recv / done / fail). */
  handle(frame: Uint8Array): void {
    this.inbound = this.inbound
      .then(() => this.processInbound(frame))
      .catch((e: unknown) => {
        this.fail(e instanceof Error ? e : new Error(String(e)));
      });
  }

  // --- internal ---------------------------------------------------------------

  private async processInbound(frame: Uint8Array): Promise<void> {
    if (this.settled) return;
    const opened = await open(this.o.recvDir, this.recvCounter++, frame);
    const msg = decodeControl(opened.plaintext);
    switch (msg.type) {
      case FrameType.BlockRecv:
        this.lastRecvBlock = Math.max(this.lastRecvBlock, msg.blockIdx);
        this.wakeWindow();
        return;
      case FrameType.Done:
        this.settle();
        return;
      case FrameType.Fail:
        this.fail(new TransferError(msg.reason, `receiver failed: ${msg.reason}`));
        return;
      default:
        this.fail(new TransferError('integrity', `unexpected sender-inbound type ${msg.type}`));
    }
  }

  private async gate(blockIdx: number): Promise<void> {
    while (!this.settled && blockIdx - this.lastRecvBlock > this.window) {
      await new Promise<void>((r) => this.windowWaiters.push(r));
    }
  }

  private wakeWindow(): void {
    const waiters = this.windowWaiters;
    this.windowWaiters = [];
    for (const w of waiters) w();
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

  private async sendFrame(header: FrameHeaderInput, payload: Uint8Array): Promise<void> {
    const frame = await seal(this.o.sendDir, this.sendCounter++, header, payload);
    await this.o.send(frame);
  }

  private settle(): void {
    if (this.settled) return;
    this.settled = true;
    this.resolveDone();
    this.wakeWindow();
  }

  private fail(err: Error): void {
    if (this.settled) return;
    this.settled = true;
    this.rejectDone(err);
    this.wakeWindow();
  }
}
