/**
 * TransferReceiver — the receiving half of the transfer engine (design §5, §6). Frames arrive
 * over an ordered/reliable channel, so blocks assemble one at a time, in order. For each block
 * the receiver verifies its SHA-256 (from `block_hash`) BEFORE writing to the sink, feeds the
 * verified bytes into the whole-file streaming digest, then signals `block_recv` (the in-flight
 * window). On `complete` it compares the recomputed digest to the sender's and returns `done`
 * or `fail{digest_mismatch}`. A GCM `open` throw or any hash mismatch → `fail{integrity}` and
 * abort — never a silent retry (design §5.5).
 */

import { open, seal, type FrameHeaderInput } from './aead.js';
import type { DirectionalKey } from './keyschedule.js';
import { FrameType, type FileEntry } from './transfer.js';
import { FRAME_VERSION } from './constants.js';
import { sha256 } from './webcrypto.js';
import { bytesToHex } from './bytes.js';
import { TransferError, type Digest, type Sink } from './transfer-ports.js';
import { decodeControl, encodeControl } from './transfer-messages.js';

export interface ReceiveResult {
  file: FileEntry;
  digest: string;
}

export interface TransferReceiverOptions {
  send(frame: Uint8Array): void | Promise<void>;
  sendDir: DirectionalKey;
  recvDir: DirectionalKey;
  sendCounterStart: number;
  recvCounterStart: number;
  createDigest(): Digest;
  sink: Sink;
  onProgress?(receivedBytes: number): void;
  /**
   * Called once when the manifest decodes, before any block is written — lets the host open a
   * destination named after the file (e.g. an OPFS sink) without the engine knowing about it.
   */
  onManifest?(file: FileEntry): void | Promise<void>;
}

export class TransferReceiver {
  private readonly o: TransferReceiverOptions;
  private readonly digest: Digest;

  private sendCounter: number;
  private recvCounter: number;

  private file: FileEntry | undefined;
  private curBlock = 0;
  private blockBuf: Uint8Array | undefined;
  private blockLen = 0;
  private received = 0;

  private resolveDone!: (r: ReceiveResult) => void;
  private rejectDone!: (e: Error) => void;
  readonly done: Promise<ReceiveResult>;
  private chain: Promise<void> = Promise.resolve();
  private settled = false;

  constructor(opts: TransferReceiverOptions) {
    this.o = opts;
    this.digest = opts.createDigest();
    this.sendCounter = opts.sendCounterStart;
    this.recvCounter = opts.recvCounterStart;
    this.done = new Promise<ReceiveResult>((res, rej) => {
      this.resolveDone = res;
      this.rejectDone = rej;
    });
    this.done.catch(() => {});
  }

  /** Feed one inbound frame from the sender (manifest / block_data / block_hash / complete). */
  handle(frame: Uint8Array): void {
    this.chain = this.chain
      .then(() => this.process(frame))
      .catch((e: unknown) => {
        void this.abortWith(
          e instanceof TransferError ? e : new TransferError('integrity', String(e)),
        );
      });
  }

  // --- internal ---------------------------------------------------------------

  private async process(frame: Uint8Array): Promise<void> {
    if (this.settled) return;
    const opened = await open(this.o.recvDir, this.recvCounter++, frame); // throw → integrity abort
    switch (opened.header.type) {
      case FrameType.Manifest:
        return this.applyManifest(opened.plaintext);
      case FrameType.BlockData:
        return this.onBlockData(opened.header.blockIdx, opened.header.frameOff, opened.plaintext);
      case FrameType.BlockHash:
        return this.onBlockHash(opened.plaintext);
      case FrameType.Complete:
        return this.onComplete(opened.plaintext);
      default:
        throw new TransferError(
          'integrity',
          `unexpected receiver-inbound type ${opened.header.type}`,
        );
    }
  }

  private async applyManifest(payload: Uint8Array): Promise<void> {
    const msg = decodeControl(payload);
    if (msg.type !== FrameType.Manifest) throw new TransferError('integrity', 'expected manifest');
    const file = msg.files[0];
    if (!file) throw new TransferError('integrity', 'manifest has no files');
    this.file = file;
    await this.o.onManifest?.(file);
  }

  private onBlockData(blockIdx: number, frameOff: number, payload: Uint8Array): void {
    if (!this.file) throw new TransferError('integrity', 'block_data before manifest');
    if (blockIdx !== this.curBlock)
      throw new TransferError('integrity', `out-of-order block ${blockIdx}`);
    if (frameOff === 0) {
      this.blockLen = Math.min(
        this.file.blockSize,
        this.file.size - blockIdx * this.file.blockSize,
      );
      this.blockBuf = new Uint8Array(this.blockLen);
      this.received = 0;
    }
    this.blockBuf!.set(payload, frameOff);
    this.received += payload.length;
  }

  private async onBlockHash(payload: Uint8Array): Promise<void> {
    if (!this.file || !this.blockBuf)
      throw new TransferError('integrity', 'block_hash without a block');
    const msg = decodeControl(payload);
    if (msg.type !== FrameType.BlockHash)
      throw new TransferError('integrity', 'expected block_hash');
    if (this.received !== this.blockLen) throw new TransferError('integrity', 'short block');
    const got = bytesToHex(await sha256(this.blockBuf));
    if (got !== msg.sha256)
      throw new TransferError('integrity', `block ${msg.blockIdx} hash mismatch`);

    await this.o.sink.write(this.curBlock * this.file.blockSize, this.blockBuf);
    this.digest.update(this.blockBuf);
    this.o.onProgress?.(this.curBlock * this.file.blockSize + this.blockLen);
    await this.sendControl(FrameType.BlockRecv, {
      type: FrameType.BlockRecv,
      fileIdx: 0,
      blockIdx: this.curBlock,
    });
    this.curBlock++;
    this.blockBuf = undefined;
  }

  private async onComplete(payload: Uint8Array): Promise<void> {
    if (!this.file) throw new TransferError('integrity', 'complete before manifest');
    const msg = decodeControl(payload);
    if (msg.type !== FrameType.Complete) throw new TransferError('integrity', 'expected complete');
    const got = await this.digest.hexDigest();
    if (got !== msg.fileDigest) {
      await this.abortWith(new TransferError('digest_mismatch', 'whole-file digest mismatch'));
      return;
    }
    await this.o.sink.close();
    await this.sendControl(FrameType.Done, { type: FrameType.Done });
    this.settled = true;
    this.resolveDone({ file: this.file, digest: got });
  }

  private async abortWith(err: TransferError): Promise<void> {
    if (this.settled) return;
    this.settled = true;
    try {
      await this.sendControl(FrameType.Fail, { type: FrameType.Fail, reason: err.reason });
    } catch {
      // best-effort — the channel may already be gone
    }
    try {
      await this.o.sink.abort(err.reason);
    } catch {
      // best-effort
    }
    this.rejectDone(err);
  }

  private async sendControl(
    type: FrameType,
    msg: Parameters<typeof encodeControl>[0],
  ): Promise<void> {
    const header: FrameHeaderInput = {
      version: FRAME_VERSION,
      type,
      flags: 0,
      fileIdx: 0,
      blockIdx: 0,
      frameOff: 0,
    };
    const frame = await seal(this.o.sendDir, this.sendCounter++, header, encodeControl(msg));
    await this.o.send(frame);
  }
}
