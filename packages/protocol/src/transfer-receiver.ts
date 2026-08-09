/**
 * Receiving half of the transport-agnostic transfer engine.
 *
 * Blocks are authenticated, hashed, and committed before acknowledgement. A valid block arriving
 * ahead of the next required index exposes a gap: it is deliberately not committed, and the
 * receiver requests the missing block. Duplicate retransmissions are reverified and acknowledged
 * without being written or hashed twice. Any AEAD or block-hash failure aborts immediately.
 */

import { open, seal, type FrameHeaderInput } from './aead.js';
import type { DirectionalKey } from './keyschedule.js';
import { FrameType, type ControlOp, type FileEntry } from './transfer.js';
import { DEFAULT_INFLIGHT_BLOCKS, FRAME_VERSION } from './constants.js';
import { sha256 } from './webcrypto.js';
import { bytesToHex } from './bytes.js';
import { TransferError, type Digest, type Sink } from './transfer-ports.js';
import { decodeControl, encodeControl } from './transfer-messages.js';
import type { TransferRunState } from './transfer-sender.js';
import { validateManifest } from './safe-path.js';

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
  /** Reports bytes only after verify-and-sink. */
  onProgress?(acknowledgedBytes: number): void;
  onStateChange?(state: TransferRunState): void;
  /** Called once after the manifest is validated and before the first sink write. */
  onManifest?(file: FileEntry): void | Promise<void>;
}

export class TransferReceiver {
  private readonly o: TransferReceiverOptions;
  private readonly digest: Digest;

  private sendCounter: number;
  private recvCounter: number;
  private file: FileEntry | undefined;
  private nextBlock = 0;
  private assemblingBlock = -1;
  private blockBuf: Uint8Array | undefined;
  private blockReceived = 0;
  private readonly seenAhead = new Set<number>();
  private nackOutstanding: number | undefined;
  private paused = false;

  private resolveDone!: (r: ReceiveResult) => void;
  private rejectDone!: (e: Error) => void;
  readonly done: Promise<ReceiveResult>;
  private inbound: Promise<void> = Promise.resolve();
  private outbound: Promise<void> = Promise.resolve();
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

  /** Feed one inbound encrypted frame from the sender. */
  handle(frame: Uint8Array): void {
    this.inbound = this.inbound
      .then(() => this.process(frame))
      .catch((e: unknown) => {
        void this.abortWith(
          e instanceof TransferError
            ? e
            : new TransferError('integrity', e instanceof Error ? e.message : String(e)),
        );
      });
  }

  /** Ask the sender to stop producing data frames. Buffered transport bytes may still drain. */
  pause(): void {
    if (this.settled || this.paused) return;
    this.setPaused(true);
    void this.sendControl(FrameType.Control, { type: FrameType.Control, op: 'pause' }).catch(
      (e: unknown) => void this.abortWith(asIntegrityError(e)),
    );
  }

  /** Ask the sender to continue. */
  resume(): void {
    if (this.settled || !this.paused) return;
    this.setPaused(false);
    void this.sendControl(FrameType.Control, { type: FrameType.Control, op: 'resume' }).catch(
      (e: unknown) => void this.abortWith(asIntegrityError(e)),
    );
  }

  /** Best-effort peer notification followed by terminal local cancellation. */
  cancel(reason = 'canceled'): void {
    if (this.settled) return;
    this.o.onStateChange?.('canceled');
    void this.sendControl(FrameType.Control, { type: FrameType.Control, op: 'cancel' })
      .catch(() => {})
      .finally(
        () => void this.abortWith(new TransferError('canceled', reason), { notifyPeer: false }),
      );
  }

  private async process(frame: Uint8Array): Promise<void> {
    if (this.settled) return;
    let opened;
    try {
      opened = await open(this.o.recvDir, this.recvCounter++, frame);
    } catch (e) {
      throw new TransferError(
        'integrity',
        e instanceof Error ? e.message : 'unable to authenticate transfer frame',
      );
    }
    switch (opened.header.type) {
      case FrameType.Manifest:
        return this.applyManifest(opened.plaintext);
      case FrameType.BlockData:
        return this.onBlockData(
          opened.header.fileIdx,
          opened.header.blockIdx,
          opened.header.frameOff,
          opened.plaintext,
        );
      case FrameType.BlockHash:
        return this.onBlockHash(opened.plaintext);
      case FrameType.Control:
        return this.onControl(opened.plaintext);
      case FrameType.Complete:
        return this.onComplete(opened.plaintext);
      case FrameType.Fail:
        return this.onPeerFail(opened.plaintext);
      default:
        throw new TransferError(
          'integrity',
          `unexpected receiver-inbound type ${opened.header.type}`,
        );
    }
  }

  private async applyManifest(payload: Uint8Array): Promise<void> {
    if (this.file) throw new TransferError('integrity', 'duplicate manifest');
    const msg = decodeControl(payload);
    if (msg.type !== FrameType.Manifest) throw new TransferError('integrity', 'expected manifest');
    let manifest;
    try {
      manifest = validateManifest(msg);
    } catch (e) {
      throw new TransferError('integrity', e instanceof Error ? e.message : String(e));
    }
    const file = manifest.files[0];
    if (!file || manifest.files.length !== 1) {
      throw new TransferError('integrity', 'single-file manifest required');
    }
    this.file = file;
    try {
      await this.o.onManifest?.(file);
    } catch (e) {
      throw e instanceof TransferError
        ? e
        : new TransferError('sink_error', e instanceof Error ? e.message : String(e));
    }
  }

  private onBlockData(
    fileIdx: number,
    blockIdx: number,
    frameOff: number,
    payload: Uint8Array,
  ): void {
    const file = this.file;
    if (!file) throw new TransferError('integrity', 'block_data before manifest');
    if (fileIdx !== 0 || blockIdx < 0 || blockIdx >= file.blocks) {
      throw new TransferError('integrity', `block_data outside manifest: ${blockIdx}`);
    }
    if (frameOff === 0) {
      if (this.blockBuf) throw new TransferError('integrity', 'new block before block_hash');
      const blockLen = Math.min(file.blockSize, file.size - blockIdx * file.blockSize);
      this.assemblingBlock = blockIdx;
      this.blockBuf = new Uint8Array(blockLen);
      this.blockReceived = 0;
    }
    if (!this.blockBuf || this.assemblingBlock !== blockIdx) {
      throw new TransferError('integrity', `unexpected block fragment ${blockIdx}`);
    }
    if (frameOff !== this.blockReceived || frameOff + payload.length > this.blockBuf.length) {
      throw new TransferError('integrity', `invalid frame offset in block ${blockIdx}`);
    }
    this.blockBuf.set(payload, frameOff);
    this.blockReceived += payload.length;
  }

  private async onBlockHash(payload: Uint8Array): Promise<void> {
    const file = this.file;
    const block = this.blockBuf;
    if (!file || !block) throw new TransferError('integrity', 'block_hash without a block');
    const msg = decodeControl(payload);
    if (msg.type !== FrameType.BlockHash) {
      throw new TransferError('integrity', 'expected block_hash');
    }
    if (msg.fileIdx !== 0 || msg.blockIdx !== this.assemblingBlock) {
      throw new TransferError('integrity', 'block_hash does not match assembled block');
    }
    if (this.blockReceived !== block.length) throw new TransferError('integrity', 'short block');
    const got = bytesToHex(await sha256(block));
    if (got !== msg.sha256) {
      throw new TransferError('integrity', `block ${msg.blockIdx} hash mismatch`);
    }

    this.blockBuf = undefined;
    this.blockReceived = 0;
    this.assemblingBlock = -1;

    if (msg.blockIdx < this.nextBlock) {
      await this.sendAck(msg.blockIdx); // verified duplicate; acknowledgement was likely lost
      return;
    }
    if (msg.blockIdx > this.nextBlock) {
      if (this.seenAhead.size < DEFAULT_INFLIGHT_BLOCKS) this.seenAhead.add(msg.blockIdx);
      await this.requestMissing();
      return;
    }

    const offset = this.nextBlock * file.blockSize;
    try {
      await this.o.sink.write(offset, block);
    } catch (e) {
      throw e instanceof TransferError
        ? e
        : new TransferError('sink_error', e instanceof Error ? e.message : String(e));
    }
    this.digest.update(block);
    this.nextBlock++;
    this.nackOutstanding = undefined;
    this.o.onProgress?.(offset + block.length);
    await this.sendAck(msg.blockIdx);

    if (this.seenAhead.delete(this.nextBlock)) await this.requestMissing();
  }

  private async sendAck(blockIdx: number): Promise<void> {
    await this.sendControl(FrameType.Ack, {
      type: FrameType.Ack,
      fileIdx: 0,
      blockIdx,
    });
  }

  private async requestMissing(): Promise<void> {
    if (this.nackOutstanding === this.nextBlock) return;
    this.nackOutstanding = this.nextBlock;
    await this.sendControl(FrameType.Nack, {
      type: FrameType.Nack,
      fileIdx: 0,
      blockIdx: this.nextBlock,
      reason: 'missing',
    });
  }

  private onControl(payload: Uint8Array): void {
    const msg = decodeControl(payload);
    if (msg.type !== FrameType.Control) throw new TransferError('integrity', 'expected control');
    this.applyRemoteControl(msg.op);
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
        void this.abortWith(new TransferError('canceled', 'peer canceled the transfer'), {
          notifyPeer: false,
        });
    }
  }

  private setPaused(paused: boolean): void {
    if (this.paused === paused || this.settled) return;
    this.paused = paused;
    this.o.onStateChange?.(paused ? 'paused' : 'running');
  }

  private async onPeerFail(payload: Uint8Array): Promise<void> {
    const msg = decodeControl(payload);
    if (msg.type !== FrameType.Fail) throw new TransferError('integrity', 'expected fail');
    await this.abortWith(new TransferError(msg.reason, `sender failed: ${msg.reason}`), {
      notifyPeer: false,
    });
  }

  private async onComplete(payload: Uint8Array): Promise<void> {
    const file = this.file;
    if (!file) throw new TransferError('integrity', 'complete before manifest');
    const msg = decodeControl(payload);
    if (msg.type !== FrameType.Complete) throw new TransferError('integrity', 'expected complete');
    if (this.nextBlock !== file.blocks) {
      await this.requestMissing();
      return;
    }
    const got = await this.digest.hexDigest();
    if (msg.fileDigest !== file.fileDigest || got !== msg.fileDigest) {
      throw new TransferError('digest_mismatch', 'whole-file digest mismatch');
    }
    try {
      await this.o.sink.close();
    } catch (e) {
      throw e instanceof TransferError
        ? e
        : new TransferError('sink_error', e instanceof Error ? e.message : String(e));
    }
    await this.sendControl(FrameType.Done, { type: FrameType.Done });
    this.settled = true;
    this.resolveDone({ file, digest: got });
  }

  private async abortWith(
    err: TransferError,
    options: { notifyPeer?: boolean } = {},
  ): Promise<void> {
    if (this.settled) return;
    this.settled = true;
    if (options.notifyPeer !== false) {
      try {
        await this.sendControl(FrameType.Fail, { type: FrameType.Fail, reason: err.reason });
      } catch {
        // The channel may already be unavailable.
      }
    }
    try {
      await this.o.sink.abort(err.reason);
    } catch {
      // Sink abort is best-effort after the first terminal failure.
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
    await this.sendFrame(header, encodeControl(msg));
  }

  /** Serialize sealing so UI controls and acknowledgements cannot reuse a nonce. */
  private sendFrame(header: FrameHeaderInput, payload: Uint8Array): Promise<void> {
    const task = this.outbound.then(async () => {
      const frame = await seal(this.o.sendDir, this.sendCounter++, header, payload);
      await this.o.send(frame);
    });
    this.outbound = task.catch(() => {});
    return task;
  }
}

function asIntegrityError(e: unknown): TransferError {
  return e instanceof TransferError
    ? e
    : new TransferError('integrity', e instanceof Error ? e.message : String(e));
}
