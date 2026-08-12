/**
 * Receiving half of the transport-agnostic transfer engine.
 *
 * Blocks are authenticated, hashed, and committed before acknowledgement. A valid block arriving
 * ahead of the next required index exposes a gap: it is deliberately not committed, and the
 * receiver requests the missing block. Duplicate retransmissions are reverified and acknowledged
 * without being written or hashed twice. Any AEAD or block-hash failure aborts immediately.
 */

import { FrameReplayError, openSequenced, seal, type FrameHeaderInput } from './aead.js';
import type { DirectionalKey } from './keyschedule.js';
import { FrameType, type ControlOp, type FileEntry, type Manifest } from './transfer.js';
import { DEFAULT_INFLIGHT_BLOCKS, FRAME_VERSION } from './constants.js';
import { sha256 } from './webcrypto.js';
import { bytesToHex } from './bytes.js';
import {
  TransferError,
  singleSinkDestination,
  type Destination,
  type Digest,
  type Sink,
} from './transfer-ports.js';
import { decodeControl, encodeControl } from './transfer-messages.js';
import type { TransferRunState } from './transfer-sender.js';
import { validateManifest, MAX_MANIFEST_BLOCK_BYTES } from './safe-path.js';
import { completionDigest } from './transfer-set.js';

export interface ReceiveResult {
  files: FileEntry[];
  digests: string[];
  totalSize: number;
  /** Compatibility aliases for the first file and transfer completion digest. */
  file: FileEntry;
  digest: string;
}

/** Per-file seed a reloaded receiver restores so held blocks are neither re-fetched nor re-hashed. */
export interface ReceiverResumeFile {
  /** Consecutively-committed blocks already persisted for this file — its restored `nextBlock`. */
  haveBlocks: number;
  /**
   * A digest already fed exactly the persisted bytes `[0, haveBlocks)`. The receiver continues
   * updating it with the streamed remainder, so the whole-file digest still matches at completion.
   * The host owns this seam because only it can read the persisted bytes back.
   */
  seedDigest: Digest;
}

/** State a reloaded receiver restores to resume a transfer in place. */
export interface ReceiverResumeState {
  /**
   * Must equal the manifest's `transferId`. A mismatch means the room was reused for a different
   * file set, so the persisted offsets are ignored and a fresh receive starts.
   */
  transferId: string;
  files: ReadonlyMap<number, ReceiverResumeFile>;
}

export interface TransferReceiverOptions {
  send(frame: Uint8Array): void | Promise<void>;
  sendDir: DirectionalKey;
  recvDir: DirectionalKey;
  sendCounterStart: number;
  recvCounterStart: number;
  createDigest(): Digest;
  /** One-file compatibility destination. Exactly one of sink/destination is required. */
  sink?: Sink;
  destination?: Destination;
  /** Reports bytes only after verify-and-sink. */
  onProgress?(acknowledgedBytes: number): void;
  onFileProgress?(fileIdx: number, fileBytes: number, acknowledgedBytes: number): void;
  onStateChange?(state: TransferRunState): void;
  /** Called once with the validated complete file set before any destination opens. */
  onManifestSet?(manifest: Manifest): void | Promise<void>;
  /** Called for each file immediately before its sink opens. */
  onManifest?(file: FileEntry): void | Promise<void>;
  /**
   * Restored progress for a reloaded receiver. When the arriving manifest carries a matching
   * `transferId`, each file restarts at its `haveBlocks` high-water mark and the sender is asked to
   * stream only the missing blocks. Absent (or a `transferId` mismatch) means a fresh receive.
   */
  resume?: ReceiverResumeState;
}

export class TransferReceiver {
  private readonly o: TransferReceiverOptions;
  private readonly destination: Destination;

  private sendCounter: number;
  private recvCounter: number;
  private manifest: Manifest | undefined;
  private fileIdx = 0;
  private file: FileEntry | undefined;
  private sink: Sink | undefined;
  private digest: Digest | undefined;
  private readonly digests: string[] = [];
  private acknowledged = 0;
  private nextBlock = 0;
  private assemblingBlock = -1;
  private assemblingFileIdx = -1;
  private blockBuf: Uint8Array | undefined;
  private blockReceived = 0;
  private awaitingRestart = false;
  private readonly seenAhead = new Set<number>();
  private nackOutstanding: number | undefined;
  private paused = false;
  /** The caller's resume seed, kept only once its transferId matches the arriving manifest. */
  private activeResume: ReceiverResumeState | undefined;

  private resolveDone!: (r: ReceiveResult) => void;
  private rejectDone!: (e: Error) => void;
  readonly done: Promise<ReceiveResult>;
  private inbound: Promise<void> = Promise.resolve();
  private outbound: Promise<void> = Promise.resolve();
  private settled = false;

  constructor(opts: TransferReceiverOptions) {
    this.o = opts;
    if ((opts.sink === undefined) === (opts.destination === undefined)) {
      throw new Error('exactly one of sink or destination is required');
    }
    this.destination = opts.destination ?? singleSinkDestination(opts.sink!);
    this.sendCounter = opts.sendCounterStart;
    this.recvCounter = opts.recvCounterStart;
    this.done = new Promise<ReceiveResult>((res, rej) => {
      this.resolveDone = res;
      this.rejectDone = rej;
    });
    this.done.catch(() => {});
  }

  /** Feed one inbound encrypted frame from the sender. */
  handle(frame: Uint8Array): Promise<void> {
    this.inbound = this.inbound
      .then(() => this.process(frame))
      .catch((e: unknown) => {
        void this.abortWith(
          e instanceof TransferError
            ? e
            : new TransferError('integrity', e instanceof Error ? e.message : String(e)),
        );
      });
    return this.inbound;
  }

  /** Discard an unverified partial block when the host replaces the ordered byte path. */
  transportChanged(): Promise<void> {
    this.inbound = this.inbound.then(() => {
      this.blockBuf = undefined;
      this.blockReceived = 0;
      this.assemblingBlock = -1;
      this.assemblingFileIdx = -1;
      this.seenAhead.clear();
      this.nackOutstanding = undefined;
      this.awaitingRestart = true;
    });
    return this.inbound;
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
      opened = await openSequenced(this.o.recvDir, this.recvCounter, frame);
      this.recvCounter = opened.counter + 1;
    } catch (e) {
      if (e instanceof FrameReplayError) return;
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
    const msg = decodeControl(payload);
    if (msg.type !== FrameType.Manifest) throw new TransferError('integrity', 'expected manifest');
    let manifest;
    try {
      manifest = validateManifest(msg);
    } catch (e) {
      throw new TransferError('integrity', e instanceof Error ? e.message : String(e));
    }
    if (this.manifest) {
      // A path cutover can retransmit the manifest while the original is still
      // being processed. An identical copy is harmless; a different one is a
      // protocol violation (mirrors the Go wire receiver).
      if (manifestsEqual(manifest, this.manifest)) return;
      throw new TransferError('integrity', 'duplicate manifest');
    }
    try {
      await this.destination.prepare(manifest);
      await this.o.onManifestSet?.(manifest);
    } catch (e) {
      throw e instanceof TransferError
        ? e
        : new TransferError('sink_error', e instanceof Error ? e.message : String(e));
    }
    this.manifest = manifest;
    if (manifest.transferId !== undefined) {
      // The sender opted into resumption. Apply persisted offsets only when they belong to this
      // exact transfer, then report each file's high-water mark so the sender skips held blocks.
      this.activeResume =
        this.o.resume && this.o.resume.transferId === manifest.transferId
          ? this.o.resume
          : undefined;
      await this.sendResumeState(manifest);
    }
    await this.openNextFile();
  }

  private async sendResumeState(manifest: Manifest): Promise<void> {
    const files = manifest.files.map((file) => ({
      idx: file.idx,
      haveBlocks: Math.min(this.activeResume?.files.get(file.idx)?.haveBlocks ?? 0, file.blocks),
    }));
    await this.sendControl(FrameType.ResumeState, {
      type: FrameType.ResumeState,
      transferId: manifest.transferId!,
      files,
    });
  }

  /** Open the next file and immediately verify/close consecutive empty files. */
  private async openNextFile(): Promise<void> {
    const manifest = this.manifest;
    if (!manifest) throw new TransferError('integrity', 'file opened before manifest');
    while (this.fileIdx < manifest.files.length) {
      const file = manifest.files[this.fileIdx]!;
      this.file = file;
      const rf = this.activeResume?.files.get(file.idx);
      this.nextBlock = rf ? Math.min(rf.haveBlocks, file.blocks) : 0;
      this.seenAhead.clear();
      this.nackOutstanding = undefined;
      // The seed digest already holds the persisted prefix; the streamed remainder appends to it.
      this.digest = rf?.seedDigest ?? this.o.createDigest();
      // Persisted bytes count as acknowledged so progress resumes without a backwards jump.
      this.acknowledged +=
        this.nextBlock >= file.blocks ? file.size : this.nextBlock * file.blockSize;
      try {
        await this.o.onManifest?.(file);
        this.sink = await this.destination.open(file);
      } catch (e) {
        throw e instanceof TransferError
          ? e
          : new TransferError('sink_error', e instanceof Error ? e.message : String(e));
      }
      // Return to receive blocks only when some remain; empty and fully-held files finish now.
      if (this.nextBlock < file.blocks) return;
      await this.finishCurrentFile();
    }
    this.file = undefined;
    this.sink = undefined;
    this.digest = undefined;
  }

  private async finishCurrentFile(): Promise<void> {
    const file = this.file;
    const digest = this.digest;
    const sink = this.sink;
    if (!file || !digest || !sink) throw new TransferError('integrity', 'no active file');
    const got = await digest.hexDigest();
    if (got !== file.fileDigest) {
      throw new TransferError('digest_mismatch', `file ${file.idx} digest mismatch`);
    }
    try {
      await sink.close();
    } catch (e) {
      throw e instanceof TransferError
        ? e
        : new TransferError('sink_error', e instanceof Error ? e.message : String(e));
    }
    this.digests[file.idx] = got;
    this.o.onFileProgress?.(file.idx, file.size, this.acknowledged);
    this.fileIdx++;
    this.file = undefined;
    this.sink = undefined;
    this.digest = undefined;
  }

  private onBlockData(
    fileIdx: number,
    blockIdx: number,
    frameOff: number,
    payload: Uint8Array,
  ): void {
    const manifest = this.manifest;
    if (!manifest) {
      // A cutover may lose the manifest while block data is already streaming;
      // the sender retransmits it, so stray data before the manifest is ignored
      // rather than treated as a protocol violation (mirrors the Go wire receiver).
      return;
    }
    const entry = manifest.files[fileIdx];
    if (!entry || fileIdx > this.fileIdx || blockIdx < 0 || blockIdx >= entry.blocks) {
      throw new TransferError('integrity', `block_data outside manifest: ${blockIdx}`);
    }
    if (this.awaitingRestart && frameOff !== 0) return;
    if (frameOff === 0) {
      if (this.blockBuf) throw new TransferError('integrity', 'new block before block_hash');
      const blockLen = Math.min(
        entry.blockSize,
        MAX_MANIFEST_BLOCK_BYTES,
        entry.size - blockIdx * entry.blockSize,
      );
      this.assemblingFileIdx = fileIdx;
      this.assemblingBlock = blockIdx;
      this.blockBuf = new Uint8Array(blockLen);
      this.blockReceived = 0;
      this.awaitingRestart = false;
    }
    if (!this.blockBuf || this.assemblingFileIdx !== fileIdx || this.assemblingBlock !== blockIdx) {
      throw new TransferError('integrity', `unexpected block fragment ${blockIdx}`);
    }
    if (frameOff !== this.blockReceived || frameOff + payload.length > this.blockBuf.length) {
      throw new TransferError('integrity', `invalid frame offset in block ${blockIdx}`);
    }
    this.blockBuf.set(payload, frameOff);
    this.blockReceived += payload.length;
  }

  private async onBlockHash(payload: Uint8Array): Promise<void> {
    const block = this.blockBuf;
    if (!block && this.awaitingRestart) return;
    if (!this.manifest) return; // pre-manifest; the manifest may be in flight after a cutover
    if (!block) {
      throw new TransferError('integrity', 'block_hash without a block');
    }
    const msg = decodeControl(payload);
    if (msg.type !== FrameType.BlockHash) {
      throw new TransferError('integrity', 'expected block_hash');
    }
    if (msg.fileIdx !== this.assemblingFileIdx || msg.blockIdx !== this.assemblingBlock) {
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
    this.assemblingFileIdx = -1;

    if (msg.fileIdx < this.fileIdx) {
      await this.sendAck(msg.fileIdx, msg.blockIdx);
      return;
    }
    const file = this.file;
    const sink = this.sink;
    const digest = this.digest;
    if (!file || !sink || !digest || msg.fileIdx !== this.fileIdx) {
      throw new TransferError('integrity', 'block_hash for inactive file');
    }

    if (msg.blockIdx < this.nextBlock) {
      await this.sendAck(msg.fileIdx, msg.blockIdx);
      return;
    }
    if (msg.blockIdx > this.nextBlock) {
      if (this.seenAhead.size < DEFAULT_INFLIGHT_BLOCKS) this.seenAhead.add(msg.blockIdx);
      await this.requestMissing();
      return;
    }

    const offset = this.nextBlock * file.blockSize;
    try {
      await sink.write(offset, block);
    } catch (e) {
      throw e instanceof TransferError
        ? e
        : new TransferError('sink_error', e instanceof Error ? e.message : String(e));
    }
    digest.update(block);
    this.nextBlock++;
    this.nackOutstanding = undefined;
    this.acknowledged += block.length;
    this.o.onProgress?.(this.acknowledged);
    this.o.onFileProgress?.(file.idx, offset + block.length, this.acknowledged);
    await this.sendAck(msg.fileIdx, msg.blockIdx);

    if (this.nextBlock === file.blocks) {
      await this.finishCurrentFile();
      await this.openNextFile();
    } else if (this.seenAhead.delete(this.nextBlock)) {
      await this.requestMissing();
    }
  }

  private async sendAck(fileIdx: number, blockIdx: number): Promise<void> {
    await this.sendControl(FrameType.Ack, {
      type: FrameType.Ack,
      fileIdx,
      blockIdx,
    });
  }

  private async requestMissing(): Promise<void> {
    if (this.nackOutstanding === this.nextBlock) return;
    this.nackOutstanding = this.nextBlock;
    await this.sendControl(FrameType.Nack, {
      type: FrameType.Nack,
      fileIdx: this.fileIdx,
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
    const manifest = this.manifest;
    if (!manifest) throw new TransferError('integrity', 'complete before manifest');
    const msg = decodeControl(payload);
    if (msg.type !== FrameType.Complete) throw new TransferError('integrity', 'expected complete');
    if (this.file && this.nextBlock !== this.file.blocks) {
      await this.requestMissing();
      return;
    }
    if (this.fileIdx !== manifest.files.length) {
      throw new TransferError('integrity', 'complete before every file was received');
    }
    const got = await completionDigest(manifest.files);
    if (got !== msg.fileDigest) throw new TransferError('digest_mismatch', 'file-set mismatch');
    try {
      await this.destination.close();
    } catch (e) {
      throw e instanceof TransferError
        ? e
        : new TransferError('sink_error', e instanceof Error ? e.message : String(e));
    }
    await this.sendControl(FrameType.Done, { type: FrameType.Done });
    this.settled = true;
    this.resolveDone({
      files: manifest.files,
      digests: [...this.digests],
      totalSize: manifest.totalSize,
      file: manifest.files[0]!,
      digest: got,
    });
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
      await this.destination.abort(err.reason);
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

// manifestsEqual reports whether two validated manifests describe the same
// transfer: same id, same total size, and identical file entries.
function manifestsEqual(a: Manifest, b: Manifest): boolean {
  if (
    a.transferId !== b.transferId ||
    a.totalSize !== b.totalSize ||
    a.files.length !== b.files.length
  ) {
    return false;
  }
  return a.files.every((file, i) => {
    const other = b.files[i];
    if (!other) return false;
    return (
      file.idx === other.idx &&
      file.name === other.name &&
      file.size === other.size &&
      file.mime === other.mime &&
      file.lastModified === other.lastModified &&
      file.blockSize === other.blockSize &&
      file.blocks === other.blocks &&
      file.fileDigest === other.fileDigest
    );
  });
}
