import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { deriveTransferKeys } from './keyschedule.js';
import { open, seal, type FrameHeaderInput } from './aead.js';
import { FrameType } from './transfer.js';
import { FRAME_VERSION } from './constants.js';
import { sha256 } from './webcrypto.js';
import { bytesToHex } from './bytes.js';
import { decodeControl, encodeControl } from './transfer-messages.js';
import {
  MemorySink,
  type Digest,
  type DigestState,
  type DigestStateSink,
  type Sink,
} from './transfer-ports.js';
import { TransferReceiver } from './transfer-receiver.js';

function nodeDigest(): Digest {
  const h = createHash('sha256');
  return { update: (b) => void h.update(b), hexDigest: () => h.digest('hex') };
}

/** Digest whose optional state serialization always fails (V13-PR05 regression). */
class StateFailDigest implements Digest, DigestState {
  private readonly h = createHash('sha256');
  update(bytes: Uint8Array): void {
    this.h.update(bytes);
  }
  hexDigest(): string {
    return this.h.digest('hex');
  }
  saveState(): Uint8Array {
    throw new Error('serialization failed');
  }
}

/** Sink with the optional DigestStateSink seam, recording every state it was handed. */
class StateRecordSink implements Sink, DigestStateSink {
  states: Array<Uint8Array | null> = [];
  chunks: Uint8Array[] = [];
  write(_offset: number, bytes: Uint8Array): void {
    this.chunks.push(bytes);
  }
  close(): void {}
  abort(): void {}
  setDigestState(state: Uint8Array | null): void {
    this.states.push(state);
  }
}

/** Sink whose state persistence (the journal write) genuinely fails. */
class FailingStateSink implements Sink, DigestStateSink {
  write(): void {}
  close(): void {}
  abort(): void {}
  setDigestState(): void {
    throw new Error('journal write failed');
  }
}
const master = new Uint8Array(32).fill(9);

// Minimal sender-side frame builders over the o2j direction.
async function build(keys: Awaited<ReturnType<typeof deriveTransferKeys>>) {
  let ctr = 0;
  const frames: Uint8Array[] = [];
  const push = async (header: FrameHeaderInput, payload: Uint8Array) => {
    frames.push(await seal(keys.o2j, ctr++, header, payload));
  };
  const ctrl = (type: FrameType, msg: Parameters<typeof encodeControl>[0]) =>
    push(
      { version: FRAME_VERSION, type, flags: 0, fileIdx: 0, blockIdx: 0, frameOff: 0 },
      encodeControl(msg),
    );
  return { frames, push, ctrl };
}

describe('TransferReceiver', () => {
  it('assembles blocks, verifies, writes the sink, and reports done', async () => {
    const keys = await deriveTransferKeys(master);
    const data = new Uint8Array(20).map((_, i) => (i * 7) & 0xff); // block=8: blocks 0,1 (8B), block2 (4B)
    const blockSize = 8;
    const fileDigest = createHash('sha256').update(data).digest('hex');
    const b = await build(keys);

    await b.ctrl(FrameType.Manifest, {
      type: FrameType.Manifest,
      files: [
        {
          idx: 0,
          name: 'f',
          size: 20,
          mime: '',
          lastModified: 0,
          blockSize,
          blocks: 3,
          fileDigest,
        },
      ],
      totalSize: 20,
    });
    for (let blk = 0; blk * blockSize < data.length; blk++) {
      const start = blk * blockSize;
      const end = Math.min(start + blockSize, data.length);
      const block = data.subarray(start, end);
      // one frame per 4 bytes
      for (let off = 0; off < block.length; off += 4) {
        const frag = block.subarray(off, Math.min(off + 4, block.length));
        const last = off + frag.length === block.length;
        await b.push(
          {
            version: FRAME_VERSION,
            type: FrameType.BlockData,
            flags: last ? 1 : 0,
            fileIdx: 0,
            blockIdx: blk,
            frameOff: off,
          },
          frag,
        );
      }
      await b.ctrl(FrameType.BlockHash, {
        type: FrameType.BlockHash,
        fileIdx: 0,
        blockIdx: blk,
        sha256: bytesToHex(await sha256(block)),
      });
    }
    await b.ctrl(FrameType.Complete, { type: FrameType.Complete, fileDigest });

    const sink = new MemorySink();
    const backChannel: Uint8Array[] = [];
    const receiver = new TransferReceiver({
      send: (f) => void backChannel.push(f),
      sendDir: keys.j2o,
      recvDir: keys.o2j,
      sendCounterStart: 0,
      recvCounterStart: 0,
      createDigest: nodeDigest,
      sink,
    });
    for (const f of b.frames) receiver.handle(f);
    const result = await receiver.done;

    expect(result.digest).toBe(fileDigest);
    expect([...sink.bytes()]).toEqual([...data]);
    expect(sink.isClosed).toBe(true);
    // Back-channel: verified ACK ×3 then done.
    let c = 0;
    const backTypes: number[] = [];
    for (const f of backChannel) backTypes.push((await open(keys.j2o, c++, f)).header.type);
    expect(backTypes).toEqual([FrameType.Ack, FrameType.Ack, FrameType.Ack, FrameType.Done]);
  });

  it('a digest whose saveState throws omits the checkpoint but the receive completes (V13-PR05)', async () => {
    const keys = await deriveTransferKeys(master);
    const data = new Uint8Array(16).map((_, i) => i);
    const fileDigest = createHash('sha256').update(data).digest('hex');
    const b = await build(keys);
    await b.ctrl(FrameType.Manifest, {
      type: FrameType.Manifest,
      files: [
        {
          idx: 0,
          name: 'f',
          size: 16,
          mime: '',
          lastModified: 0,
          blockSize: 8,
          blocks: 2,
          fileDigest,
        },
      ],
      totalSize: 16,
    });
    for (let blk = 0; blk * 8 < data.length; blk++) {
      const block = data.subarray(blk * 8, Math.min(blk * 8 + 8, data.length));
      await b.push(
        {
          version: FRAME_VERSION,
          type: FrameType.BlockData,
          flags: 1,
          fileIdx: 0,
          blockIdx: blk,
          frameOff: 0,
        },
        block,
      );
      await b.ctrl(FrameType.BlockHash, {
        type: FrameType.BlockHash,
        fileIdx: 0,
        blockIdx: blk,
        sha256: bytesToHex(await sha256(block)),
      });
    }
    await b.ctrl(FrameType.Complete, { type: FrameType.Complete, fileDigest });

    // Serialization of the optimization state fails: the sink must be handed null (the
    // durable host journals a checkpoint without digest state and resume re-hashes).
    const sink = new StateRecordSink();
    const receiver = new TransferReceiver({
      send: () => void Promise.resolve(),
      sendDir: keys.j2o,
      recvDir: keys.o2j,
      sendCounterStart: 0,
      recvCounterStart: 0,
      createDigest: () => new StateFailDigest(),
      sink,
    });
    for (const f of b.frames) receiver.handle(f);
    const result = await receiver.done;
    expect(result.digest).toBe(fileDigest);
    expect(sink.states).toEqual([null, null]);
    expect(sink.chunks.flatMap((c) => [...c])).toEqual([...data]);
  });

  it('a failing setDigestState still fails the receive (genuine journal failure, V13-PR05)', async () => {
    const keys = await deriveTransferKeys(master);
    const data = new Uint8Array(8).map((_, i) => i);
    const fileDigest = createHash('sha256').update(data).digest('hex');
    const b = await build(keys);
    await b.ctrl(FrameType.Manifest, {
      type: FrameType.Manifest,
      files: [
        {
          idx: 0,
          name: 'f',
          size: 8,
          mime: '',
          lastModified: 0,
          blockSize: 8,
          blocks: 1,
          fileDigest,
        },
      ],
      totalSize: 8,
    });
    await b.push(
      {
        version: FRAME_VERSION,
        type: FrameType.BlockData,
        flags: 1,
        fileIdx: 0,
        blockIdx: 0,
        frameOff: 0,
      },
      data,
    );
    await b.ctrl(FrameType.BlockHash, {
      type: FrameType.BlockHash,
      fileIdx: 0,
      blockIdx: 0,
      sha256: bytesToHex(await sha256(data)),
    });
    await b.ctrl(FrameType.Complete, { type: FrameType.Complete, fileDigest });

    const receiver = new TransferReceiver({
      send: () => void Promise.resolve(),
      sendDir: keys.j2o,
      recvDir: keys.o2j,
      sendCounterStart: 0,
      recvCounterStart: 0,
      createDigest: nodeDigest,
      sink: new FailingStateSink(),
    });
    for (const f of b.frames) receiver.handle(f);
    await expect(receiver.done).rejects.toThrow(/sink_error/);
  });

  it('ignores pre-manifest data and identical duplicate manifests (cutover recovery)', async () => {
    const keys = await deriveTransferKeys(master);
    const data = new Uint8Array(8).map((_, i) => i);
    const fileDigest = createHash('sha256').update(data).digest('hex');
    const b = await build(keys);
    const manifest = {
      type: FrameType.Manifest,
      files: [
        {
          idx: 0,
          name: 'f',
          size: 8,
          mime: '',
          lastModified: 0,
          blockSize: 8,
          blocks: 1,
          fileDigest,
        },
      ],
      totalSize: 8,
    };

    // A path cutover can deliver block data before the manifest arrives; it must
    // be ignored, not treated as a protocol violation.
    await b.push(
      {
        version: FRAME_VERSION,
        type: FrameType.BlockData,
        flags: 1,
        fileIdx: 0,
        blockIdx: 0,
        frameOff: 0,
      },
      data,
    );
    await b.ctrl(FrameType.Manifest, manifest);
    // The sender may then retransmit the identical manifest on the new path.
    await b.ctrl(FrameType.Manifest, manifest);
    await b.push(
      {
        version: FRAME_VERSION,
        type: FrameType.BlockData,
        flags: 1,
        fileIdx: 0,
        blockIdx: 0,
        frameOff: 0,
      },
      data,
    );
    await b.ctrl(FrameType.BlockHash, {
      type: FrameType.BlockHash,
      fileIdx: 0,
      blockIdx: 0,
      sha256: bytesToHex(await sha256(data)),
    });
    await b.ctrl(FrameType.Complete, { type: FrameType.Complete, fileDigest });

    const sink = new MemorySink();
    const receiver = new TransferReceiver({
      send: () => {},
      sendDir: keys.j2o,
      recvDir: keys.o2j,
      sendCounterStart: 0,
      recvCounterStart: 0,
      createDigest: nodeDigest,
      sink,
    });
    for (const f of b.frames) receiver.handle(f);
    const result = await receiver.done;
    expect(result.digest).toBe(fileDigest);
    expect([...sink.bytes()]).toEqual([...data]);
  });

  it('aborts with integrity on a corrupted frame (GCM failure)', async () => {
    const keys = await deriveTransferKeys(master);
    const data = new Uint8Array(8).map((_, i) => i);
    const fileDigest = createHash('sha256').update(data).digest('hex');
    const b = await build(keys);
    await b.ctrl(FrameType.Manifest, {
      type: FrameType.Manifest,
      files: [
        {
          idx: 0,
          name: 'f',
          size: 8,
          mime: '',
          lastModified: 0,
          blockSize: 8,
          blocks: 1,
          fileDigest,
        },
      ],
      totalSize: 8,
    });
    await b.push(
      {
        version: FRAME_VERSION,
        type: FrameType.BlockData,
        flags: 1,
        fileIdx: 0,
        blockIdx: 0,
        frameOff: 0,
      },
      data,
    );
    b.frames.at(-1)![b.frames.at(-1)!.length - 1] ^= 0x01; // corrupt the tag

    const sink = new MemorySink();
    const backChannel: Uint8Array[] = [];
    const receiver = new TransferReceiver({
      send: (frame) => void backChannel.push(frame),
      sendDir: keys.j2o,
      recvDir: keys.o2j,
      sendCounterStart: 0,
      recvCounterStart: 0,
      createDigest: nodeDigest,
      sink,
    });
    for (const f of b.frames) receiver.handle(f);
    await expect(receiver.done).rejects.toThrow(/integrity/);
    expect(sink.abortReason).toBe('integrity');
    expect(backChannel).toHaveLength(1);
    expect((await open(keys.j2o, 0, backChannel[0]!)).header.type).toBe(FrameType.Fail);
  });

  it('invokes onManifest with the file entry before writing the first block', async () => {
    const keys = await deriveTransferKeys(master);
    const data = new Uint8Array(8).map((_, i) => i);
    const fileDigest = createHash('sha256').update(data).digest('hex');
    const b = await build(keys);
    await b.ctrl(FrameType.Manifest, {
      type: FrameType.Manifest,
      files: [
        {
          idx: 0,
          name: 'note.txt',
          size: 8,
          mime: 'text/plain',
          lastModified: 0,
          blockSize: 8,
          blocks: 1,
          fileDigest,
        },
      ],
      totalSize: 8,
    });
    await b.push(
      {
        version: FRAME_VERSION,
        type: FrameType.BlockData,
        flags: 1,
        fileIdx: 0,
        blockIdx: 0,
        frameOff: 0,
      },
      data,
    );
    await b.ctrl(FrameType.BlockHash, {
      type: FrameType.BlockHash,
      fileIdx: 0,
      blockIdx: 0,
      sha256: bytesToHex(await sha256(data)),
    });
    await b.ctrl(FrameType.Complete, { type: FrameType.Complete, fileDigest });

    const events: string[] = [];
    const seen: string[] = [];
    const sink: Sink = {
      write: () => void events.push('write'),
      close: () => {},
      abort: () => {},
    };
    const receiver = new TransferReceiver({
      send: () => {},
      sendDir: keys.j2o,
      recvDir: keys.o2j,
      sendCounterStart: 0,
      recvCounterStart: 0,
      createDigest: nodeDigest,
      sink,
      onManifest: (file) => {
        events.push('manifest');
        seen.push(file.name);
      },
    });
    for (const f of b.frames) receiver.handle(f);
    await receiver.done;

    expect(seen).toEqual(['note.txt']);
    expect(events[0]).toBe('manifest');
    expect(events).toContain('write');
    expect(events.indexOf('manifest')).toBeLessThan(events.indexOf('write'));
  });

  it('fails digest_mismatch when complete disagrees', async () => {
    const keys = await deriveTransferKeys(master);
    const data = new Uint8Array(8).map((_, i) => i);
    const b = await build(keys);
    await b.ctrl(FrameType.Manifest, {
      type: FrameType.Manifest,
      files: [
        {
          idx: 0,
          name: 'f',
          size: 8,
          mime: '',
          lastModified: 0,
          blockSize: 8,
          blocks: 1,
          fileDigest: 'ff',
        },
      ],
      totalSize: 8,
    });
    await b.push(
      {
        version: FRAME_VERSION,
        type: FrameType.BlockData,
        flags: 1,
        fileIdx: 0,
        blockIdx: 0,
        frameOff: 0,
      },
      data,
    );
    await b.ctrl(FrameType.BlockHash, {
      type: FrameType.BlockHash,
      fileIdx: 0,
      blockIdx: 0,
      sha256: bytesToHex(await sha256(data)),
    });
    await b.ctrl(FrameType.Complete, { type: FrameType.Complete, fileDigest: 'deadbeef' });

    const receiver = new TransferReceiver({
      send: () => {},
      sendDir: keys.j2o,
      recvDir: keys.o2j,
      sendCounterStart: 0,
      recvCounterStart: 0,
      createDigest: nodeDigest,
      sink: new MemorySink(),
    });
    for (const f of b.frames) receiver.handle(f);
    await expect(receiver.done).rejects.toThrow(/digest_mismatch/);
  });

  it('requests a missing block, reorders by retransmission, and verifies the file', async () => {
    const keys = await deriveTransferKeys(master);
    const first = new Uint8Array([1, 2, 3, 4]);
    const second = new Uint8Array([5, 6, 7, 8]);
    const data = new Uint8Array([...first, ...second]);
    const fileDigest = createHash('sha256').update(data).digest('hex');
    const b = await build(keys);
    await b.ctrl(FrameType.Manifest, {
      type: FrameType.Manifest,
      files: [
        {
          idx: 0,
          name: 'reordered.bin',
          size: data.length,
          mime: '',
          lastModified: 0,
          blockSize: 4,
          blocks: 2,
          fileDigest,
        },
      ],
      totalSize: data.length,
    });
    const addBlock = async (blockIdx: number, block: Uint8Array) => {
      await b.push(
        {
          version: FRAME_VERSION,
          type: FrameType.BlockData,
          flags: 1,
          fileIdx: 0,
          blockIdx,
          frameOff: 0,
        },
        block,
      );
      await b.ctrl(FrameType.BlockHash, {
        type: FrameType.BlockHash,
        fileIdx: 0,
        blockIdx,
        sha256: bytesToHex(await sha256(block)),
      });
    };

    // A transport transition exposes block 1 before block 0. The first copy of block 1 is
    // authenticated but not committed; both blocks then arrive in the requested order.
    await addBlock(1, second);
    await addBlock(0, first);
    await addBlock(1, second);
    await b.ctrl(FrameType.Complete, { type: FrameType.Complete, fileDigest });

    const sink = new MemorySink();
    const backChannel: Uint8Array[] = [];
    const receiver = new TransferReceiver({
      send: (frame) => void backChannel.push(frame),
      sendDir: keys.j2o,
      recvDir: keys.o2j,
      sendCounterStart: 0,
      recvCounterStart: 0,
      createDigest: nodeDigest,
      sink,
    });
    for (const frame of b.frames) receiver.handle(frame);
    const result = await receiver.done;

    expect(result.digest).toBe(fileDigest);
    expect(sink.bytes()).toEqual(data);
    let counter = 0;
    const controls = [];
    for (const frame of backChannel) {
      controls.push(decodeControl((await open(keys.j2o, counter++, frame)).plaintext));
    }
    expect(controls).toEqual([
      { type: FrameType.Nack, fileIdx: 0, blockIdx: 0, reason: 'missing' },
      { type: FrameType.Ack, fileIdx: 0, blockIdx: 0 },
      { type: FrameType.Nack, fileIdx: 0, blockIdx: 1, reason: 'missing' },
      { type: FrameType.Ack, fileIdx: 0, blockIdx: 1 },
      { type: FrameType.Done },
    ]);
  });

  it('discards an unverified partial block when the ordered transport changes', async () => {
    const keys = await deriveTransferKeys(master);
    const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const fileDigest = createHash('sha256').update(data).digest('hex');
    const b = await build(keys);
    await b.ctrl(FrameType.Manifest, {
      type: FrameType.Manifest,
      files: [
        {
          idx: 0,
          name: 'switched.bin',
          size: data.length,
          mime: '',
          lastModified: 0,
          blockSize: 8,
          blocks: 1,
          fileDigest,
        },
      ],
      totalSize: data.length,
    });
    await b.push(
      {
        version: FRAME_VERSION,
        type: FrameType.BlockData,
        flags: 0,
        fileIdx: 0,
        blockIdx: 0,
        frameOff: 0,
      },
      data.subarray(0, 4),
    );
    const partialEnd = b.frames.length;
    await b.push(
      {
        version: FRAME_VERSION,
        type: FrameType.BlockData,
        flags: 1,
        fileIdx: 0,
        blockIdx: 0,
        frameOff: 0,
      },
      data,
    );
    await b.ctrl(FrameType.BlockHash, {
      type: FrameType.BlockHash,
      fileIdx: 0,
      blockIdx: 0,
      sha256: bytesToHex(await sha256(data)),
    });
    await b.ctrl(FrameType.Complete, { type: FrameType.Complete, fileDigest });

    const sink = new MemorySink();
    const receiver = new TransferReceiver({
      send: () => {},
      sendDir: keys.j2o,
      recvDir: keys.o2j,
      sendCounterStart: 0,
      recvCounterStart: 0,
      createDigest: nodeDigest,
      sink,
    });
    for (const frame of b.frames.slice(0, partialEnd)) await receiver.handle(frame);
    await receiver.transportChanged();
    for (const frame of b.frames.slice(partialEnd)) await receiver.handle(frame);
    const result = await receiver.done;
    expect(result.digest).toBe(fileDigest);
    expect(sink.bytes()).toEqual(data);
  });
});
