import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { deriveTransferKeys } from './keyschedule.js';
import { open, seal } from './aead.js';
import { FrameType } from './transfer.js';
import { FRAME_VERSION } from './constants.js';
import { decodeControl, encodeControl } from './transfer-messages.js';
import { bytesSource, type Digest } from './transfer-ports.js';
import { TransferSender } from './transfer-sender.js';

function nodeDigest(): Digest {
  const h = createHash('sha256');
  return { update: (b) => void h.update(b), hexDigest: () => h.digest('hex') };
}
const master = new Uint8Array(32).fill(9);

async function waitFor(check: () => boolean): Promise<void> {
  const deadline = Date.now() + 1000;
  while (!check()) {
    if (Date.now() >= deadline) throw new Error('timed out waiting for sender state');
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
}

describe('TransferSender', () => {
  it('emits manifest → block_data/block_hash → complete, gated by verified acknowledgements', async () => {
    const keys = await deriveTransferKeys(master);
    const data = new Uint8Array(20).map((_, i) => i); // block=8 → blocks 0,1 full, block2 = 4B
    const outbound: Uint8Array[] = [];
    const progress: number[] = [];

    const sender = new TransferSender({
      file: bytesSource(data, { name: 'f', size: 20, mime: '', lastModified: 0 }),
      send: (f) => void outbound.push(f),
      sendDir: keys.o2j,
      recvDir: keys.j2o,
      sendCounterStart: 0,
      recvCounterStart: 0,
      createDigest: nodeDigest,
      blockSize: 8,
      frameSize: 4,
      window: 1, // force gating after block 0
      onProgress: (bytes) => progress.push(bytes),
    });

    const runP = sender.run();

    // Let the sender push manifest + block 0's frames + block 0 hash, then stall on window=1.
    await new Promise((r) => setTimeout(r, 10));
    let peek = 0;
    const types = await Promise.all(
      outbound.map(async (f) => (await open(keys.o2j, peek++, f)).header.type),
    );
    expect(types[0]).toBe(FrameType.Manifest);
    // With window=1 the sender may run 1 block ahead; it must NOT have sent `complete` yet.
    expect(types).not.toContain(FrameType.Complete);

    // Feed a verified acknowledgement for each block so the window drains, then `done`.
    let ackCtr = 0;
    const ack = async (blockIdx: number) => {
      const frame = await seal(
        keys.j2o,
        ackCtr++,
        {
          version: FRAME_VERSION,
          type: FrameType.Ack,
          flags: 0,
          fileIdx: 0,
          blockIdx: 0,
          frameOff: 0,
        },
        encodeControl({ type: FrameType.Ack, fileIdx: 0, blockIdx }),
      );
      sender.handle(frame);
    };
    await ack(0);
    await new Promise((r) => setTimeout(r, 10));
    await ack(1);
    await new Promise((r) => setTimeout(r, 10));
    await ack(2);
    await new Promise((r) => setTimeout(r, 10));
    const done = await seal(
      keys.j2o,
      ackCtr++,
      {
        version: FRAME_VERSION,
        type: FrameType.Done,
        flags: 0,
        fileIdx: 0,
        blockIdx: 0,
        frameOff: 0,
      },
      encodeControl({ type: FrameType.Done }),
    );
    sender.handle(done);
    await runP;
    expect(progress).toEqual([8, 16, 20]);

    // Decode the full outbound sequence and check the message grammar + digest.
    let c = 0;
    const decoded: Array<{ type: number; payload: Uint8Array }> = [];
    for (const f of outbound) {
      const o = await open(keys.o2j, c++, f);
      decoded.push({ type: o.header.type, payload: o.plaintext });
    }
    expect(decoded.at(-1)!.type).toBe(FrameType.Complete);
    const complete = decodeControl(decoded.at(-1)!.payload);
    if (complete.type !== FrameType.Complete) throw new Error('expected complete');
    expect(complete.fileDigest).toBe(createHash('sha256').update(data).digest('hex'));
    // Reassemble block_data payloads → original bytes.
    const body: number[] = [];
    for (const d of decoded) if (d.type === FrameType.BlockData) body.push(...d.payload);
    expect(body).toEqual([...data]);
  });

  it('rejects run() when the receiver reports fail', async () => {
    const keys = await deriveTransferKeys(master);
    const sender = new TransferSender({
      file: bytesSource(new Uint8Array(4), { name: 'f', size: 4, mime: '', lastModified: 0 }),
      send: () => {},
      sendDir: keys.o2j,
      recvDir: keys.j2o,
      sendCounterStart: 0,
      recvCounterStart: 0,
      createDigest: nodeDigest,
      blockSize: 8,
      frameSize: 4,
    });
    const runP = sender.run();
    await new Promise((r) => setTimeout(r, 0));
    const fail = await seal(
      keys.j2o,
      0,
      {
        version: FRAME_VERSION,
        type: FrameType.Fail,
        flags: 0,
        fileIdx: 0,
        blockIdx: 0,
        frameOff: 0,
      },
      encodeControl({ type: FrameType.Fail, reason: 'integrity' }),
    );
    sender.handle(fail);
    await expect(runP).rejects.toThrow(/integrity/);
  });

  it('reseals a nacked block with fresh counters and advances progress only on ack', async () => {
    const keys = await deriveTransferKeys(master);
    const data = new Uint8Array([1, 2, 3, 4]);
    const outbound: Uint8Array[] = [];
    const progress: number[] = [];
    const sender = new TransferSender({
      file: bytesSource(data, { name: 'f', size: data.length, mime: '', lastModified: 0 }),
      send: (frame) => void outbound.push(frame),
      sendDir: keys.o2j,
      recvDir: keys.j2o,
      sendCounterStart: 0,
      recvCounterStart: 0,
      createDigest: nodeDigest,
      blockSize: 8,
      frameSize: 4,
      window: 1,
      ackTimeoutMs: 1000,
      onProgress: (bytes) => progress.push(bytes),
    });

    const runP = sender.run();
    await waitFor(() => outbound.length === 3); // manifest, block_data, block_hash
    expect(progress).toEqual([]);

    const nack = await seal(
      keys.j2o,
      0,
      {
        version: FRAME_VERSION,
        type: FrameType.Nack,
        flags: 0,
        fileIdx: 0,
        blockIdx: 0,
        frameOff: 0,
      },
      encodeControl({ type: FrameType.Nack, fileIdx: 0, blockIdx: 0, reason: 'missing' }),
    );
    sender.handle(nack);
    await waitFor(() => outbound.length === 5); // freshly sealed data + hash

    const ack = await seal(
      keys.j2o,
      1,
      {
        version: FRAME_VERSION,
        type: FrameType.Ack,
        flags: 0,
        fileIdx: 0,
        blockIdx: 0,
        frameOff: 0,
      },
      encodeControl({ type: FrameType.Ack, fileIdx: 0, blockIdx: 0 }),
    );
    sender.handle(ack);
    await waitFor(() => outbound.length === 6); // complete
    expect(progress).toEqual([4]);

    const done = await seal(
      keys.j2o,
      2,
      {
        version: FRAME_VERSION,
        type: FrameType.Done,
        flags: 0,
        fileIdx: 0,
        blockIdx: 0,
        frameOff: 0,
      },
      encodeControl({ type: FrameType.Done }),
    );
    sender.handle(done);
    await runP;

    let counter = 0;
    const opened = [];
    for (const frame of outbound) opened.push(await open(keys.o2j, counter++, frame));
    expect(opened.map((item) => item.header.type)).toEqual([
      FrameType.Manifest,
      FrameType.BlockData,
      FrameType.BlockHash,
      FrameType.BlockData,
      FrameType.BlockHash,
      FrameType.Complete,
    ]);
    expect(opened[1]?.plaintext).toEqual(data);
    expect(opened[3]?.plaintext).toEqual(data);
    expect(outbound[1]).not.toEqual(outbound[3]); // retransmission uses a fresh GCM nonce
  });

  it('immediately retransmits the unacknowledged window after a transport change', async () => {
    const keys = await deriveTransferKeys(master);
    const data = new Uint8Array([1, 2, 3, 4]);
    const outbound: Uint8Array[] = [];
    const sender = new TransferSender({
      file: bytesSource(data, { name: 'f', size: data.length, mime: '', lastModified: 0 }),
      send: (frame) => void outbound.push(frame),
      sendDir: keys.o2j,
      recvDir: keys.j2o,
      sendCounterStart: 0,
      recvCounterStart: 0,
      createDigest: nodeDigest,
      blockSize: 8,
      frameSize: 4,
      window: 1,
      ackTimeoutMs: 60_000,
    });

    const run = sender.run();
    await waitFor(() => outbound.length === 3);
    sender.transportChanged();
    await waitFor(() => outbound.length === 5);
    sender.cancel('test complete');
    await expect(run).rejects.toThrow(/test complete/);

    let counter = 0;
    const opened = [];
    for (const frame of outbound.slice(0, 5)) opened.push(await open(keys.o2j, counter++, frame));
    expect(opened.map((frame) => frame.header.type)).toEqual([
      FrameType.Manifest,
      FrameType.BlockData,
      FrameType.BlockHash,
      FrameType.BlockData,
      FrameType.BlockHash,
    ]);
    expect(outbound[1]).not.toEqual(outbound[3]);
  });

  it('halts new data while paused and resumes without losing the window', async () => {
    const keys = await deriveTransferKeys(master);
    const outbound: Uint8Array[] = [];
    const states: string[] = [];
    const sender = new TransferSender({
      file: bytesSource(new Uint8Array([1, 2, 3, 4]), {
        name: 'f',
        size: 4,
        mime: '',
        lastModified: 0,
      }),
      send: (frame) => void outbound.push(frame),
      sendDir: keys.o2j,
      recvDir: keys.j2o,
      sendCounterStart: 0,
      recvCounterStart: 0,
      createDigest: nodeDigest,
      blockSize: 8,
      frameSize: 4,
      onStateChange: (state) => states.push(state),
    });

    sender.pause();
    const runP = sender.run();
    await waitFor(() => outbound.length === 2); // pause control + manifest
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(outbound).toHaveLength(2);

    sender.resume();
    await waitFor(() => outbound.length === 5); // resume + block_data + block_hash
    const ack = await seal(
      keys.j2o,
      0,
      {
        version: FRAME_VERSION,
        type: FrameType.Ack,
        flags: 0,
        fileIdx: 0,
        blockIdx: 0,
        frameOff: 0,
      },
      encodeControl({ type: FrameType.Ack, fileIdx: 0, blockIdx: 0 }),
    );
    sender.handle(ack);
    await waitFor(() => outbound.length === 6);
    const done = await seal(
      keys.j2o,
      1,
      {
        version: FRAME_VERSION,
        type: FrameType.Done,
        flags: 0,
        fileIdx: 0,
        blockIdx: 0,
        frameOff: 0,
      },
      encodeControl({ type: FrameType.Done }),
    );
    sender.handle(done);
    await runP;
    expect(states).toEqual(['paused', 'running']);
  });
});
