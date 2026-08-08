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

describe('TransferSender', () => {
  it('emits manifest → block_data/block_hash → complete, gated by block_recv', async () => {
    const keys = await deriveTransferKeys(master);
    const data = new Uint8Array(20).map((_, i) => i); // block=8 → blocks 0,1 full, block2 = 4B
    const outbound: Uint8Array[] = [];

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

    // Feed block_recv for every block so it drains, then `done`.
    let ackCtr = 0;
    const ack = async (blockIdx: number) => {
      const frame = await seal(
        keys.j2o,
        ackCtr++,
        { version: FRAME_VERSION, type: FrameType.BlockRecv, flags: 0, fileIdx: 0, blockIdx: 0, frameOff: 0 },
        encodeControl({ type: FrameType.BlockRecv, fileIdx: 0, blockIdx }),
      );
      sender.handle(frame);
    };
    await ack(0);
    await ack(1);
    await ack(2);
    await new Promise((r) => setTimeout(r, 10));
    const done = await seal(
      keys.j2o,
      ackCtr++,
      { version: FRAME_VERSION, type: FrameType.Done, flags: 0, fileIdx: 0, blockIdx: 0, frameOff: 0 },
      encodeControl({ type: FrameType.Done }),
    );
    sender.handle(done);
    await runP;

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
    const fail = await seal(
      keys.j2o,
      0,
      { version: FRAME_VERSION, type: FrameType.Fail, flags: 0, fileIdx: 0, blockIdx: 0, frameOff: 0 },
      encodeControl({ type: FrameType.Fail, reason: 'integrity' }),
    );
    sender.handle(fail);
    await expect(runP).rejects.toThrow(/integrity/);
  });
});
