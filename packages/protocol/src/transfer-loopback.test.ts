import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { deriveTransferKeys } from './keyschedule.js';
import { bytesSource, MemorySink, type Digest } from './transfer-ports.js';
import { TransferSender } from './transfer-sender.js';
import { TransferReceiver } from './transfer-receiver.js';

function nodeDigest(): Digest {
  const h = createHash('sha256');
  return { update: (b) => void h.update(b), hexDigest: () => h.digest('hex') };
}
const master = new Uint8Array(32).fill(3);

/** Wire a sender (offerer role, o2j) to a receiver (joiner role) via async queues. */
async function runTransfer(
  data: Uint8Array,
  opts: { blockSize: number; frameSize: number; window: number; corrupt?: boolean },
) {
  const keys = await deriveTransferKeys(master);
  const sink = new MemorySink();

  // The two engines reference each other; a holder breaks the declaration cycle.
  const box: { receiver?: TransferReceiver } = {};
  const sender = new TransferSender({
    file: bytesSource(data, {
      name: 'f',
      size: data.length,
      mime: 'application/octet-stream',
      lastModified: 1,
    }),
    send: (f) => queueMicrotask(() => box.receiver!.handle(f)),
    sendDir: keys.o2j,
    recvDir: keys.j2o,
    sendCounterStart: 0,
    recvCounterStart: 0,
    createDigest: nodeDigest,
    blockSize: opts.blockSize,
    frameSize: opts.frameSize,
    window: opts.window,
  });
  let corrupted = false;
  const receiver = new TransferReceiver({
    send: (f) => queueMicrotask(() => sender.handle(f)),
    sendDir: keys.j2o,
    recvDir: keys.o2j,
    sendCounterStart: 0,
    recvCounterStart: 0,
    createDigest: nodeDigest,
    sink,
  });
  box.receiver = receiver;

  if (opts.corrupt) {
    // Re-wrap send to flip one byte in the second frame (a block_data payload/tag).
    let n = 0;
    (sender as unknown as { o: { send: (f: Uint8Array) => void } }).o.send = (f: Uint8Array) => {
      if (!corrupted && n++ === 1) {
        f = f.slice();
        f[f.length - 1] ^= 0x01;
        corrupted = true;
      }
      queueMicrotask(() => receiver.handle(f));
    };
  }

  const runP = sender.run();
  const result = await Promise.allSettled([runP, receiver.done]);
  return { result, sink };
}

describe('transfer loopback (no browser)', () => {
  const sizes = [0, 1, 7, 8, 20, 4096, 100_000];
  for (const size of sizes) {
    it(`streams ${size} bytes end-to-end with a matching digest`, async () => {
      const data = new Uint8Array(size).map((_, i) => (i * 131 + 7) & 0xff);
      const { result, sink } = await runTransfer(data, {
        blockSize: 1024,
        frameSize: 256,
        window: 4,
      });
      expect(result[0].status).toBe('fulfilled');
      expect(result[1].status).toBe('fulfilled');
      expect([...sink.bytes()]).toEqual([...data]);
      if (result[1].status === 'fulfilled') {
        expect(result[1].value.digest).toBe(createHash('sha256').update(data).digest('hex'));
      }
    });
  }

  it('aborts loudly when a frame is corrupted in flight', async () => {
    const data = new Uint8Array(4096).map((_, i) => i & 0xff);
    const { result, sink } = await runTransfer(data, {
      blockSize: 1024,
      frameSize: 256,
      window: 4,
      corrupt: true,
    });
    expect(result.some((r) => r.status === 'rejected')).toBe(true);
    expect(sink.isClosed).toBe(false);
  });
});
