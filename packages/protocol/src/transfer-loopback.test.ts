import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { deriveTransferKeys } from './keyschedule.js';
import { bytesSource, MemorySink, type Destination, type Digest } from './transfer-ports.js';
import { FrameType } from './transfer.js';
import type { FileEntry, Manifest } from './transfer.js';
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

  it('re-sends Done when a cutover drops it after the receiver settled', async () => {
    // The receiver settles and sends its one-shot Done, but that Done is lost — the exact
    // loss a direct→relay cutover can cause right after every block is acknowledged. The
    // sender retransmits Complete on the new path; a settled receiver must re-answer with
    // a fresh Done or the sender stalls waiting for it.
    const keys = await deriveTransferKeys(master);
    const data = new Uint8Array(64_000).map((_, i) => (i * 131 + 7) & 0xff);
    const sink = new MemorySink();

    const box: { receiver?: TransferReceiver } = {};
    let didCutover = false;
    let doneDropped = false;
    const sender = new TransferSender({
      file: bytesSource(data, {
        name: 'f',
        size: data.length,
        mime: 'application/octet-stream',
        lastModified: 1,
      }),
      send: (frame) => queueMicrotask(() => box.receiver!.handle(frame)),
      sendDir: keys.o2j,
      recvDir: keys.j2o,
      sendCounterStart: 0,
      recvCounterStart: 0,
      createDigest: nodeDigest,
      blockSize: 1024,
      frameSize: 256,
      window: 4,
      doneTimeoutMs: 2000, // keep the no-fix failure fast
    });
    const receiver = new TransferReceiver({
      send: (frame) => {
        queueMicrotask(() => {
          // Drop the receiver's first Done (type byte at sealed offset 9), then simulate
          // the sender's path change so it retransmits Complete.
          if (!doneDropped && frame[9] === FrameType.Done) {
            doneDropped = true;
            if (!didCutover) {
              didCutover = true;
              sender.transportChanged();
            }
            return;
          }
          sender.handle(frame);
        });
      },
      sendDir: keys.j2o,
      recvDir: keys.o2j,
      sendCounterStart: 0,
      recvCounterStart: 0,
      createDigest: nodeDigest,
      sink,
    });
    box.receiver = receiver;

    const [digest, result] = await Promise.all([sender.run(), receiver.done]);
    expect(doneDropped).toBe(true);
    expect([...sink.bytes()]).toEqual([...data]);
    expect(result.digest).toBe(createHash('sha256').update(data).digest('hex'));
    expect(digest).toBe(result.digest);
  });

  it('streams a nested multi-file set with empty files and aggregate progress', async () => {
    const keys = await deriveTransferKeys(master);
    const contents = [
      new Uint8Array([1, 2, 3]),
      new Uint8Array(),
      new Uint8Array(3000).map((_, i) => i & 0xff),
    ];
    const names = ['folder/a.bin', 'folder/empty.txt', 'b.bin'];
    const sinks = new Map<string, MemorySink>();
    let prepared: Manifest | undefined;
    let committed = false;
    const destination: Destination = {
      prepare(manifest) {
        prepared = manifest;
      },
      open(file: FileEntry) {
        const sink = new MemorySink();
        sinks.set(file.name, sink);
        return sink;
      },
      close() {
        committed = true;
      },
      abort(reason) {
        for (const sink of sinks.values()) sink.abort(reason);
      },
    };
    const box: { receiver?: TransferReceiver } = {};
    const progress: number[] = [];
    const sender = new TransferSender({
      files: contents.map((bytes, idx) =>
        bytesSource(bytes, { name: names[idx]!, size: bytes.length, mime: '', lastModified: 1 }),
      ),
      send: (frame) => queueMicrotask(() => box.receiver!.handle(frame)),
      sendDir: keys.o2j,
      recvDir: keys.j2o,
      sendCounterStart: 0,
      recvCounterStart: 0,
      createDigest: nodeDigest,
      blockSize: 1024,
      frameSize: 256,
      window: 2,
      onProgress: (bytes) => progress.push(bytes),
    });
    const receiver = new TransferReceiver({
      send: (frame) => queueMicrotask(() => sender.handle(frame)),
      sendDir: keys.j2o,
      recvDir: keys.o2j,
      sendCounterStart: 0,
      recvCounterStart: 0,
      createDigest: nodeDigest,
      destination,
    });
    box.receiver = receiver;

    const [sendDigest, received] = await Promise.all([sender.run(), receiver.done]);
    expect(prepared?.files.map((file) => file.name)).toEqual(names);
    expect(received.files.map((file) => file.name)).toEqual(names);
    expect(received.digest).toBe(sendDigest);
    expect(received.digests).toEqual(
      contents.map((bytes) => createHash('sha256').update(bytes).digest('hex')),
    );
    for (const [idx, name] of names.entries())
      expect(sinks.get(name)?.bytes()).toEqual(contents[idx]);
    expect(progress.at(-1)).toBe(contents.reduce((total, bytes) => total + bytes.length, 0));
    expect(committed).toBe(true);
  });

  it('resumes a partially received transfer from the committed high-water mark', async () => {
    const keys = await deriveTransferKeys(master);
    const blockSize = 1024;
    const data = new Uint8Array(100_000).map((_, i) => (i * 131 + 7) & 0xff);
    const blocks = Math.ceil(data.length / blockSize);
    const stop = 10;
    const prefixLen = stop * blockSize;
    const transferId = 'a'.repeat(32);

    // Model a reloaded receiver: the first `stop` blocks are already persisted, so restore a
    // prefilled sink and a digest already fed exactly those bytes.
    const sink = new MemorySink();
    sink.write(0, data.subarray(0, prefixLen));
    const seed = nodeDigest();
    seed.update(data.subarray(0, prefixLen));

    let commits = 0;
    const box: { receiver?: TransferReceiver } = {};
    const sender = new TransferSender({
      file: bytesSource(data, { name: 'f', size: data.length, mime: '', lastModified: 1 }),
      send: (f) => queueMicrotask(() => box.receiver!.handle(f)),
      sendDir: keys.o2j,
      recvDir: keys.j2o,
      sendCounterStart: 0,
      recvCounterStart: 0,
      createDigest: nodeDigest,
      blockSize,
      frameSize: 256,
      window: 4,
      transferId,
    });
    const receiver = new TransferReceiver({
      send: (f) => queueMicrotask(() => sender.handle(f)),
      sendDir: keys.j2o,
      recvDir: keys.o2j,
      sendCounterStart: 0,
      recvCounterStart: 0,
      createDigest: nodeDigest,
      sink,
      resume: { transferId, files: new Map([[0, { haveBlocks: stop, seedDigest: seed }]]) },
      onProgress: () => void commits++,
    });
    box.receiver = receiver;

    const [digest, result] = await Promise.all([sender.run(), receiver.done]);
    expect([...sink.bytes()]).toEqual([...data]);
    expect(result.digest).toBe(createHash('sha256').update(data).digest('hex'));
    expect(digest).toBe(result.digest);
    // Only the blocks the receiver lacked are streamed and committed on resume.
    expect(commits).toBe(blocks - stop);
  });

  it('ignores a resume seed whose transferId does not match the manifest', async () => {
    const keys = await deriveTransferKeys(master);
    const blockSize = 1024;
    const data = new Uint8Array(20_000).map((_, i) => (i * 131 + 7) & 0xff);
    const blocks = Math.ceil(data.length / blockSize);

    // A seed for a *different* transfer must be discarded: wrong high-water and a poisoned digest.
    // If it were wrongly applied, the whole-file digest would fail and receiver.done would reject.
    const staleSeed = nodeDigest();
    staleSeed.update(new Uint8Array(blockSize).fill(0xff));

    let commits = 0;
    const sink = new MemorySink();
    const box: { receiver?: TransferReceiver } = {};
    const sender = new TransferSender({
      file: bytesSource(data, { name: 'f', size: data.length, mime: '', lastModified: 1 }),
      send: (f) => queueMicrotask(() => box.receiver!.handle(f)),
      sendDir: keys.o2j,
      recvDir: keys.j2o,
      sendCounterStart: 0,
      recvCounterStart: 0,
      createDigest: nodeDigest,
      blockSize,
      frameSize: 256,
      window: 4,
      transferId: 'b'.repeat(32),
    });
    const receiver = new TransferReceiver({
      send: (f) => queueMicrotask(() => sender.handle(f)),
      sendDir: keys.j2o,
      recvDir: keys.o2j,
      sendCounterStart: 0,
      recvCounterStart: 0,
      createDigest: nodeDigest,
      sink,
      resume: {
        transferId: 'a'.repeat(32),
        files: new Map([[0, { haveBlocks: 1, seedDigest: staleSeed }]]),
      },
      onProgress: () => void commits++,
    });
    box.receiver = receiver;

    const [digest, result] = await Promise.all([sender.run(), receiver.done]);
    expect([...sink.bytes()]).toEqual([...data]);
    expect(result.digest).toBe(createHash('sha256').update(data).digest('hex'));
    expect(digest).toBe(result.digest);
    // Fresh receive: every block is streamed because the stale seed was rejected.
    expect(commits).toBe(blocks);
  });
});
