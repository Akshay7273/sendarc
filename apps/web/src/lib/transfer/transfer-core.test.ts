import { describe, it, expect } from 'vitest';
import { deriveTransferKeys, sha256, bytesToHex, MemorySink } from '@sendarc/protocol';
import { runTransferCore, type TransferCoreDeps } from './transfer-core.js';
import { blobFileSource } from './file-source.js';
import { createSha256DigestFactory } from './digest.js';
import type { DuplexPort, HostToWorker, WorkerToHost } from './wire.js';

/**
 * A fake worker port. The core calls `postMessage` (worker → host, surfaced via `onWorkerOut`)
 * and receives via the handler it registers (host → worker, driven by `toWorker`). Delivery is
 * async and FIFO per direction, mirroring a real MessageChannel.
 */
class FakePort implements DuplexPort<HostToWorker, WorkerToHost> {
  private handler: ((ev: { data: HostToWorker }) => void) | undefined;
  onWorkerOut: (msg: WorkerToHost) => void = () => {};
  postMessage(msg: WorkerToHost): void {
    queueMicrotask(() => this.onWorkerOut(msg));
  }
  addEventListener(_type: 'message', handler: (ev: { data: HostToWorker }) => void): void {
    this.handler = handler;
  }
  toWorker(msg: HostToWorker): void {
    queueMicrotask(() => this.handler?.({ data: msg }));
  }
}

describe('transfer-core loopback', () => {
  it('completes a transfer through the worker message protocol', async () => {
    const keys = await deriveTransferKeys(new Uint8Array(32).fill(7));
    const bytes = new Uint8Array(200 * 1024 + 7).map((_, i) => (i * 31) & 0xff);
    const file = new File([bytes], 'loop.bin', { type: 'application/octet-stream' });

    const sendPort = new FakePort();
    const recvPort = new FakePort();
    const sink = new MemorySink();

    let senderDone: (WorkerToHost & { kind: 'done' }) | undefined;
    let receiverDone: (WorkerToHost & { kind: 'done' }) | undefined;
    let manifest: (WorkerToHost & { kind: 'manifest' }) | undefined;

    sendPort.onWorkerOut = (m) => {
      if (m.kind === 'outbound-frame') recvPort.toWorker({ kind: 'inbound-frame', frame: m.frame });
      else if (m.kind === 'done') senderDone = m;
    };
    recvPort.onWorkerOut = (m) => {
      if (m.kind === 'outbound-frame') sendPort.toWorker({ kind: 'inbound-frame', frame: m.frame });
      else if (m.kind === 'done') receiverDone = m;
      else if (m.kind === 'manifest') manifest = m;
    };

    const senderDeps: TransferCoreDeps = {
      createDigest: await createSha256DigestFactory(),
      createSink: () => {
        throw new Error('sender has no sink');
      },
      fileSource: (f) => blobFileSource(f),
    };
    const receiverDeps: TransferCoreDeps = {
      createDigest: await createSha256DigestFactory(),
      createSink: () => sink,
      fileSource: () => {
        throw new Error('receiver has no source');
      },
    };

    const recvP = runTransferCore(recvPort, receiverDeps);
    const sendP = runTransferCore(sendPort, senderDeps);

    recvPort.toWorker({
      kind: 'start-recv',
      sendDir: keys.j2o,
      recvDir: keys.o2j,
      sendCounter: 1,
      recvCounter: 1,
    });
    sendPort.toWorker({
      kind: 'start-send',
      file,
      sendDir: keys.o2j,
      recvDir: keys.j2o,
      sendCounter: 1,
      recvCounter: 1,
      blockSize: 64 * 1024,
      frameSize: 16 * 1024,
    });

    await Promise.all([recvP, sendP]);

    const expected = bytesToHex(await sha256(bytes));
    expect(sink.bytes()).toEqual(bytes);
    expect(sink.isClosed).toBe(true);
    expect(receiverDone?.digest).toBe(expected);
    expect(senderDone?.digest).toBe(expected);
    expect(receiverDone?.name).toBe('loop.bin');
    expect(receiverDone?.size).toBe(bytes.length);
    expect(manifest?.name).toBe('loop.bin');
    expect(manifest?.size).toBe(bytes.length);
  });

  it('surfaces an integrity failure when a data frame is corrupted in flight', async () => {
    const keys = await deriveTransferKeys(new Uint8Array(32).fill(5));
    const bytes = new Uint8Array(80 * 1024).map((_, i) => i & 0xff);
    const file = new File([bytes], 'corrupt.bin');

    const sendPort = new FakePort();
    const recvPort = new FakePort();
    const sink = new MemorySink();
    let flipped = false;

    sendPort.onWorkerOut = (m) => {
      if (m.kind !== 'outbound-frame') return;
      const view = new Uint8Array(m.frame);
      // Corrupt the first non-manifest frame (a block_data frame) after the manifest.
      const last = view.length - 1;
      const b = view[last];
      if (!flipped && view.length > 64 && b !== undefined) {
        flipped = true;
        view[last] = b ^ 0xff;
      }
      recvPort.toWorker({ kind: 'inbound-frame', frame: m.frame });
    };
    recvPort.onWorkerOut = (m) => {
      if (m.kind === 'outbound-frame') sendPort.toWorker({ kind: 'inbound-frame', frame: m.frame });
    };

    const senderDeps: TransferCoreDeps = {
      createDigest: await createSha256DigestFactory(),
      createSink: () => sink,
      fileSource: (f) => blobFileSource(f),
    };
    const receiverDeps: TransferCoreDeps = {
      createDigest: await createSha256DigestFactory(),
      createSink: () => sink,
      fileSource: (f) => blobFileSource(f),
    };

    const recvP = runTransferCore(recvPort, receiverDeps);
    const sendP = runTransferCore(sendPort, senderDeps);

    recvPort.toWorker({
      kind: 'start-recv',
      sendDir: keys.j2o,
      recvDir: keys.o2j,
      sendCounter: 1,
      recvCounter: 1,
    });
    sendPort.toWorker({
      kind: 'start-send',
      file,
      sendDir: keys.o2j,
      recvDir: keys.j2o,
      sendCounter: 1,
      recvCounter: 1,
      blockSize: 64 * 1024,
      frameSize: 16 * 1024,
    });

    await expect(Promise.all([recvP, sendP])).rejects.toThrow(/integrity/);
  });
});
