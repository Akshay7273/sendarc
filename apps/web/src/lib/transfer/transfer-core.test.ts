import { describe, it, expect } from 'vitest';
import {
  deriveTransferKeys,
  sha256,
  bytesToHex,
  MemorySink,
  FrameType,
  manifestFingerprint,
  type Manifest,
} from '@sendbeam/protocol';
import { runTransferCore, type TransferCoreDeps } from './transfer-core.js';
import { blobFileSource } from './file-source.js';
import { createSha256DigestFactory } from './digest.js';
import {
  memorySenderRecordStore,
  newSenderRecord,
  type SenderRecord,
  type SenderRecordLoad,
  type SenderRecordStore,
} from './sender-record.js';
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

async function waitFor(check: () => boolean): Promise<void> {
  const deadline = Date.now() + 1000;
  while (!check()) {
    if (Date.now() >= deadline) throw new Error('timed out waiting for worker state');
    await new Promise((resolve) => setTimeout(resolve, 1));
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

    let senderDone: Extract<WorkerToHost, { kind: 'done' }> | undefined;
    let receiverDone: Extract<WorkerToHost, { kind: 'done' }> | undefined;
    let manifest: Extract<WorkerToHost, { kind: 'manifest' }> | undefined;
    const senderStates: string[] = [];

    sendPort.onWorkerOut = (m) => {
      if (m.kind === 'outbound-frame') recvPort.toWorker({ kind: 'inbound-frame', frame: m.frame });
      else if (m.kind === 'done') senderDone = m;
      else if (m.kind === 'state') senderStates.push(m.state);
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
      destination: { kind: 'auto' },
      sendDir: keys.j2o,
      recvDir: keys.o2j,
      sendCounter: 1,
      recvCounter: 1,
    });
    // Controls may arrive while WebRTC is still negotiating, before the engine is bound. The
    // worker retains this pause and applies it before the first data block.
    sendPort.toWorker({ kind: 'control', op: 'pause' });
    sendPort.toWorker({
      kind: 'start-send',
      files: [file],
      sendDir: keys.o2j,
      recvDir: keys.j2o,
      sendCounter: 1,
      recvCounter: 1,
      blockSize: 64 * 1024,
      frameSize: 16 * 1024,
    });

    await waitFor(() => senderStates.includes('paused'));
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(senderDone).toBeUndefined();
    sendPort.toWorker({ kind: 'control', op: 'resume' });

    await Promise.all([recvP, sendP]);

    const expected = bytesToHex(await sha256(bytes));
    expect(sink.bytes()).toEqual(bytes);
    expect(sink.isClosed).toBe(true);
    expect(receiverDone?.digest).toBe(expected);
    expect(senderDone?.digest).toBe(expected);
    expect(receiverDone?.files[0]?.name).toBe('loop.bin');
    expect(receiverDone?.totalSize).toBe(bytes.length);
    expect(manifest?.files[0]?.name).toBe('loop.bin');
    expect(manifest?.totalSize).toBe(bytes.length);
    expect(senderStates).toEqual(['running', 'paused', 'running']);
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
      destination: { kind: 'auto' },
      sendDir: keys.j2o,
      recvDir: keys.o2j,
      sendCounter: 1,
      recvCounter: 1,
    });
    sendPort.toWorker({
      kind: 'start-send',
      files: [file],
      sendDir: keys.o2j,
      recvDir: keys.j2o,
      sendCounter: 1,
      recvCounter: 1,
      blockSize: 64 * 1024,
      frameSize: 16 * 1024,
    });

    await expect(Promise.all([recvP, sendP])).rejects.toThrow(/integrity/);
  });

  it('carries a nested file set through the worker protocol', async () => {
    const keys = await deriveTransferKeys(new Uint8Array(32).fill(9));
    const files = [new File([new Uint8Array([1, 2, 3])], 'a.bin'), new File([], 'empty.txt')];
    Object.defineProperty(files[0], 'webkitRelativePath', { value: 'folder/a.bin' });
    Object.defineProperty(files[1], 'webkitRelativePath', { value: 'folder/empty.txt' });
    const sendPort = new FakePort();
    const recvPort = new FakePort();
    const sinks = new Map<string, MemorySink>();
    let received: Extract<WorkerToHost, { kind: 'done' }> | undefined;
    sendPort.onWorkerOut = (message) => {
      if (message.kind === 'outbound-frame') {
        recvPort.toWorker({ kind: 'inbound-frame', frame: message.frame });
      }
    };
    recvPort.onWorkerOut = (message) => {
      if (message.kind === 'outbound-frame') {
        sendPort.toWorker({ kind: 'inbound-frame', frame: message.frame });
      } else if (message.kind === 'done') received = message;
    };
    const receiverDigest = await createSha256DigestFactory();
    const senderDigest = await createSha256DigestFactory();
    const recvP = runTransferCore(recvPort, {
      createDigest: receiverDigest,
      createSink: (file) => {
        const sink = new MemorySink();
        sinks.set(file.name, sink);
        return sink;
      },
      fileSource: blobFileSource,
    });
    const sendP = runTransferCore(sendPort, {
      createDigest: senderDigest,
      createSink: () => {
        throw new Error('sender has no sink');
      },
      fileSource: blobFileSource,
    });
    recvPort.toWorker({
      kind: 'start-recv',
      destination: { kind: 'auto' },
      sendDir: keys.j2o,
      recvDir: keys.o2j,
      sendCounter: 1,
      recvCounter: 1,
    });
    sendPort.toWorker({
      kind: 'start-send',
      files,
      sendDir: keys.o2j,
      recvDir: keys.j2o,
      sendCounter: 1,
      recvCounter: 1,
      blockSize: 8,
      frameSize: 4,
    });
    await Promise.all([recvP, sendP]);
    expect(received?.files.map((file) => file.name)).toEqual(['folder/a.bin', 'folder/empty.txt']);
    expect(sinks.get('folder/a.bin')?.bytes()).toEqual(new Uint8Array([1, 2, 3]));
    expect(sinks.get('folder/empty.txt')?.bytes()).toEqual(new Uint8Array());
  });
});

/** Build the sender record the worker would persist for one File with the given id. */
async function recordForFile(file: File, transferId: string): Promise<SenderRecord> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const manifest: Manifest = {
    type: FrameType.Manifest,
    transferId,
    files: [
      {
        idx: 0,
        name: file.webkitRelativePath || file.name,
        size: file.size,
        mime: file.type,
        lastModified: file.lastModified,
        blockSize: 64 * 1024,
        blocks: Math.ceil(file.size / (64 * 1024)),
        fileDigest: bytesToHex(await sha256(bytes)),
      },
    ],
    totalSize: file.size,
  };
  return newSenderRecord(manifest, { kind: 'reselection' }, 1_000);
}

describe('sender-record seam (V13-PR04)', () => {
  it('persists a fresh sender record before the manifest frame and removes it after success', async () => {
    const keys = await deriveTransferKeys(new Uint8Array(32).fill(11));
    const bytes = new Uint8Array(50 * 1024).map((_, i) => (i * 13) & 0xff);
    const file = new File([bytes], 'fresh.bin', { type: 'application/octet-stream' });
    const store = memorySenderRecordStore();

    const sendPort = new FakePort();
    const recvPort = new FakePort();
    const sink = new MemorySink();
    let atFirstFrame: Promise<SenderRecordLoad[]> | undefined;
    recvPort.onWorkerOut = (m) => {
      if (m.kind === 'outbound-frame') {
        if (atFirstFrame === undefined) atFirstFrame = store.list();
        sendPort.toWorker({ kind: 'inbound-frame', frame: m.frame });
      }
    };
    sendPort.onWorkerOut = (m) => {
      if (m.kind === 'outbound-frame') recvPort.toWorker({ kind: 'inbound-frame', frame: m.frame });
    };
    const recvP = runTransferCore(recvPort, {
      createDigest: await createSha256DigestFactory(),
      createSink: () => sink,
      fileSource: blobFileSource,
    });
    const sendP = runTransferCore(sendPort, {
      createDigest: await createSha256DigestFactory(),
      createSink: () => {
        throw new Error('sender has no sink');
      },
      fileSource: blobFileSource,
      senderRecords: store,
    });

    recvPort.toWorker({
      kind: 'start-recv',
      destination: { kind: 'auto' },
      sendDir: keys.j2o,
      recvDir: keys.o2j,
      sendCounter: 1,
      recvCounter: 1,
    });
    sendPort.toWorker({
      kind: 'start-send',
      files: [file],
      sendDir: keys.o2j,
      recvDir: keys.j2o,
      sendCounter: 1,
      recvCounter: 1,
      blockSize: 64 * 1024,
      frameSize: 16 * 1024,
    });
    await Promise.all([recvP, sendP]);

    // The record existed before the first (manifest) frame was transmitted...
    const seen = await atFirstFrame!;
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({ kind: 'ok' });
    const record = (seen[0] as { kind: 'ok'; record: SenderRecord }).record;
    expect(record.transferId).toMatch(/^[0-9a-f]{32}$/);
    expect(record.reattachment).toEqual({ kind: 'reselection' });
    expect(record.files).toEqual([
      {
        name: 'fresh.bin',
        size: bytes.length,
        mime: 'application/octet-stream',
        lastModified: file.lastModified,
      },
    ]);
    // ...and was removed after verified success.
    await expect(store.list()).resolves.toEqual([]);
  });

  it('resumes an interrupted send over a matching source, refreshing and then removing the record', async () => {
    const keys = await deriveTransferKeys(new Uint8Array(32).fill(13));
    const bytes = new Uint8Array(50 * 1024).map((_, i) => (i * 17) & 0xff);
    const file = new File([bytes], 'resume.bin', { type: 'application/octet-stream' });
    const id = 'dd'.repeat(16);
    const store = memorySenderRecordStore();
    await store.put(await recordForFile(file, id));

    const sendPort = new FakePort();
    const recvPort = new FakePort();
    const sink = new MemorySink();
    let atFirstFrame: Promise<SenderRecordLoad[]> | undefined;
    recvPort.onWorkerOut = (m) => {
      if (m.kind === 'outbound-frame') {
        if (atFirstFrame === undefined) atFirstFrame = store.list();
        sendPort.toWorker({ kind: 'inbound-frame', frame: m.frame });
      }
    };
    sendPort.onWorkerOut = (m) => {
      if (m.kind === 'outbound-frame') recvPort.toWorker({ kind: 'inbound-frame', frame: m.frame });
    };
    const recvP = runTransferCore(recvPort, {
      createDigest: await createSha256DigestFactory(),
      createSink: () => sink,
      fileSource: blobFileSource,
    });
    const sendP = runTransferCore(sendPort, {
      createDigest: await createSha256DigestFactory(),
      createSink: () => {
        throw new Error('sender has no source');
      },
      fileSource: blobFileSource,
      senderRecords: store,
    });

    recvPort.toWorker({
      kind: 'start-recv',
      destination: { kind: 'auto' },
      sendDir: keys.j2o,
      recvDir: keys.o2j,
      sendCounter: 1,
      recvCounter: 1,
    });
    sendPort.toWorker({
      kind: 'start-send',
      files: [file],
      transferId: id,
      sendDir: keys.o2j,
      recvDir: keys.j2o,
      sendCounter: 1,
      recvCounter: 1,
      blockSize: 64 * 1024,
      frameSize: 16 * 1024,
    });
    await Promise.all([recvP, sendP]);

    const seen = await atFirstFrame!;
    expect(seen).toHaveLength(1);
    const record = (seen[0] as { kind: 'ok'; record: SenderRecord }).record;
    // The interrupted id was reused (not re-minted) and the record refreshed...
    expect(record.transferId).toBe(id);
    expect(record.updatedAt).toBeGreaterThan(1_000);
    // ...and removed after verified success.
    await expect(store.list()).resolves.toEqual([]);
  });

  it('runs resume-auth-v1 through the worker protocol before reusing the interrupted id (V13-PR08)', async () => {
    const keys = await deriveTransferKeys(new Uint8Array(32).fill(23));
    const bytes = new Uint8Array(50 * 1024).map((_, i) => (i * 29) & 0xff);
    const file = new File([bytes], 'resumed.bin', { type: 'application/octet-stream' });
    const id = 'ff'.repeat(16);
    // Both peers hold the SAME persisted transfer-scoped credential from the interrupted
    // session; the attempt binds transferId + manifest fingerprint + secret.
    const secret = new Uint8Array(32).fill(0x42);
    const manifest: Manifest = {
      type: FrameType.Manifest,
      transferId: id,
      files: [
        {
          idx: 0,
          name: 'resumed.bin',
          size: file.size,
          mime: 'application/octet-stream',
          lastModified: 0,
          blockSize: 64 * 1024,
          blocks: Math.ceil(file.size / (64 * 1024)),
          fileDigest: bytesToHex(await sha256(bytes)),
        },
      ],
      totalSize: file.size,
    };
    const fingerprint = await manifestFingerprint(manifest);

    const sendPort = new FakePort();
    const recvPort = new FakePort();
    const sink = new MemorySink();
    let manifestSeen: Extract<WorkerToHost, { kind: 'manifest' }> | undefined;
    sendPort.onWorkerOut = (m) => {
      if (m.kind === 'outbound-frame') recvPort.toWorker({ kind: 'inbound-frame', frame: m.frame });
    };
    recvPort.onWorkerOut = (m) => {
      if (m.kind === 'outbound-frame') sendPort.toWorker({ kind: 'inbound-frame', frame: m.frame });
      else if (m.kind === 'manifest') manifestSeen = m;
    };
    const recvP = runTransferCore(recvPort, {
      createDigest: await createSha256DigestFactory(),
      createSink: () => sink,
      fileSource: blobFileSource,
    });
    const sendP = runTransferCore(sendPort, {
      createDigest: await createSha256DigestFactory(),
      createSink: () => {
        throw new Error('sender has no sink');
      },
      fileSource: blobFileSource,
    });

    recvPort.toWorker({
      kind: 'start-recv',
      destination: { kind: 'auto' },
      sendDir: keys.j2o,
      recvDir: keys.o2j,
      sendCounter: 1,
      recvCounter: 1,
      resumeAttempt: {
        transferId: id,
        manifestFingerprint: fingerprint,
        role: 'joiner',
        resumeSecret: secret,
      },
    });
    sendPort.toWorker({
      kind: 'start-send',
      files: [file],
      sendDir: keys.o2j,
      recvDir: keys.j2o,
      sendCounter: 1,
      recvCounter: 1,
      blockSize: 64 * 1024,
      frameSize: 16 * 1024,
      resumeAttempt: {
        transferId: id,
        manifestFingerprint: fingerprint,
        role: 'offerer',
        resumeSecret: secret,
      },
    });
    await Promise.all([recvP, sendP]);

    // The manifest carries the INTERRUPTED id (never re-minted): the preamble ran to mutual
    // success and the transfer proceeded under the fresh resumed key epoch.
    expect(manifestSeen?.files[0]?.name).toBe('resumed.bin');
    expect(manifestSeen?.totalSize).toBe(bytes.length);
    expect(sink.bytes()).toEqual(bytes);
  });

  it('fails closed when the resumed peer holds a different credential (V13-PR08)', async () => {
    const keys = await deriveTransferKeys(new Uint8Array(32).fill(31));
    const bytes = new Uint8Array(10 * 1024).map((_, i) => (i * 3) & 0xff);
    const file = new File([bytes], 'x.bin');
    const id = 'ab'.repeat(16);
    const fingerprint = 'a'.repeat(64);

    const sendPort = new FakePort();
    const recvPort = new FakePort();
    const sink = new MemorySink();
    sendPort.onWorkerOut = (m) => {
      if (m.kind === 'outbound-frame') recvPort.toWorker({ kind: 'inbound-frame', frame: m.frame });
    };
    recvPort.onWorkerOut = (m) => {
      if (m.kind === 'outbound-frame') sendPort.toWorker({ kind: 'inbound-frame', frame: m.frame });
    };
    const recvP = runTransferCore(recvPort, {
      createDigest: await createSha256DigestFactory(),
      createSink: () => sink,
      fileSource: blobFileSource,
    });
    const sendP = runTransferCore(sendPort, {
      createDigest: await createSha256DigestFactory(),
      createSink: () => {
        throw new Error('sender has no sink');
      },
      fileSource: blobFileSource,
    });

    recvPort.toWorker({
      kind: 'start-recv',
      destination: { kind: 'auto' },
      sendDir: keys.j2o,
      recvDir: keys.o2j,
      sendCounter: 1,
      recvCounter: 1,
      resumeAttempt: {
        transferId: id,
        manifestFingerprint: fingerprint,
        role: 'joiner',
        resumeSecret: new Uint8Array(32).fill(1), // WRONG credential
      },
    });
    sendPort.toWorker({
      kind: 'start-send',
      files: [file],
      sendDir: keys.o2j,
      recvDir: keys.j2o,
      sendCounter: 1,
      recvCounter: 1,
      resumeAttempt: {
        transferId: id,
        manifestFingerprint: fingerprint,
        role: 'offerer',
        resumeSecret: new Uint8Array(32).fill(2), // WRONG credential
      },
    });
    // One-sided failure propagates via the sealed channel teardown in production, which
    // cancels the peer's context. The fake-port harness has no transport teardown, so mirror
    // production: race for the first side to settle (the auth-failing side rejects), then
    // cancel the peer so both settle deterministically instead of one waiting forever.
    const first = await Promise.race([
      sendP.then(
        () => 'send' as const,
        () => 'send' as const,
      ),
      recvP.then(
        () => 'recv' as const,
        () => 'recv' as const,
      ),
    ]);
    if (first === 'send') {
      recvPort.toWorker({ kind: 'cancel' });
      await recvP.catch(() => {});
    } else {
      sendPort.toWorker({ kind: 'cancel' });
      await sendP.catch(() => {});
    }
    await expect(sendP).rejects.toThrow();
    await expect(recvP).rejects.toThrow();
  });

  it('rejects a resume whose source changed before any frame is sent, keeping the record', async () => {
    const keys = await deriveTransferKeys(new Uint8Array(32).fill(17));
    const original = new File([new Uint8Array(10)], 'same.bin');
    const id = 'ee'.repeat(16);
    const store = memorySenderRecordStore();
    await store.put(await recordForFile(original, id));

    const sendPort = new FakePort();
    let frames = 0;
    sendPort.onWorkerOut = (m) => {
      if (m.kind === 'outbound-frame') frames++;
    };
    const sendP = runTransferCore(sendPort, {
      createDigest: await createSha256DigestFactory(),
      createSink: () => {
        throw new Error('sender has no sink');
      },
      fileSource: blobFileSource,
      senderRecords: store,
    });
    // Same name, different content: the fingerprint check must refuse the resume.
    const changed = new File([new Uint8Array(11)], 'same.bin');
    sendPort.toWorker({
      kind: 'start-send',
      files: [changed],
      transferId: id,
      sendDir: keys.o2j,
      recvDir: keys.j2o,
      sendCounter: 1,
      recvCounter: 1,
    });
    await expect(sendP).rejects.toThrow(/does not match interrupted transfer/);
    expect(frames).toBe(0);
    await expect(store.load(id)).resolves.toMatchObject({ kind: 'ok' });
  });

  it('fails closed when the prior sender record is corrupt', async () => {
    const keys = await deriveTransferKeys(new Uint8Array(32).fill(19));
    const file = new File([new Uint8Array(10)], 'x.bin');
    const id = 'aa'.repeat(16);
    const corrupt: SenderRecordStore = {
      load: async () => ({ kind: 'corrupt', transferId: id, error: 'tampered record' }),
      list: async () => [],
      put: async () => {},
      remove: async () => {},
    };
    const sendPort = new FakePort();
    const sendP = runTransferCore(sendPort, {
      createDigest: await createSha256DigestFactory(),
      createSink: () => {
        throw new Error('sender has no sink');
      },
      fileSource: blobFileSource,
      senderRecords: corrupt,
    });
    sendPort.toWorker({
      kind: 'start-send',
      files: [file],
      transferId: id,
      sendDir: keys.o2j,
      recvDir: keys.j2o,
      sendCounter: 1,
      recvCounter: 1,
    });
    await expect(sendP).rejects.toThrow(/corrupt/);
  });

  it('fails closed when a supplied transfer id has no sender record', async () => {
    const keys = await deriveTransferKeys(new Uint8Array(32).fill(21));
    const file = new File([new Uint8Array(10)], 'x.bin');
    const id = 'bc'.repeat(16);
    const sendPort = new FakePort();
    const sendP = runTransferCore(sendPort, {
      createDigest: await createSha256DigestFactory(),
      createSink: () => {
        throw new Error('sender has no sink');
      },
      fileSource: blobFileSource,
      senderRecords: memorySenderRecordStore(),
    });
    sendPort.toWorker({
      kind: 'start-send',
      files: [file],
      transferId: id,
      sendDir: keys.o2j,
      recvDir: keys.j2o,
      sendCounter: 1,
      recvCounter: 1,
    });
    await expect(sendP).rejects.toThrow(/no sender record/);
  });
});

describe('resume role binding (V13-PR08 review)', () => {
  it('rejects a sender resume attempt whose role is not offerer', async () => {
    const keys = await deriveTransferKeys(new Uint8Array(32).fill(41));
    const sendPort = new FakePort();
    const sendP = runTransferCore(sendPort, {
      createDigest: await createSha256DigestFactory(),
      createSink: () => {
        throw new Error('sender has no sink');
      },
      fileSource: blobFileSource,
    });
    sendPort.toWorker({
      kind: 'start-send',
      files: [new File([new Uint8Array(8)], 'x.bin')],
      sendDir: keys.o2j,
      recvDir: keys.j2o,
      sendCounter: 1,
      recvCounter: 1,
      resumeAttempt: {
        transferId: 'ab'.repeat(16),
        manifestFingerprint: 'a'.repeat(64),
        role: 'joiner', // mismatched persisted/host role
        resumeSecret: new Uint8Array(32).fill(9),
      },
    });
    await expect(sendP).rejects.toThrow(/sender resume attempt must carry the offerer role/);
  });

  it('rejects a receiver resume attempt whose role is not joiner', async () => {
    const keys = await deriveTransferKeys(new Uint8Array(32).fill(42));
    const recvPort = new FakePort();
    const recvP = runTransferCore(recvPort, {
      createDigest: await createSha256DigestFactory(),
      createSink: () => new MemorySink(),
      fileSource: blobFileSource,
    });
    recvPort.toWorker({
      kind: 'start-recv',
      destination: { kind: 'auto' },
      sendDir: keys.j2o,
      recvDir: keys.o2j,
      sendCounter: 1,
      recvCounter: 1,
      resumeAttempt: {
        transferId: 'ab'.repeat(16),
        manifestFingerprint: 'a'.repeat(64),
        role: 'offerer', // mismatched persisted/host role
        resumeSecret: new Uint8Array(32).fill(9),
      },
    });
    await expect(recvP).rejects.toThrow(/receiver resume attempt must carry the joiner role/);
  });
});
