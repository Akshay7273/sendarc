/**
 * transfer-core — the transport-agnostic engine loop that runs inside the transfer Web Worker.
 * It waits on a {@link DuplexPort} for one start message, drives a TransferSender or
 * TransferReceiver against that port (forwarding outbound frames, progress, and completion to
 * the host, feeding inbound frames into the engine), and resolves when the transfer settles.
 * The receiver's sink is opened lazily from the manifest via a deferred wrapper, so the same
 * core runs unchanged in the browser and in the Node loopback test with two fake ports wired
 * together.
 */

import {
  TransferSender,
  TransferReceiver,
  TransferError,
  bytesToHex,
  type Digest,
  type Destination,
  type FileEntry,
  type FileSource,
  type Manifest,
  type Sink,
} from '@sendbeam/protocol';
import type {
  DuplexPort,
  HostToWorker,
  ReceiveDestinationSpec,
  StartSendMsg,
  StartRecvMsg,
  WorkerToHost,
} from './wire.js';
import type { BrowserDestination } from './sink.js';
import { newSenderRecord, refreshSenderRecord, type SenderRecordStore } from './sender-record.js';

export interface TransferCoreDeps {
  /** Fresh streaming whole-file hasher (matches `sha256sum`). One live digest per call. */
  createDigest(): Digest;
  /** Open the receive destination once the manifest names the file. */
  createSink(file: FileEntry): Sink | Promise<Sink>;
  /** Browser worker destination selection; tests may continue supplying createSink only. */
  createDestination?(spec: ReceiveDestinationSpec): BrowserDestination;
  /** Adapt the sender's File into a re-callable byte source. */
  fileSource(file: File): FileSource;
  /**
   * Sender metadata store (V13-PR04). Absent when the platform cannot persist records
   * (no IndexedDB): the send proceeds but offers no restart/reopen capability.
   */
  senderRecords?: SenderRecordStore;
}

type Port = DuplexPort<HostToWorker, WorkerToHost>;

/** Drive one transfer to completion over `port`. Resolves on `done`, rejects on any failure. */
export function runTransferCore(port: Port, deps: TransferCoreDeps): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    let engine:
      | {
          handle(frame: Uint8Array): void | Promise<void>;
          pause(): void;
          resume(): void;
          cancel(reason?: string): void;
          transportChanged(): void | Promise<void>;
        }
      | undefined;
    let started = false;
    const pending: Uint8Array[] = [];
    const pendingControls: Array<'pause' | 'resume' | 'cancel'> = [];
    let pendingTransportChange = false;

    const post = (msg: WorkerToHost): void => port.postMessage(msg);
    const send = (frame: Uint8Array): void => {
      const buf = transferable(frame);
      port.postMessage({ kind: 'outbound-frame', frame: buf }, [buf]);
    };
    const bind = (e: {
      handle(frame: Uint8Array): void | Promise<void>;
      pause(): void;
      resume(): void;
      cancel(reason?: string): void;
      transportChanged(): void | Promise<void>;
    }): void => {
      engine = e;
      post({ kind: 'state', state: 'running' });
      if (pendingTransportChange) void e.transportChanged();
      pendingTransportChange = false;
      for (const f of pending) consume(e, f);
      pending.length = 0;
      for (const op of pendingControls) {
        if (op === 'pause') e.pause();
        else if (op === 'resume') e.resume();
        else e.cancel();
      }
      pendingControls.length = 0;
    };
    const fail = (e: unknown): void => {
      const reason = e instanceof TransferError ? e.reason : 'integrity';
      const message = e instanceof Error ? e.message : String(e);
      post({ kind: 'error', reason, message });
      reject(e instanceof Error ? e : new Error(message));
    };
    const consume = (
      target: { handle(frame: Uint8Array): void | Promise<void> },
      frame: Uint8Array,
    ): void => {
      void Promise.resolve(target.handle(frame)).finally(() =>
        post({ kind: 'frame-consumed', bytes: frame.byteLength }),
      );
    };

    port.addEventListener('message', (ev) => {
      const msg = ev.data;
      switch (msg.kind) {
        case 'start-send':
          if (!started) {
            started = true;
            void startSend(msg);
          }
          return;
        case 'start-recv':
          if (!started) {
            started = true;
            void startRecv(msg);
          }
          return;
        case 'inbound-frame': {
          const frame = new Uint8Array(msg.frame);
          if (engine) consume(engine, frame);
          else pending.push(frame);
          return;
        }
        case 'transport-changed':
          if (engine) void engine.transportChanged();
          else pendingTransportChange = true;
          return;
        case 'cancel':
          if (engine) engine.cancel(msg.reason);
          else pendingControls.push('cancel');
          return;
        case 'control':
          if (!engine) {
            pendingControls.push(msg.op);
          } else if (msg.op === 'pause') engine.pause();
          else if (msg.op === 'resume') engine.resume();
          else engine.cancel();
          return;
      }
    });

    async function startSend(msg: StartSendMsg): Promise<void> {
      try {
        const sources = msg.files.map((file) => deps.fileSource(file));
        let manifestFiles: FileEntry[] = [];
        let transferId = msg.transferId ?? '';
        const sender = new TransferSender({
          files: sources,
          send,
          sendDir: msg.sendDir,
          recvDir: msg.recvDir,
          sendCounterStart: msg.sendCounter,
          recvCounterStart: msg.recvCounter,
          createDigest: deps.createDigest,
          // Mint a stable transfer id so the manifest opts into resumption and a crashed
          // receiver can journal and resume this exact transfer (V13-PR03). A restart
          // reuses the caller's id instead (V13-PR04).
          newTransferId: () => {
            transferId = mintTransferId();
            return transferId;
          },
          ...(msg.transferId !== undefined ? { transferId: msg.transferId } : {}),
          onProgress: (bytes) => post({ kind: 'progress', bytes }),
          onManifest: async (manifest) => {
            manifestFiles = manifest.files;
            const store = deps.senderRecords;
            if (!store) return;
            // Persist or verify the sender record strictly before the manifest frame goes
            // out: the stable id + canonical source identity are durable before the id is
            // advertised, and a changed source aborts the send with nothing transmitted.
            await persistSenderRecord(store, msg, manifest);
          },
          onStateChange: (state) => post({ kind: 'state', state }),
          ...(msg.blockSize !== undefined ? { blockSize: msg.blockSize } : {}),
          ...(msg.frameSize !== undefined ? { frameSize: msg.frameSize } : {}),
          ...(msg.window !== undefined ? { window: msg.window } : {}),
        });
        bind(sender);
        const digest = await sender.run();
        // Verified success: the transfer settled, so the sender record is spent. Removal
        // is post-success cleanup, so a failure here must not fail the transfer — the
        // lingering record only offers a harmless (receiver-verified) re-send.
        if (transferId !== '' && deps.senderRecords) {
          await deps.senderRecords.remove(transferId).catch(() => {});
        }
        post({
          kind: 'done',
          files: manifestFiles.map((file) => ({
            name: file.name,
            size: file.size,
            digest: file.fileDigest,
          })),
          totalSize: manifestFiles.reduce((total, file) => total + file.size, 0),
          digest,
        });
        resolve();
      } catch (e) {
        fail(e);
      }
    }

    async function startRecv(_msg: StartRecvMsg): Promise<void> {
      try {
        const destination = deps.createDestination
          ? deps.createDestination(_msg.destination)
          : sinkFactoryDestination(deps.createSink);
        // The resume seam mirrors the CLI driver (durable.go): a shared, mutable resume
        // seed is filled from onManifestSet — after the destination prepares against the
        // authenticated manifest — and the wire receiver applies it before streaming.
        const receiverOpts: ConstructorParameters<typeof TransferReceiver>[0] = {
          send,
          sendDir: _msg.sendDir,
          recvDir: _msg.recvDir,
          sendCounterStart: _msg.sendCounter,
          recvCounterStart: _msg.recvCounter,
          createDigest: deps.createDigest,
          destination,
          onProgress: (bytes) => post({ kind: 'progress', bytes }),
          onStateChange: (state) => post({ kind: 'state', state }),
          onManifestSet: async (manifest) => {
            post({
              kind: 'manifest',
              files: manifest.files.map((file) => ({
                name: file.name,
                size: file.size,
                mime: file.mime,
              })),
              totalSize: manifest.totalSize,
            });
            if (isBrowserDestination(destination) && destination.durableMeta) {
              const meta = destination.durableMeta();
              if (meta) {
                post({
                  kind: 'durable',
                  transferId: meta.transferId,
                  ownerId: meta.ownerId,
                  resumed: meta.resumed,
                  committedBytes: meta.committedBytes,
                  totalBytes: meta.totalBytes,
                });
                const state = destination.resumeStateFor?.(manifest);
                if (state) receiverOpts.resume = state;
              }
            }
          },
        };
        const receiver = new TransferReceiver(receiverOpts);
        bind(receiver);
        const result = await receiver.done;
        const output = isBrowserDestination(destination) ? destination.result() : undefined;
        post({
          kind: 'done',
          files: result.files.map((file, idx) => ({
            name: file.name,
            size: file.size,
            digest: result.digests[idx]!,
          })),
          totalSize: result.totalSize,
          digest: result.digest,
          ...(output?.kind === 'opfs' ? { output } : {}),
        });
        resolve();
      } catch (e) {
        fail(e);
      }
    }
  });
}

/**
 * A Sink whose destination is opened after construction — the receiver builds it before the
 * manifest arrives, then `onManifest` attaches the real sink before the first verified write.
 */
function sinkFactoryDestination(
  createSink: (file: FileEntry) => Sink | Promise<Sink>,
): Destination {
  const sinks: Sink[] = [];
  return {
    prepare: () => {},
    async open(file) {
      const sink = await createSink(file);
      sinks.push(sink);
      return sink;
    },
    close: () => {},
    async abort(reason) {
      await Promise.allSettled(sinks.map((sink) => sink.abort(reason)));
    },
  };
}

function isBrowserDestination(destination: Destination): destination is BrowserDestination {
  return 'result' in destination;
}

/** A sealed frame's own ArrayBuffer when it fits exactly (the common case), else a fresh copy. */
function transferable(frame: Uint8Array): ArrayBuffer {
  if (frame.byteOffset === 0 && frame.byteLength === frame.buffer.byteLength) {
    return frame.buffer as ArrayBuffer;
  }
  return frame.slice().buffer;
}

/** Mint a stable 128-bit lowercase-hex transfer id so the manifest opts into resumption. */
function mintTransferId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

/**
 * The V13-PR04 sender seam, run strictly before the manifest frame is transmitted:
 *
 *  - Fresh send (no caller-supplied id): persist a new record binding the minted id to the
 *    canonical source identity. A persist failure aborts the send — the id is never
 *    advertised unless a durable record backs it.
 *  - Restart (caller-supplied id): the record must exist and be valid, and its canonical
 *    fingerprint must match the manifest about to be advertised. Any mismatch (or a
 *    missing/corrupt record) fails closed with nothing transmitted, so a changed source is
 *    never advertised under the old id.
 */
async function persistSenderRecord(
  store: SenderRecordStore,
  msg: StartSendMsg,
  manifest: Manifest,
): Promise<void> {
  if (manifest.transferId === undefined) {
    throw new TransferError('integrity', 'sender record requires a manifest with a transfer id');
  }
  const prior = await store.load(manifest.transferId);
  if (prior.kind === 'corrupt') {
    throw new TransferError(
      'integrity',
      `the sender record for transfer ${manifest.transferId} is corrupt and cannot verify ` +
        'the source; forget it and start a new transfer',
    );
  }
  if (prior.kind === 'none') {
    if (msg.transferId !== undefined) {
      throw new TransferError(
        'integrity',
        `no sender record for transfer ${msg.transferId}; the record was lost, so the ` +
          'source cannot be verified — start a new transfer',
      );
    }
    const record = await newSenderRecord(
      manifest,
      msg.reattachment ?? { kind: 'reselection' },
      Date.now(),
    );
    await store.put(record);
    return;
  }
  const refreshed = await refreshSenderRecord(prior.record, manifest, msg.reattachment, Date.now());
  await store.put(refreshed);
}
