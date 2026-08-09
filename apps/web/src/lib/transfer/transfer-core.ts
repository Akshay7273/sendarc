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
  type Digest,
  type FileEntry,
  type FileSource,
  type Sink,
} from '@sendarc/protocol';
import type { DuplexPort, HostToWorker, StartSendMsg, StartRecvMsg, WorkerToHost } from './wire.js';

export interface TransferCoreDeps {
  /** Fresh streaming whole-file hasher (matches `sha256sum`). One live digest per call. */
  createDigest(): Digest;
  /** Open the receive destination once the manifest names the file. */
  createSink(file: FileEntry): Sink | Promise<Sink>;
  /** Adapt the sender's File into a re-callable byte source. */
  fileSource(file: File): FileSource;
}

type Port = DuplexPort<HostToWorker, WorkerToHost>;

/** Drive one transfer to completion over `port`. Resolves on `done`, rejects on any failure. */
export function runTransferCore(port: Port, deps: TransferCoreDeps): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    let engine:
      | {
          handle(frame: Uint8Array): void;
          pause(): void;
          resume(): void;
          cancel(reason?: string): void;
        }
      | undefined;
    let started = false;
    const pending: Uint8Array[] = [];
    const pendingControls: Array<'pause' | 'resume' | 'cancel'> = [];

    const post = (msg: WorkerToHost): void => port.postMessage(msg);
    const send = (frame: Uint8Array): void => {
      const buf = transferable(frame);
      port.postMessage({ kind: 'outbound-frame', frame: buf }, [buf]);
    };
    const bind = (e: {
      handle(frame: Uint8Array): void;
      pause(): void;
      resume(): void;
      cancel(reason?: string): void;
    }): void => {
      engine = e;
      post({ kind: 'state', state: 'running' });
      for (const f of pending) e.handle(f);
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
          if (engine) engine.handle(frame);
          else pending.push(frame);
          return;
        }
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
        const source = deps.fileSource(msg.file);
        const sender = new TransferSender({
          file: source,
          send,
          sendDir: msg.sendDir,
          recvDir: msg.recvDir,
          sendCounterStart: msg.sendCounter,
          recvCounterStart: msg.recvCounter,
          createDigest: deps.createDigest,
          onProgress: (bytes) => post({ kind: 'progress', bytes }),
          onStateChange: (state) => post({ kind: 'state', state }),
          ...(msg.blockSize !== undefined ? { blockSize: msg.blockSize } : {}),
          ...(msg.frameSize !== undefined ? { frameSize: msg.frameSize } : {}),
          ...(msg.window !== undefined ? { window: msg.window } : {}),
        });
        bind(sender);
        const digest = await sender.run();
        post({ kind: 'done', name: source.meta.name, size: source.meta.size, digest });
        resolve();
      } catch (e) {
        fail(e);
      }
    }

    async function startRecv(_msg: StartRecvMsg): Promise<void> {
      try {
        const deferred = new DeferredSink();
        const receiver = new TransferReceiver({
          send,
          sendDir: _msg.sendDir,
          recvDir: _msg.recvDir,
          sendCounterStart: _msg.sendCounter,
          recvCounterStart: _msg.recvCounter,
          createDigest: deps.createDigest,
          sink: deferred,
          onProgress: (bytes) => post({ kind: 'progress', bytes }),
          onStateChange: (state) => post({ kind: 'state', state }),
          onManifest: async (file) => {
            deferred.attach(await deps.createSink(file));
            post({ kind: 'manifest', name: file.name, size: file.size, mime: file.mime });
          },
        });
        bind(receiver);
        const result = await receiver.done;
        post({
          kind: 'done',
          name: result.file.name,
          size: result.file.size,
          digest: result.digest,
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
class DeferredSink implements Sink {
  private inner: Sink | undefined;
  attach(sink: Sink): void {
    this.inner = sink;
  }
  write(offset: number, bytes: Uint8Array): void | Promise<void> {
    if (!this.inner) throw new TransferError('sink_error', 'sink not opened before write');
    return this.inner.write(offset, bytes);
  }
  close(): void | Promise<void> {
    return this.inner?.close();
  }
  abort(reason?: string): void | Promise<void> {
    return this.inner?.abort(reason);
  }
}

/** A sealed frame's own ArrayBuffer when it fits exactly (the common case), else a fresh copy. */
function transferable(frame: Uint8Array): ArrayBuffer {
  if (frame.byteOffset === 0 && frame.byteLength === frame.buffer.byteLength) {
    return frame.buffer as ArrayBuffer;
  }
  return frame.slice().buffer;
}
