/**
 * Transfer Web Worker entry. It hosts {@link runTransferCore} with the browser-backed deps —
 * `hash-wasm` for the whole-file digest, an OPFS sink for the received file, a Blob-backed source
 * for the sent file — so all crypto, hashing, and disk writes stay off the main thread. Loading
 * the SHA-256 wasm is async; we post `{kind:'ready'}` only once it resolves, and the orchestrator
 * waits for that before sending a start message.
 *
 * Browser-only (runs as a module worker); not unit-tested — the core it drives has its own
 * loopback test, and the whole path is exercised by the e2e transfer.
 */

import { runTransferCore } from './transfer-core.js';
import { createSha256DigestFactory } from './digest.js';
import { blobFileSource } from './file-source.js';
import { createBrowserDestination } from './sink.js';
import type { DuplexPort, HostToWorker, WorkerToHost } from './wire.js';

/** The slice of the worker global we touch, typed narrowly to avoid the DOM/WebWorker lib clash. */
interface WorkerScope {
  postMessage(message: unknown, transfer?: Transferable[]): void;
  addEventListener(type: 'message', handler: (ev: MessageEvent) => void): void;
}
const ctx = self as unknown as WorkerScope;

const post = (msg: WorkerToHost, transfer?: Transferable[]): void => ctx.postMessage(msg, transfer);

const port: DuplexPort<HostToWorker, WorkerToHost> = {
  postMessage: (msg, transfer) => post(msg, transfer),
  addEventListener: (_type, handler) =>
    ctx.addEventListener('message', (ev) => handler({ data: ev.data as HostToWorker })),
};

async function main(): Promise<void> {
  const createDigest = await createSha256DigestFactory();
  post({ kind: 'ready' });
  await runTransferCore(port, {
    createDigest,
    createSink: () => {
      throw new Error('browser worker uses a destination factory');
    },
    createDestination: (spec) => createBrowserDestination(spec, createDigest),
    fileSource: (file) => blobFileSource(file),
  });
}

void main().catch((err: unknown) => {
  post({
    kind: 'error',
    reason: 'worker',
    message: err instanceof Error ? err.message : String(err),
  });
});
