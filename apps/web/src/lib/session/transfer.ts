/**
 * Transfer orchestrator — the main-thread conductor that turns a settled rendezvous into a running
 * file transfer. It adopts the still-open signaling socket, brings up the authenticated WebRTC data
 * channel ({@link createPeer}), spawns the transfer worker ({@link runTransferCore} host), and pumps
 * frames between the two: worker → channel with SCTP backpressure ({@link ChannelWriter}), channel →
 * worker as inbound frames. The worker owns crypto and disk; this module owns transport and the
 * public {@link TransferController} the UI binds against (progress, a `done` promise, cancel).
 *
 * Browser-only (needs `Worker`, `RTCPeerConnection`); not unit-tested — the pieces it wires each
 * have their own tests, and the whole path is covered by the e2e transfer.
 */

import type { RendezvousResult } from '@sendarc/protocol';
import type { SignalChannel } from '../signaling/client.js';
import { SignalAuthenticator } from '../transfer/authed-signaling.js';
import { createPeer, type Peer } from '../transfer/peer.js';
import { ChannelWriter } from '../transfer/channel-writer.js';
import { ProgressTracker, type TransferSnapshot } from '../transfer/progress.js';
import { readOpfsFile } from '../transfer/sink.js';
import type { HostToWorker, SessionCrypto, WorkerToHost } from '../transfer/wire.js';

/** Terminal outcome of a transfer. `file` is present on the receive side (the downloadable result). */
export interface TransferOutcome {
  name: string;
  size: number;
  digest: string;
  file?: File;
}

/** A transfer in progress. `done` settles once; `progress` is polled by the UI for a live bar. */
export interface TransferController {
  /** Bytes moved so far (plaintext payload), updated as the worker reports progress. */
  progress(): number;
  /** The declared total size in bytes, once known (immediately when sending, on manifest when receiving). */
  total(): number | undefined;
  /** A coherent acknowledged-byte, smoothed-rate, ETA, and run-state snapshot. */
  snapshot(): TransferSnapshot;
  /** Resolves when the transfer completes and verifies; rejects on any failure. */
  readonly done: Promise<TransferOutcome>;
  /** Stop producing new data frames; already-buffered transport bytes may drain. */
  pause(): void;
  /** Continue a paused transfer. */
  resume(): void;
  /** Abort the transfer and tear down the worker, peer, and socket. Idempotent. */
  cancel(reason?: string): void;
}

export interface SendOptions {
  file: File;
}

/** Start sending `opts.file` to the peer over the adopted rendezvous socket. */
export function runSend(
  rendezvous: RendezvousResult,
  signaling: SignalChannel,
  opts: SendOptions,
): TransferController {
  return run(rendezvous, signaling, {
    role: 'send',
    total: opts.file.size,
    start: () => ({ kind: 'start-send', file: opts.file, ...crypto(rendezvous) }),
  });
}

/** Start receiving a file from the peer over the adopted rendezvous socket. */
export function runReceive(
  rendezvous: RendezvousResult,
  signaling: SignalChannel,
): TransferController {
  return run(rendezvous, signaling, {
    role: 'receive',
    start: () => ({ kind: 'start-recv', ...crypto(rendezvous) }),
  });
}

interface RunSpec {
  role: 'send' | 'receive';
  /** Known upfront only when sending. */
  total?: number;
  start: () => HostToWorker;
}

function run(
  rendezvous: RendezvousResult,
  signaling: SignalChannel,
  spec: RunSpec,
): TransferController {
  let total = spec.total;
  const progress = new ProgressTracker(total);
  let settled = false;
  let peer: Peer | undefined;
  let worker: Worker | undefined;
  let writer: ChannelWriter | undefined;
  let cancelTimer: ReturnType<typeof setTimeout> | undefined;

  let resolveDone!: (o: TransferOutcome) => void;
  let rejectDone!: (err: Error) => void;
  const donePromise = new Promise<TransferOutcome>((resolve, reject) => {
    resolveDone = resolve;
    rejectDone = reject;
  });

  const cleanup = (): void => {
    clearTimeout(cancelTimer);
    worker?.terminate();
    peer?.close();
    signaling.close();
  };
  const finish = (o: TransferOutcome): void => {
    if (settled) return;
    settled = true;
    cleanup();
    resolveDone(o);
  };
  const fail = (err: Error): void => {
    if (settled) return;
    settled = true;
    cleanup();
    rejectDone(err);
  };

  void (async () => {
    try {
      const auth = SignalAuthenticator.fromSession(
        rendezvous.role,
        rendezvous.room,
        rendezvous.spake2,
      );
      const p = createPeer({ role: rendezvous.role, auth, send: (msg) => signaling.send(msg) });
      peer = p;
      signaling.onMessage((msg) => {
        if (msg.type === 'sdp' || msg.type === 'ice') p.accept(msg);
      });

      const w = new Worker(new URL('../transfer/transfer.worker.ts', import.meta.url), {
        type: 'module',
      });
      worker = w;
      // Listen for `ready` before any await — the worker posts it as soon as its SHA-256 wasm loads,
      // which can beat the channel negotiation; a late listener would miss it and hang forever.
      const ready = workerReady(w);

      const channel = await p.channel;
      writer = new ChannelWriter(channel);
      await ready;

      // Worker → host events.
      w.addEventListener('message', (ev: MessageEvent) => {
        const msg = ev.data as WorkerToHost;
        switch (msg.kind) {
          case 'outbound-frame':
            writer?.write(msg.frame);
            return;
          case 'progress':
            progress.update(msg.bytes);
            return;
          case 'manifest':
            total = msg.size;
            progress.setTotal(msg.size);
            return;
          case 'state':
            progress.setState(msg.state);
            return;
          case 'done':
            void completeReceive(msg.name, msg.size, msg.digest);
            return;
          case 'error':
            if (msg.reason === 'canceled') {
              void (async () => {
                await writer?.drain();
                fail(new Error(msg.message));
              })();
            } else {
              fail(new Error(msg.message));
            }
            return;
          case 'ready':
            return;
        }
      });

      // Channel → worker: forward every inbound data frame as a Transferable.
      p.onData((frame) =>
        w.postMessage({ kind: 'inbound-frame', frame } satisfies HostToWorker, [frame]),
      );

      // Kick off the transfer in the worker.
      const startMsg = spec.start();
      w.postMessage(startMsg);
    } catch (err) {
      fail(err instanceof Error ? err : new Error(String(err)));
    }
  })();

  async function completeReceive(name: string, size: number, digest: string): Promise<void> {
    if (spec.role === 'receive') {
      try {
        const file = await readOpfsFile(name);
        finish({ name, size, digest, file });
      } catch (err) {
        fail(err instanceof Error ? err : new Error(String(err)));
      }
    } else {
      finish({ name, size, digest });
    }
  }

  return {
    progress: () => progress.snapshot().bytes,
    total: () => total,
    snapshot: () => progress.snapshot(),
    done: donePromise,
    pause: () => {
      if (settled || progress.snapshot().state === 'paused') return;
      progress.setState('paused');
      worker?.postMessage({ kind: 'control', op: 'pause' } satisfies HostToWorker);
    },
    resume: () => {
      if (settled || progress.snapshot().state !== 'paused') return;
      progress.setState('running');
      worker?.postMessage({ kind: 'control', op: 'resume' } satisfies HostToWorker);
    },
    cancel: (reason = 'cancelled') => {
      if (settled) return;
      progress.setState('canceled');
      if (!worker) {
        fail(new Error(reason));
        return;
      }
      worker.postMessage({ kind: 'control', op: 'cancel' } satisfies HostToWorker);
      cancelTimer = setTimeout(() => fail(new Error(reason)), 1000);
    },
  };
}

/** Resolve once the worker posts its one-time `ready` handshake. */
function workerReady(w: Worker): Promise<void> {
  return new Promise<void>((resolve) => {
    const onReady = (ev: MessageEvent): void => {
      if ((ev.data as WorkerToHost).kind === 'ready') {
        w.removeEventListener('message', onReady);
        resolve();
      }
    };
    w.addEventListener('message', onReady);
  });
}

/** Pull the directional keys and continuing counters out of the handshake result for the worker. */
function crypto(r: RendezvousResult): SessionCrypto {
  const sendDir = r.role === 'offerer' ? r.keys.o2j : r.keys.j2o;
  const recvDir = r.role === 'offerer' ? r.keys.j2o : r.keys.o2j;
  return { sendDir, recvDir, sendCounter: r.sendCounter, recvCounter: r.recvCounter };
}
