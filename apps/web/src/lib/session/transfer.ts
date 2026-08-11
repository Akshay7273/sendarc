/**
 * Transfer orchestrator — the main-thread conductor that turns a settled rendezvous into a running
 * file transfer. It adopts the still-open signaling socket, prefers an authenticated WebRTC data
 * channel ({@link createPeer}), and falls back to the encrypted relay when negotiation or an active
 * direct path fails. It spawns the transfer worker ({@link runTransferCore} host) and pumps frames
 * between the selected path and worker. The worker owns crypto and disk; this module owns transport selection and the
 * public {@link TransferController} the UI binds against (progress, a `done` promise, cancel).
 *
 * Browser-only (needs `Worker`, `RTCPeerConnection`); not unit-tested — the pieces it wires each
 * have their own tests, and the whole path is covered by the e2e transfer.
 */

import type { RendezvousResult } from '@sendbeam/protocol';
import { WakeLockManager } from './wake-lock.js';
import type { SignalChannel } from '../signaling/client.js';
import { SignalAuthenticator } from '../transfer/authed-signaling.js';
import { createPeer, type Peer } from '../transfer/peer.js';
import { ChannelWriter } from '../transfer/channel-writer.js';
import { RelayTransport } from '../transfer/relay.js';
import { ProgressTracker, type TransferSnapshot } from '../transfer/progress.js';
import { readOpfsOutput, removeOpfsOutput } from '../transfer/sink.js';
import type {
  HostToWorker,
  ReceiveDestinationSpec,
  SessionCrypto,
  WorkerToHost,
} from '../transfer/wire.js';

/** Terminal outcome of a transfer. `file` is present on the receive side (the downloadable result). */
export interface TransferOutcome {
  name: string;
  size: number;
  digest: string;
  files: Array<{ name: string; size: number; digest: string }>;
  file?: File;
  savedDirectly?: boolean;
  /** Release a temporary browser-staged output after its download link is gone. */
  cleanup?: () => Promise<void>;
}

/** A transfer in progress. `done` settles once; `progress` is polled by the UI for a live bar. */
export interface TransferController {
  /** Bytes moved so far (plaintext payload), updated as the worker reports progress. */
  progress(): number;
  /** The declared total size in bytes, once known (immediately when sending, on manifest when receiving). */
  total(): number | undefined;
  /** A coherent acknowledged-byte, smoothed-rate, ETA, and run-state snapshot. */
  snapshot(): TransferSnapshot;
  /** Active byte path, including automatic relay fallback. */
  transport(): 'connecting' | 'direct' | 'relay';
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
  files: File[];
}

/** Start sending an ordered file/folder selection over the adopted rendezvous socket. */
export function runSend(
  rendezvous: RendezvousResult,
  signaling: SignalChannel,
  opts: SendOptions,
): TransferController {
  return run(rendezvous, signaling, {
    role: 'send',
    total: opts.files.reduce((total, file) => total + file.size, 0),
    start: () => ({ kind: 'start-send', files: opts.files, ...crypto(rendezvous) }),
  });
}

/** Start receiving a file from the peer over the adopted rendezvous socket. */
export function runReceive(
  rendezvous: RendezvousResult,
  signaling: SignalChannel,
  destination: ReceiveDestinationSpec = { kind: 'auto' },
): TransferController {
  return run(rendezvous, signaling, {
    role: 'receive',
    start: () => ({ kind: 'start-recv', destination, ...crypto(rendezvous) }),
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
  const wakeLock = new WakeLockManager();
  let settled = false;
  let peer: Peer | undefined;
  let worker: Worker | undefined;
  let writer: ChannelWriter | undefined;
  let relay: RelayTransport | undefined;
  let transport: 'connecting' | 'direct' | 'relay' = 'connecting';
  let switchPromise: Promise<void> | undefined;
  let cancelTimer: ReturnType<typeof setTimeout> | undefined;

  let resolveDone!: (o: TransferOutcome) => void;
  let rejectDone!: (err: Error) => void;
  const donePromise = new Promise<TransferOutcome>((resolve, reject) => {
    resolveDone = resolve;
    rejectDone = reject;
  });

  const cleanup = (): void => {
    clearTimeout(cancelTimer);
    wakeLock.setActive(false);
    worker?.terminate();
    peer?.close();
    relay?.close();
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
      const relayPath = new RelayTransport(signaling);
      relay = relayPath;
      signaling.onClose((err) => {
        relayPath.fail(err);
        if (transport !== 'direct' || switchPromise) {
          fail(err);
        }
      });
      signaling.onMessage((msg) => {
        if (relayPath.handleMessage(msg)) return;
        if (msg.type === 'sdp' || msg.type === 'ice') p.accept(msg);
      });
      signaling.onBinary((frame) => relayPath.handleBinary(frame));

      const w = new Worker(new URL('../transfer/transfer.worker.ts', import.meta.url), {
        type: 'module',
      });
      worker = w;
      // Listen for `ready` before any await — the worker posts it as soon as its SHA-256 wasm loads,
      // which can beat the channel negotiation; a late listener would miss it and hang forever.
      const ready = workerReady(w);

      const selected = await selectTransport(p, relayPath);
      transport = selected.kind;
      if (selected.kind === 'direct') {
        writer = new ChannelWriter(selected.channel);
      } else {
        p.close();
      }
      await ready;

      // Channel → worker: forward every inbound data frame as a Transferable.
      const receive = (frame: ArrayBuffer): void =>
        w.postMessage({ kind: 'inbound-frame', frame } satisfies HostToWorker, [frame]);
      const switchToRelay = (): Promise<void> => {
        if (transport === 'relay') return Promise.resolve();
        if (switchPromise) return switchPromise;
        switchPromise = (async () => {
          relayPath.open();
          await relayPath.ready;
          if (settled) return;
          transport = 'relay';
          w.postMessage({ kind: 'transport-changed' } satisfies HostToWorker);
          writer = undefined;
          p.close();
        })().catch((err: unknown) => {
          const failure = err instanceof Error ? err : new Error(String(err));
          fail(failure);
          throw failure;
        });
        return switchPromise;
      };
      const sendOutbound = async (frame: ArrayBuffer): Promise<void> => {
        if (transport === 'relay') {
          await relayPath.write(frame);
          return;
        }
        if (switchPromise) {
          await switchPromise;
          await relayPath.write(frame);
          return;
        }
        try {
          writer!.write(frame);
        } catch {
          await switchToRelay();
          await relayPath.write(frame);
        }
      };

      if (selected.kind === 'direct') {
        p.onData((frame) => {
          if (transport === 'direct' && !switchPromise) receive(frame);
        });
        p.onDisconnect(() => void switchToRelay().catch(() => {}));
        void relayPath.ready.then(switchToRelay).catch(() => {});
        relayPath.onData((frame) => {
          void switchToRelay()
            .then(() => receive(frame))
            .catch(() => {});
        });
      } else {
        relayPath.onData(receive);
      }

      // Worker → host events.
      w.addEventListener('message', (ev: MessageEvent) => {
        const msg = ev.data as WorkerToHost;
        switch (msg.kind) {
          case 'outbound-frame':
            void sendOutbound(msg.frame).catch((err: unknown) =>
              fail(err instanceof Error ? err : new Error(String(err))),
            );
            return;
          case 'frame-consumed':
            if (transport === 'relay') relayPath.consumed(msg.bytes);
            return;
          case 'progress':
            progress.update(msg.bytes);
            return;
          case 'manifest':
            total = msg.totalSize;
            progress.setTotal(msg.totalSize);
            return;
          case 'state':
            progress.setState(msg.state);
            return;
          case 'done':
            void completeTransfer(msg);
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

      // Kick off the transfer in the worker.
      const startMsg = spec.start();
      w.postMessage(startMsg);
      wakeLock.setActive(true);
    } catch (err) {
      fail(err instanceof Error ? err : new Error(String(err)));
    }
  })();

  async function completeTransfer(msg: Extract<WorkerToHost, { kind: 'done' }>): Promise<void> {
    const first = msg.files[0]!;
    if (spec.role === 'receive') {
      try {
        const output = msg.output;
        if (output?.kind === 'opfs') {
          // The transfer is done and the peer was already told (the done ack goes out
          // before this `done`). Tear down the wire before the slow OPFS read so a peer
          // disconnect can't trigger a relay fallback into a room the sender has already
          // left — the server would refuse it and drop our socket. cleanup() below repeats
          // this teardown; every piece is idempotent.
          signaling.close();
          relay?.close();
          peer?.close();
          const file = await readOpfsOutput(output.key, output.name, output.mime);
          finish({
            name: output.name,
            size: msg.totalSize,
            digest: msg.digest,
            files: msg.files,
            file,
            cleanup: () => removeOpfsOutput(output.key),
          });
        } else {
          finish({
            name: first.name,
            size: msg.totalSize,
            digest: msg.digest,
            files: msg.files,
            savedDirectly: true,
          });
        }
      } catch (err) {
        fail(err instanceof Error ? err : new Error(String(err)));
      }
    } else {
      finish({
        name: msg.files.length === 1 ? first.name : `${msg.files.length} files`,
        size: msg.totalSize,
        digest: msg.digest,
        files: msg.files,
      });
    }
  }

  return {
    progress: () => progress.snapshot().bytes,
    total: () => total,
    snapshot: () => progress.snapshot(),
    transport: () => transport,
    done: donePromise,
    pause: () => {
      if (settled || progress.snapshot().state === 'paused') return;
      progress.setState('paused');
      worker?.postMessage({ kind: 'control', op: 'pause' } satisfies HostToWorker);
      wakeLock.setActive(false);
    },
    resume: () => {
      if (settled || progress.snapshot().state !== 'paused') return;
      progress.setState('running');
      worker?.postMessage({ kind: 'control', op: 'resume' } satisfies HostToWorker);
      wakeLock.setActive(true);
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

type SelectedTransport = { kind: 'direct'; channel: RTCDataChannel } | { kind: 'relay' };

async function selectTransport(peer: Peer, relay: RelayTransport): Promise<SelectedTransport> {
  let timer: ReturnType<typeof setTimeout> | undefined = setTimeout(() => relay.open(), 8000);
  const direct = peer.channel.then(
    (channel): SelectedTransport => ({ kind: 'direct', channel }),
    async (): Promise<SelectedTransport> => {
      relay.open();
      await relay.ready;
      return { kind: 'relay' };
    },
  );
  const relayed = relay.ready.then((): SelectedTransport => ({ kind: 'relay' }));
  const selected = await Promise.race([direct, relayed]);
  clearTimeout(timer);
  timer = undefined;
  return selected;
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
