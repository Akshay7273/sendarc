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
  RESUME_AUTH_VERSION,
  ResumePreamble,
  TransferSender,
  TransferReceiver,
  TransferError,
  bytesToHex,
  deriveResumeSecret,
  encodeResumeSecretEnvelope,
  manifestFingerprint,
  type Digest,
  type Destination,
  type DirectionalKey,
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
import {
  newSenderRecord,
  refreshSenderRecord,
  senderRecordChecksum,
  type SenderRecordStore,
} from './sender-record.js';

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
    // V13-PR08: while a resume preamble is in flight, inbound frames feed the preamble, not
    // the engine; frames arriving after it settles but before the engine is installed are
    // queued and replayed in order, so no frame is dropped or misrouted.
    let preamble: ResumePreamble | undefined;
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
          if (preamble && !preamble.isSettled()) void preamble.handle(frame);
          else if (engine) consume(engine, frame);
          else pending.push(frame);
          return;
        }
        case 'transport-changed':
          if (engine) void engine.transportChanged();
          else pendingTransportChange = true;
          return;
        case 'cancel':
          if (engine) engine.cancel(msg.reason);
          // An in-flight resume preamble must settle when the peer tears down, exactly as
          // the CLI driver's ctx-bound wait aborts; a queued cancel that only reaches the
          // future engine would leave the handshake hanging forever.
          else if (preamble && !preamble.isSettled()) preamble.cancel();
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
        // V13-PR08: an explicit cross-session resume runs resume-auth-v1 with the peer
        // strictly before the transfer engine starts; only a successful mutual
        // authentication reuses the record's verified progress under a FRESH resumed key
        // epoch (never the session keys for the transfer).
        let sendDir = msg.sendDir;
        let recvDir = msg.recvDir;
        let sendCounter = msg.sendCounter;
        let recvCounter = msg.recvCounter;
        if (msg.resumeAttempt !== undefined) {
          const resumed = await runResumePreamble(msg, send, (p) => (preamble = p));
          sendDir = resumed.sendDir;
          recvDir = resumed.recvDir;
          sendCounter = resumed.sendCounter;
          recvCounter = resumed.recvCounter;
          transferId = msg.resumeAttempt.transferId;
        }
        const sender = new TransferSender({
          files: sources,
          send,
          sendDir,
          recvDir,
          sendCounterStart: sendCounter,
          recvCounterStart: recvCounter,
          createDigest: deps.createDigest,
          // Mint a stable transfer id so the manifest opts into resumption and a crashed
          // receiver can journal and resume this exact transfer (V13-PR03). A restart
          // reuses the caller's id instead (V13-PR04).
          newTransferId: () => {
            transferId = mintTransferId();
            return transferId;
          },
          // Fresh sends carry `msg.transferId`; an explicit cross-session resume reuses the
          // interrupted id from the attempt (set above) so the manifest binds to the same
          // journal/fingerprint the peer authenticated. Omitting it would mint a NEW id and
          // silently abandon the interrupted transfer's durable state.
          ...(transferId !== '' ? { transferId } : {}),
          onProgress: (bytes) => post({ kind: 'progress', bytes }),
          onManifest: async (manifest) => {
            manifestFiles = manifest.files;
            const store = deps.senderRecords;
            if (!store) return;
            // Persist or verify the sender record strictly before the manifest frame goes
            // out: the stable id + canonical source identity are durable before the id is
            // advertised, and a changed source aborts the send with nothing transmitted.
            // The transfer-scoped resume credential (V13-PR07) is derived from the resume
            // root and attached only to a fresh record — a restart's already-persisted
            // credential is never replaced.
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
        // V13-PR08: an explicit cross-session resume runs resume-auth-v1 with the peer
        // strictly before the transfer engine starts; only after mutual authentication may
        // the pre-selected interrupted journal's verified progress be advertised, under a
        // FRESH resumed key epoch.
        let sendDir = _msg.sendDir;
        let recvDir = _msg.recvDir;
        let sendCounter = _msg.sendCounter;
        let recvCounter = _msg.recvCounter;
        if (_msg.resumeAttempt !== undefined) {
          // The user pre-selected this interrupted journal locally; its verified progress
          // may be reused only after resume-auth succeeds in this session.
          if (isBrowserDestination(destination) && destination.expectResumeFor) {
            destination.expectResumeFor(_msg.resumeAttempt.transferId);
          }
          const resumed = await runResumePreamble(_msg, send, (p) => (preamble = p));
          sendDir = resumed.sendDir;
          recvDir = resumed.recvDir;
          sendCounter = resumed.sendCounter;
          recvCounter = resumed.recvCounter;
          if (isBrowserDestination(destination) && destination.durableMeta) {
            // Only now may the pre-selected journal's verified progress be reused.
            destination.authorizeResume?.();
          }
        }
        // The resume seam mirrors the CLI driver (durable.go): a shared, mutable resume
        // seed is filled from onManifestSet — after the destination prepares against the
        // authenticated manifest — and the wire receiver applies it before streaming.
        const receiverOpts: ConstructorParameters<typeof TransferReceiver>[0] = {
          send,
          sendDir,
          recvDir,
          sendCounterStart: sendCounter,
          recvCounterStart: recvCounter,
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
            // V13-PR07: after the manifest validated and bound to the journal, derive the
            // transfer-scoped resume credential from the original session resume root and
            // persist it into the receive journal — before it can authorize a future
            // cross-session resume. Only the scoped root crosses into the worker.
            if (_msg.resumeRoot !== undefined && isBrowserDestination(destination)) {
              await destination.attachResumeSecret?.(manifest, _msg.resumeRoot);
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
 * V13-PR08: run resume-auth-v1 with the peer over the sealed session channel, strictly
 * before the transfer engine starts. The resume-auth messages travel as FrameResumeAuth
 * frames sealed under the SESSION directional keys; the engine then runs under the FRESH
 * resumed key epoch derived from the mutually authenticated resume master, with counters
 * starting at 0 (safe only because the keys+salts are new). Inbound frames arriving while
 * the preamble is in flight are routed to it by the message handler; frames arriving after
 * it settles but before the engine is installed are queued and replayed by `bind`.
 *
 * `setPreamble` publishes the in-flight preamble to the inbound handler so frames reach it.
 */
async function runResumePreamble(
  msg: StartSendMsg | StartRecvMsg,
  send: (frame: Uint8Array) => void,
  setPreamble: (p: ResumePreamble | undefined) => void,
): Promise<{
  sendDir: DirectionalKey;
  recvDir: DirectionalKey;
  sendCounter: number;
  recvCounter: number;
}> {
  const attempt = msg.resumeAttempt!;
  const preamble = new ResumePreamble({
    role: attempt.role,
    transferId: attempt.transferId,
    fingerprint: attempt.manifestFingerprint,
    resumeSecret: attempt.resumeSecret,
    send,
    sendDir: msg.sendDir,
    recvDir: msg.recvDir,
    sendCounter: msg.sendCounter,
    recvCounter: msg.recvCounter,
  });
  setPreamble(preamble);
  try {
    await preamble.start();
    const result = await preamble.done();
    if (result === undefined) {
      throw preamble.result(); // throws the terminal error
    }
    // The offerer sends on O2J and receives on J2O; the joiner is the mirror. The resumed
    // result is role-agnostic directional keys; pick this peer's send/recv by its role.
    const sendDir: DirectionalKey = attempt.role === 'offerer' ? result.keys.o2j : result.keys.j2o;
    const recvDir: DirectionalKey = attempt.role === 'offerer' ? result.keys.j2o : result.keys.o2j;
    return { sendDir, recvDir, sendCounter: result.sendCounter, recvCounter: result.recvCounter };
  } finally {
    setPreamble(undefined);
  }
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
    if (msg.resumeRoot !== undefined) {
      // V13-PR07: derive the transfer-scoped resume credential from the ORIGINAL session
      // resume root and persist it in the same record, strictly before the manifest frame
      // is transmitted. On a restart the record already carries the original-session
      // credential and it is never re-derived or replaced.
      const envelope = await deriveResumeSecretEnvelope(manifest, msg.resumeRoot);
      record.resumeSecret = envelope;
      record.checksum = await senderRecordChecksum(record);
    }
    await store.put(record);
    return;
  }
  const refreshed = await refreshSenderRecord(prior.record, manifest, msg.reattachment, Date.now());
  // A restart keeps the record's original-session credential untouched: refreshSenderRecord
  // spreads the prior record, so resumeSecret rides along and is never replaced.
  await store.put(refreshed);
}

/**
 * Derive the persisted transfer-scoped resume credential envelope from the resume root and
 * the authenticated manifest (V13-PR07). The manifest's transfer id + canonical fingerprint
 * are bound into the derivation; the secret is never persisted outside this envelope.
 */
async function deriveResumeSecretEnvelope(
  manifest: Manifest,
  resumeRoot: Uint8Array,
): Promise<import('@sendbeam/protocol').ResumeSecretEnvelope> {
  if (manifest.transferId === undefined) {
    throw new TransferError('integrity', 'resume secret requires a manifest with a transfer id');
  }
  const fingerprint = await manifestFingerprint(manifest);
  const secret = await deriveResumeSecret(
    resumeRoot,
    RESUME_AUTH_VERSION,
    manifest.transferId,
    fingerprint,
  );
  return encodeResumeSecretEnvelope(secret);
}
