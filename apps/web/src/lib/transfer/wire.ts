/**
 * Message protocol between the main thread and the transfer Web Worker. The worker owns crypto,
 * per-block and whole-file hashing, and sink writes; the main thread owns the RTCDataChannel.
 * Frame payloads cross the boundary as Transferable ArrayBuffers (zero-copy). Both directions of
 * this protocol are exercised end-to-end by the Node loopback test, so the shapes are the contract.
 */

import type { ControlOp, DirectionalKey, TransferRunState } from '@sendbeam/protocol';
import type { SenderReattachment } from './sender-record.js';

/** Session crypto state handed to the worker at start — counters continue, never reset. */
export interface SessionCrypto {
  sendDir: DirectionalKey;
  recvDir: DirectionalKey;
  sendCounter: number;
  recvCounter: number;
}

/**
 * V13-PR08: the LOCAL resume context for an explicit cross-session resume attempt. The user
 * chose the interrupted transfer locally; the peer must prove continuity with the original
 * session via resume-auth-v1 before any durable progress is reused. Only the decoded secret
 * crosses into the worker (the envelope is decoded by the host); it is never printed.
 */
export interface ResumeAttempt {
  /** Stable id of the interrupted transfer being resumed. */
  transferId: string;
  /** Canonical manifest fingerprint of the interrupted transfer. */
  manifestFingerprint: string;
  /** This peer's stable role: offerer (sender) or joiner (receiver). */
  role: 'offerer' | 'joiner';
  /** Decoded 32-byte transfer-scoped resume credential from the local record/journal. */
  resumeSecret: Uint8Array;
}

export interface StartSendMsg extends SessionCrypto {
  kind: 'start-send';
  files: File[];
  /** Reuse a stable transfer id from an interrupted send (worker re-verifies the source). */
  transferId?: string;
  /**
   * V13-PR08: explicit cross-session resume attempt. The worker runs resume-auth-v1 with the
   * peer strictly before the transfer engine starts; only a successful mutual authentication
   * reuses the record's verified progress under a FRESH resumed key epoch.
   */
  resumeAttempt?: ResumeAttempt;
  /**
   * The transient resume root derived by the MAIN THREAD from the original session master
   * (V13-PR07) — never the master itself. The worker uses it to derive the transfer-scoped
   * resume secret for the sender record; it is never persisted, logged, or returned to UI.
   */
  resumeRoot?: Uint8Array;
  /**
   * How this send's source can be reopened after an interruption. Persisted by the
   * worker's `onManifest` hook with the sender record; the handle crosses postMessage
   * via structured clone (Chromium supports serializing FileSystemHandles).
   */
  reattachment?: SenderReattachment;
  blockSize?: number;
  frameSize?: number;
  window?: number;
}
export interface StartRecvMsg extends SessionCrypto {
  kind: 'start-recv';
  destination: ReceiveDestinationSpec;
  /**
   * The transient resume root derived by the MAIN THREAD from the original session master
   * (V13-PR07) — never the master itself. The worker uses it to derive the transfer-scoped
   * resume secret persisted into the receive journal after the authenticated manifest
   * validates; it is never persisted, logged, or returned to UI.
   */
  resumeRoot?: Uint8Array;
  /**
   * V13-PR08: explicit cross-session resume attempt. The worker runs resume-auth-v1 with the
   * peer strictly before the transfer engine starts; only after mutual authentication may
   * the pre-selected interrupted journal's verified progress be advertised.
   */
  resumeAttempt?: ResumeAttempt;
}
export type ReceiveDestinationSpec =
  | { kind: 'auto' }
  | { kind: 'direct-file'; handle: FileSystemFileHandle }
  | { kind: 'direct-directory'; handle: FileSystemDirectoryHandle };
export interface InboundFrameMsg {
  kind: 'inbound-frame';
  frame: ArrayBuffer;
}
export interface CancelMsg {
  kind: 'cancel';
  reason?: string;
}
export interface TransferControlMsg {
  kind: 'control';
  op: ControlOp;
}
export interface TransportChangedMsg {
  kind: 'transport-changed';
}
export type HostToWorker =
  | StartSendMsg
  | StartRecvMsg
  | InboundFrameMsg
  | TransferControlMsg
  | TransportChangedMsg
  | CancelMsg;

export interface OutboundFrameMsg {
  kind: 'outbound-frame';
  frame: ArrayBuffer;
}
export interface FrameConsumedMsg {
  kind: 'frame-consumed';
  bytes: number;
}
/** Worker → host, emitted once the core is wired and ready to accept a start message. */
export interface ReadyMsg {
  kind: 'ready';
}
export interface ManifestMsg {
  kind: 'manifest';
  files: Array<{ name: string; size: number; mime: string }>;
  totalSize: number;
}
export interface ProgressMsg {
  kind: 'progress';
  bytes: number;
}
export interface StateMsg {
  kind: 'state';
  state: TransferRunState;
}
/** Worker → host, once a durable receive journal is prepared: lease + resumable progress. */
export interface DurableInfoMsg {
  kind: 'durable';
  transferId: string;
  /** Lease owner id so the main thread can release the lease (pagehide, discard). */
  ownerId: string;
  resumed: boolean;
  committedBytes: number;
  totalBytes: number;
}
export interface DoneMsg {
  kind: 'done';
  files: Array<{ name: string; size: number; digest: string }>;
  totalSize: number;
  digest: string;
  output?: { kind: 'opfs'; key: string; name: string; mime: string };
}
export interface ErrorMsg {
  kind: 'error';
  reason: string;
  message: string;
}
export type WorkerToHost =
  | ReadyMsg
  | OutboundFrameMsg
  | FrameConsumedMsg
  | ManifestMsg
  | ProgressMsg
  | StateMsg
  | DurableInfoMsg
  | DoneMsg
  | ErrorMsg;

/** The slice of Worker / DedicatedWorkerGlobalScope the core needs, so a test can inject a fake. */
export interface DuplexPort<In, Out> {
  postMessage(msg: Out, transfer?: Transferable[]): void;
  addEventListener(type: 'message', handler: (ev: { data: In }) => void): void;
}
