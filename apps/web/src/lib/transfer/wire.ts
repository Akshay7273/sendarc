/**
 * Message protocol between the main thread and the transfer Web Worker. The worker owns crypto,
 * per-block and whole-file hashing, and sink writes; the main thread owns the RTCDataChannel.
 * Frame payloads cross the boundary as Transferable ArrayBuffers (zero-copy). Both directions of
 * this protocol are exercised end-to-end by the Node loopback test, so the shapes are the contract.
 */

import type { DirectionalKey } from '@sendarc/protocol';

/** Session crypto state handed to the worker at start — counters continue from M1, never reset. */
export interface SessionCrypto {
  sendDir: DirectionalKey;
  recvDir: DirectionalKey;
  sendCounter: number;
  recvCounter: number;
}

export interface StartSendMsg extends SessionCrypto {
  kind: 'start-send';
  file: File;
  blockSize?: number;
  frameSize?: number;
  window?: number;
}
export interface StartRecvMsg extends SessionCrypto {
  kind: 'start-recv';
}
export interface InboundFrameMsg {
  kind: 'inbound-frame';
  frame: ArrayBuffer;
}
export interface CancelMsg {
  kind: 'cancel';
  reason?: string;
}
export type HostToWorker = StartSendMsg | StartRecvMsg | InboundFrameMsg | CancelMsg;

export interface OutboundFrameMsg {
  kind: 'outbound-frame';
  frame: ArrayBuffer;
}
/** Worker → host, emitted once the core is wired and ready to accept a start message. */
export interface ReadyMsg {
  kind: 'ready';
}
export interface ManifestMsg {
  kind: 'manifest';
  name: string;
  size: number;
  mime: string;
}
export interface ProgressMsg {
  kind: 'progress';
  bytes: number;
}
export interface DoneMsg {
  kind: 'done';
  name: string;
  size: number;
  digest: string;
}
export interface ErrorMsg {
  kind: 'error';
  reason: string;
  message: string;
}
export type WorkerToHost =
  ReadyMsg | OutboundFrameMsg | ManifestMsg | ProgressMsg | DoneMsg | ErrorMsg;

/** The slice of Worker / DedicatedWorkerGlobalScope the core needs, so a test can inject a fake. */
export interface DuplexPort<In, Out> {
  postMessage(msg: Out, transfer?: Transferable[]): void;
  addEventListener(type: 'message', handler: (ev: { data: In }) => void): void;
}
