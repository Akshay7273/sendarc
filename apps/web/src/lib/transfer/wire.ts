/**
 * Message protocol between the main thread and the transfer Web Worker. The worker owns crypto,
 * per-block and whole-file hashing, and sink writes; the main thread owns the RTCDataChannel.
 * Frame payloads cross the boundary as Transferable ArrayBuffers (zero-copy). Both directions of
 * this protocol are exercised end-to-end by the Node loopback test, so the shapes are the contract.
 */

import type { ControlOp, DirectionalKey, TransferRunState } from '@sendarc/protocol';

/** Session crypto state handed to the worker at start — counters continue, never reset. */
export interface SessionCrypto {
  sendDir: DirectionalKey;
  recvDir: DirectionalKey;
  sendCounter: number;
  recvCounter: number;
}

export interface StartSendMsg extends SessionCrypto {
  kind: 'start-send';
  files: File[];
  blockSize?: number;
  frameSize?: number;
  window?: number;
}
export interface StartRecvMsg extends SessionCrypto {
  kind: 'start-recv';
  destination: ReceiveDestinationSpec;
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
export type HostToWorker =
  StartSendMsg | StartRecvMsg | InboundFrameMsg | TransferControlMsg | CancelMsg;

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
  ReadyMsg | OutboundFrameMsg | ManifestMsg | ProgressMsg | StateMsg | DoneMsg | ErrorMsg;

/** The slice of Worker / DedicatedWorkerGlobalScope the core needs, so a test can inject a fake. */
export interface DuplexPort<In, Out> {
  postMessage(msg: Out, transfer?: Transferable[]): void;
  addEventListener(type: 'message', handler: (ev: { data: In }) => void): void;
}
