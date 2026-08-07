/**
 * Transfer protocol — messages carried as plaintext INSIDE AES-GCM frames, over the
 * DataChannel or the relay (plan.md §6.2). The frame header (§6.3) is the GCM AAD.
 */

/** One frame's binary header fields (plan.md §6.3). `frameOff` is within-block. */
export interface FrameHeader {
  version: number;
  type: FrameType;
  flags: number;
  fileIdx: number; // u16
  blockIdx: number; // u32
  frameOff: number; // u16 — byte offset WITHIN the block (not the file)
  len: number; // u16 — ciphertext payload length
}

/** Frame type tags (the `type` byte in the header). */
export enum FrameType {
  Caps = 1,
  Manifest = 2,
  BlockData = 3,
  BlockHash = 4,
  BlockRecv = 5, // lightweight M2 in-flight-window signal
  Ack = 6,
  Nack = 7,
  Control = 8,
  Complete = 9,
  Done = 10,
  Fail = 11,
}

/** Feature flags negotiated in caps. */
export type Feature = 'folders' | 'resume' | 'relay' | 'archive';

/** Hints about which receiver sink is available (plan.md M4). */
export type SinkHint = 'direct-file' | 'opfs' | 'archive';

/** First encrypted message after the handshake. */
export interface Caps {
  type: FrameType.Caps;
  version: string;
  maxFrame: number;
  blockSize: number;
  features: Feature[];
  sinkHints: SinkHint[];
}

/** One file's metadata within a manifest. */
export interface FileEntry {
  idx: number;
  name: string; // sanitized on receipt (plan.md M4)
  size: number;
  mime: string;
  lastModified: number;
  blockSize: number;
  blocks: number;
  /** Canonical whole-file SHA-256 (hex), matches `sha256sum`. */
  fileDigest: string;
}

export interface Manifest {
  type: FrameType.Manifest;
  files: FileEntry[];
  totalSize: number;
}

/** Sent at block end so the receiver can verify before acking. */
export interface BlockHash {
  type: FrameType.BlockHash;
  fileIdx: number;
  blockIdx: number;
  sha256: string; // hex
}

/** M2 window signal: receiver has taken delivery of a block (pre-ack). */
export interface BlockRecv {
  type: FrameType.BlockRecv;
  fileIdx: number;
  blockIdx: number;
}

/** M3: receiver confirms a block was verified and written to the sink. */
export interface Ack {
  type: FrameType.Ack;
  fileIdx: number;
  blockIdx: number;
}

/** M3: receiver requests retransmission of a missing block (not for integrity fails). */
export interface Nack {
  type: FrameType.Nack;
  fileIdx: number;
  blockIdx: number;
  reason: 'missing' | 'timeout';
}

export type ControlOp = 'pause' | 'resume' | 'cancel';

export interface Control {
  type: FrameType.Control;
  op: ControlOp;
}

/** Sender → receiver: all blocks sent; here is the canonical digest to verify. */
export interface Complete {
  type: FrameType.Complete;
  fileDigest: string; // hex; for multi-file, per-file digests live in the manifest
}

/** Receiver → sender: verification result. */
export interface Done {
  type: FrameType.Done;
}

export interface Fail {
  type: FrameType.Fail;
  reason: 'digest_mismatch' | 'integrity' | 'sink_error' | 'canceled' | 'quota';
}

export type TransferMsg =
  Caps | Manifest | BlockHash | BlockRecv | Ack | Nack | Control | Complete | Done | Fail;
