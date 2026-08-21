/**
 * Transfer protocol — messages carried as plaintext INSIDE AES-GCM frames, over the
 * DataChannel or another binary transport. The frame header is the GCM AAD.
 */

/** One frame's binary header fields. `frameOff` is within-block. */
export interface FrameHeader {
  version: number;
  type: FrameType;
  flags: number;
  fileIdx: number; // u16
  blockIdx: number; // u32
  frameOff: number; // u32 — byte offset WITHIN the block (not the file)
  len: number; // u16 — ciphertext payload length
}

/** Frame type tags (the `type` byte in the header). */
export enum FrameType {
  Caps = 1,
  Manifest = 2,
  BlockData = 3,
  BlockHash = 4,
  BlockRecv = 5, // legacy pre-verification receipt tag; retained for decoder compatibility
  Ack = 6,
  Nack = 7,
  Control = 8,
  Complete = 9,
  Done = 10,
  Fail = 11,
  ResumeState = 12,
  ResumeAuth = 13,
  PairingExchange = 14,
  TrustedAuth = 15,
}

/** Feature flags negotiated in caps. */
export type Feature = 'folders' | 'resume' | 'relay' | 'archive' | 'resume-auth-v1';

/** Hints about which receiver sink is available. */
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
  name: string; // sanitized on receipt
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
  /**
   * Random 128-bit id (hex) minted by the sender so a resumed receiver can prove it is
   * resuming *this* transfer, not a different file set that reused the room. Optional: older
   * senders omit it, and a transfer that is never resumed never needs it.
   */
  transferId?: string;
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

/** Legacy pre-verification receipt. Reliable engines use Ack after verify-and-sink. */
export interface BlockRecv {
  type: FrameType.BlockRecv;
  fileIdx: number;
  blockIdx: number;
}

/** Receiver confirms a block was verified and written to the sink. */
export interface Ack {
  type: FrameType.Ack;
  fileIdx: number;
  blockIdx: number;
}

/** Receiver requests retransmission of a missing block (not for integrity failures). */
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
  reason: 'digest_mismatch' | 'integrity' | 'sink_error' | 'canceled' | 'quota' | 'retry_exhausted';
}

/** One file's resume position within a {@link ResumeState}. */
export interface ResumeFileState {
  idx: number;
  /**
   * Per-file high-water mark: the count of consecutively-committed blocks the receiver already
   * holds (its `nextBlock`). Because commitment is strictly in order, a single integer fully
   * describes what is held — no sparse bitmap on the wire.
   */
  haveBlocks: number;
}

/**
 * Receiver → sender (forwarded), sent once immediately after the manifest is re-confirmed on a
 * fresh session: "I already hold blocks `[0, haveBlocks)` of each file — restart there." The
 * sender validates it against its own manifest (same `transferId`, `haveBlocks ≤ file.blocks`)
 * and streams only the missing blocks; a mismatch fails the transfer closed.
 *
 * `manifestFingerprint` is the optional canonical manifest fingerprint (additive since V13-PR06,
 * identical algorithm to the durable journal's `manifestFingerprint`). Receivers that understand
 * it include it so the sender can prove the claims are for exactly the manifest being streamed
 * before skipping any source block. It is omitted when the receiver predates the binding: an old
 * sender ignores it, and a new sender treats absence as legacy negotiation (the structural
 * validation that always applied still runs; a present-but-wrong fingerprint fails closed).
 */
export interface ResumeState {
  type: FrameType.ResumeState;
  transferId: string;
  manifestFingerprint?: string;
  files: ResumeFileState[];
}

export type TransferMsg =
  | Caps
  | Manifest
  | BlockHash
  | BlockRecv
  | Ack
  | Nack
  | Control
  | Complete
  | Done
  | Fail
  | ResumeState;
