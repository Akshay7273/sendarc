/**
 * Protocol-wide constants. Source of truth for values shared by the web client and
 * the Go server. Go mirrors these in apps/server (see docs/protocol.md). Changing a
 * wire value here is a protocol change — bump PROTOCOL_VERSION and negotiate in caps.
 */

/** Protocol version string, embedded in the handshake transcript and caps. */
export const PROTOCOL_VERSION = 'sendarc/1';

/** Rendezvous / secret sizes (bytes). */
export const SID_BYTES = 16; // 128-bit routing token the server sees
export const SECRET_BYTES = 32; // 256-bit invite secret S — never sent to the server

/** Framing (see plan.md §6.3). Header is fixed-size and used as AES-GCM AAD. */
export const FRAME_HEADER_BYTES = 16;

/** Default DataChannel/relay payload size; negotiable up to MAX_FRAME_BYTES via caps. */
export const DEFAULT_FRAME_BYTES = 16 * 1024;
export const MAX_FRAME_BYTES = 64 * 1024;

/** Logical block size — the unit of ack/retry/resume. */
export const DEFAULT_BLOCK_BYTES = 1024 * 1024;

/**
 * Receiver memory bound: how many blocks the sender may have in flight ahead of the
 * receiver's confirmation. Bounds receiver RAM regardless of sink speed (plan.md M2/M3).
 */
export const DEFAULT_INFLIGHT_BLOCKS = 8;

/** Sender-side DataChannel backpressure watermarks (bytes). */
export const BUFFERED_AMOUNT_HIGH = 8 * 1024 * 1024;
export const BUFFERED_AMOUNT_LOW = 1 * 1024 * 1024;

/** Structural caps implied by the wire header field widths (plan.md §6.3). */
export const MAX_FILES_PER_TRANSFER = 0xffff + 1; // fileIdx is u16
export const MAX_BLOCKS_PER_FILE = 0xffffffff + 1; // blockIdx is u32

/** Session inactivity TTL on the server (ms). */
export const SESSION_TTL_MS = 10 * 60 * 1000;

/** HKDF info / domain-separation labels. Keep in sync with the Go server. */
export const HKDF_INFO = {
  auth: `${PROTOCOL_VERSION} auth`,
  master: `${PROTOCOL_VERSION} master`,
  dirOffererToJoiner: 'o2j',
  dirJoinerToOfferer: 'j2o',
} as const;
