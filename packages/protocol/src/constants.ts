/**
 * Protocol-wide constants. Source of truth for values shared by the web client, the
 * Go server, and the Go CLI. The Go module `packages/wire` mirrors these; a
 * cross-language vector test asserts they stay in sync. Changing a wire value here is
 * a protocol change — bump PROTOCOL_VERSION and negotiate in caps.
 */

/** Protocol version string, embedded in the handshake transcript and caps. */
export const PROTOCOL_VERSION = 'sendarc/1';

/**
 * Invite code (e.g. `4-brave-otter`). The room number is server-allocated and routes
 * the two sockets; the words are generated client-side and never sent to the server.
 * The full normalized string is the SPAKE2 password.
 */
export const DEFAULT_WORD_COUNT = 2; // 2 words × 8 bits = 16 bits; configurable higher
export const WORDLIST_SIZE = 256; // one byte of entropy per word
export const CODE_SEPARATOR = '-';

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

/**
 * AES-256-GCM parameters for the frame AEAD. The 12-byte nonce is the directional
 * 4-byte salt followed by a big-endian u64 counter (see aead.ts / packages/wire/aead).
 */
export const AEAD_KEY_BYTES = 32;
export const AEAD_NONCE_BYTES = 12;
export const AEAD_TAG_BYTES = 16;
export const AEAD_SALT_BYTES = 4;

/**
 * SPAKE2 (RFC 9382, P-256) domain separation. `CONFIRMATION_KEYS_INFO` is fixed by the
 * RFC (§4) and MUST NOT change. The `sendarc/1 …` labels are SendArc's own key schedule
 * layered on top of the RFC's `Ke` output.
 */
export const HKDF_INFO = {
  /** Maps the invite code to the SPAKE2 password scalar w (SendArc-specific). */
  spake2W: `${PROTOCOL_VERSION} spake2 w`,
  /** RFC 9382 §4: KcA || KcB = HKDF(Ka, nil, "ConfirmationKeys", 32). Do not change. */
  confirmationKeys: 'ConfirmationKeys',
  /** SendArc master key from the RFC `Ke` output, bound to the transcript. */
  master: `${PROTOCOL_VERSION} master`,
  /** Directional transfer keys derived from the master key. */
  dirOffererToJoiner: `${PROTOCOL_VERSION} o2j`,
  dirJoinerToOfferer: `${PROTOCOL_VERSION} j2o`,
} as const;

/**
 * Length in bytes of the HKDF output reduced mod n to form the SPAKE2 scalar w. 48 bytes
 * (384 bits) reduced into the 256-bit scalar field leaves negligible modular bias.
 */
export const SPAKE2_W_HKDF_BYTES = 48;
