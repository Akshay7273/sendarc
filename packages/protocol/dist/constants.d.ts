/**
 * Protocol-wide constants. Source of truth for values shared by the web client and
 * the Go server. Go mirrors these in apps/server (see docs/protocol.md). Changing a
 * wire value here is a protocol change — bump PROTOCOL_VERSION and negotiate in caps.
 */
/** Protocol version string, embedded in the handshake transcript and caps. */
export declare const PROTOCOL_VERSION = "sendarc/1";
/** Rendezvous / secret sizes (bytes). */
export declare const SID_BYTES = 16;
export declare const SECRET_BYTES = 32;
/** Framing (see plan.md §6.3). Header is fixed-size and used as AES-GCM AAD. */
export declare const FRAME_HEADER_BYTES = 16;
/** Default DataChannel/relay payload size; negotiable up to MAX_FRAME_BYTES via caps. */
export declare const DEFAULT_FRAME_BYTES: number;
export declare const MAX_FRAME_BYTES: number;
/** Logical block size — the unit of ack/retry/resume. */
export declare const DEFAULT_BLOCK_BYTES: number;
/**
 * Receiver memory bound: how many blocks the sender may have in flight ahead of the
 * receiver's confirmation. Bounds receiver RAM regardless of sink speed (plan.md M2/M3).
 */
export declare const DEFAULT_INFLIGHT_BLOCKS = 8;
/** Sender-side DataChannel backpressure watermarks (bytes). */
export declare const BUFFERED_AMOUNT_HIGH: number;
export declare const BUFFERED_AMOUNT_LOW: number;
/** Structural caps implied by the wire header field widths (plan.md §6.3). */
export declare const MAX_FILES_PER_TRANSFER: number;
export declare const MAX_BLOCKS_PER_FILE: number;
/** Session inactivity TTL on the server (ms). */
export declare const SESSION_TTL_MS: number;
/** HKDF info / domain-separation labels. Keep in sync with the Go server. */
export declare const HKDF_INFO: {
    readonly auth: "sendarc/1 auth";
    readonly master: "sendarc/1 master";
    readonly dirOffererToJoiner: "o2j";
    readonly dirJoinerToOfferer: "j2o";
};
//# sourceMappingURL=constants.d.ts.map