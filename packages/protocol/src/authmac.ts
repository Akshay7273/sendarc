/**
 * SDP/ICE authentication. Each `sdp`/`ice` signaling message is
 * authenticated so a malicious server cannot swap in its own SDP to MITM the DataChannel:
 *
 *   mac = HMAC-SHA256(k_auth, utf8(type) || ":" || u32be(room) || ":" || u32be(seq) || ":" || body)
 *
 * `k_auth` is retained SPAKE2 key-confirmation material: each peer signs with its own
 * confirmation key and verifies with the peer's. This is defense-in-depth for the direct
 * path — confidentiality still rests on the AES-GCM frame layer keyed by K.
 */

import { concatBytes, constantTimeEqual, utf8 } from './bytes.js';
import { hmacSha256 } from './webcrypto.js';
import type { Spake2Output } from './spake2.js';
import type { Role } from './signaling.js';

/** The kind of signaling message being authenticated. */
export type SignalMacType = 'sdp' | 'ice';

/** Encode a non-negative integer as 4 big-endian bytes. Throws outside u32 range. */
export function u32be(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) {
    throw new RangeError(`u32 out of range: ${n}`);
  }
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, false);
  return out;
}

/** The exact byte string the MAC is computed over (design §4.2). */
export function signalMacInput(
  type: SignalMacType,
  room: number,
  seq: number,
  body: string,
): Uint8Array {
  const colon = utf8(':');
  return concatBytes(utf8(type), colon, u32be(room), colon, u32be(seq), colon, utf8(body));
}

/** Compute the authentication MAC for a signaling message. */
export function signSignal(
  kAuth: Uint8Array,
  type: SignalMacType,
  room: number,
  seq: number,
  body: string,
): Promise<Uint8Array> {
  return hmacSha256(kAuth, signalMacInput(type, room, seq, body));
}

/** Recompute and compare in constant time. A mismatch means abort the session. */
export async function verifySignal(
  kAuth: Uint8Array,
  type: SignalMacType,
  room: number,
  seq: number,
  body: string,
  mac: Uint8Array,
): Promise<boolean> {
  const expected = await signSignal(kAuth, type, room, seq, body);
  return constantTimeEqual(expected, mac);
}

/**
 * The per-role signing/verifying keys. The offerer (RFC party "A") signs with KcA and
 * verifies the joiner's messages with KcB; the joiner is the mirror.
 */
export function authKeys(
  role: Role,
  spake2: Spake2Output,
): { sign: Uint8Array; verify: Uint8Array } {
  return role === 'offerer'
    ? { sign: spake2.KcA, verify: spake2.KcB }
    : { sign: spake2.KcB, verify: spake2.KcA };
}
