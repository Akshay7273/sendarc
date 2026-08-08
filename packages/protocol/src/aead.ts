/**
 * AES-256-GCM frame codec (plan.md §6.3). Each frame is a fixed 16-byte header followed
 * by the GCM output (ciphertext with appended 16-byte tag). The encoded header is the
 * GCM additional authenticated data, so any header tampering fails decryption.
 *
 * The 12-byte nonce is the direction's 4-byte salt followed by a big-endian u64 frame
 * counter. Counters are per-direction and supplied by the caller (the session tracks
 * them), giving nonce continuity without ever reusing a (key, nonce) pair. Uses native
 * WebCrypto; mirrored by Go `crypto/cipher` in `packages/wire`.
 */

import { AEAD_NONCE_BYTES, AEAD_TAG_BYTES, FRAME_HEADER_BYTES } from './constants.js';
import { decodeFrameHeader, encodeFrameHeader } from './frame.js';
import type { DirectionalKey } from './keyschedule.js';
import type { FrameHeader } from './transfer.js';
import { aesGcmOpen, aesGcmSeal } from './webcrypto.js';

/** Header fields the caller supplies; `len` is set from the plaintext by `seal`. */
export type FrameHeaderInput = Omit<FrameHeader, 'len'>;

const U16_MAX = 0xffff;

function nonce(salt: Uint8Array, counter: number): Uint8Array {
  if (!Number.isInteger(counter) || counter < 0) {
    throw new RangeError(`frame counter ${counter} is not a non-negative integer`);
  }
  const out = new Uint8Array(AEAD_NONCE_BYTES);
  out.set(salt, 0);
  new DataView(out.buffer).setBigUint64(salt.length, BigInt(counter), false);
  return out;
}

/**
 * Encrypt `plaintext` into a frame: `header(16) || ciphertext || tag(16)`. The header's
 * `len` field is set to the plaintext length and authenticated as GCM AAD.
 */
export async function seal(
  dir: DirectionalKey,
  counter: number,
  header: FrameHeaderInput,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  if (plaintext.length > U16_MAX) {
    throw new RangeError(`frame payload ${plaintext.length} exceeds u16 max ${U16_MAX}`);
  }
  const aad = encodeFrameHeader({ ...header, len: plaintext.length });
  const sealed = await aesGcmSeal(dir.key, nonce(dir.salt, counter), aad, plaintext);
  const out = new Uint8Array(aad.length + sealed.length);
  out.set(aad, 0);
  out.set(sealed, aad.length);
  return out;
}

/** A decrypted frame: its parsed header and recovered plaintext. */
export interface OpenedFrame {
  readonly header: FrameHeader;
  readonly plaintext: Uint8Array;
}

/**
 * Decrypt a frame produced by `seal`. Verifies the GCM tag over the header AAD and the
 * expected nonce; throws if authentication fails, the frame is truncated, or the header
 * `len` disagrees with the ciphertext length.
 */
export async function open(
  dir: DirectionalKey,
  counter: number,
  frame: Uint8Array,
): Promise<OpenedFrame> {
  if (frame.length < FRAME_HEADER_BYTES + AEAD_TAG_BYTES) {
    throw new Error(`frame too short: ${frame.length} bytes`);
  }
  const aad = frame.slice(0, FRAME_HEADER_BYTES);
  const header = decodeFrameHeader(aad);
  const body = frame.slice(FRAME_HEADER_BYTES);
  if (body.length !== header.len + AEAD_TAG_BYTES) {
    throw new Error(`frame len field ${header.len} disagrees with body ${body.length}`);
  }
  const plaintext = await aesGcmOpen(dir.key, nonce(dir.salt, counter), aad, body);
  return { header, plaintext };
}
