/**
 * AES-256-GCM frame codec. Each frame is an 8-byte monotonic counter, a fixed 16-byte header,
 * and the GCM output (ciphertext with appended 16-byte tag). Counter and header are the GCM
 * additional authenticated data, so tampering with either fails decryption.
 *
 * The 12-byte nonce is the direction's 4-byte salt followed by a big-endian u64 frame
 * counter. Counters are per-direction and supplied by the caller (the session tracks
 * them), giving nonce continuity without ever reusing a (key, nonce) pair. Uses native
 * WebCrypto; mirrored by Go `crypto/cipher` in `packages/wire`.
 */

import {
  AEAD_NONCE_BYTES,
  AEAD_TAG_BYTES,
  FRAME_COUNTER_BYTES,
  FRAME_HEADER_BYTES,
} from './constants.js';
import { decodeFrameHeader, encodeFrameHeader } from './frame.js';
import type { DirectionalKey } from './keyschedule.js';
import type { FrameHeader } from './transfer.js';
import { aesGcmOpen, aesGcmSeal } from './webcrypto.js';

/** Header fields the caller supplies; `len` is set from the plaintext by `seal`. */
export type FrameHeaderInput = Omit<FrameHeader, 'len'>;

const U16_MAX = 0xffff;

function nonce(salt: Uint8Array, counter: number): Uint8Array {
  if (!Number.isSafeInteger(counter) || counter < 0) {
    throw new RangeError(`frame counter ${counter} is not a non-negative integer`);
  }
  const out = new Uint8Array(AEAD_NONCE_BYTES);
  out.set(salt, 0);
  new DataView(out.buffer).setBigUint64(salt.length, BigInt(counter), false);
  return out;
}

/**
 * Encrypt `plaintext` into `counter(8) || header(16) || ciphertext || tag(16)`.
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
  const aad = new Uint8Array(FRAME_COUNTER_BYTES + FRAME_HEADER_BYTES);
  new DataView(aad.buffer).setBigUint64(0, BigInt(counter), false);
  aad.set(encodeFrameHeader({ ...header, len: plaintext.length }), FRAME_COUNTER_BYTES);
  const sealed = await aesGcmSeal(dir.key, nonce(dir.salt, counter), aad, plaintext);
  const out = new Uint8Array(aad.length + sealed.length);
  out.set(aad, 0);
  out.set(sealed, aad.length);
  return out;
}

/** A decrypted frame: its parsed header and recovered plaintext. */
export interface OpenedFrame {
  readonly counter: number;
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
  const embedded = readCounter(frame);
  if (embedded !== counter) {
    throw new Error(`frame counter ${embedded} does not match expected ${counter}`);
  }
  return openEmbedded(dir, embedded, frame);
}

/** A frame older than the next accepted counter; callers may safely ignore this replay. */
export class FrameReplayError extends Error {
  constructor(
    readonly counter: number,
    readonly minimum: number,
  ) {
    super(`frame counter ${counter} is below next accepted ${minimum}`);
    this.name = 'FrameReplayError';
  }
}

/**
 * Open a transfer frame carrying its own authenticated counter. Forward gaps are permitted so a
 * reliable transport can be replaced after losing a suffix; already-consumed counters are
 * reported as replays and nonce values are never reset or guessed.
 */
export async function openSequenced(
  dir: DirectionalKey,
  minimumCounter: number,
  frame: Uint8Array,
): Promise<OpenedFrame> {
  const embedded = readCounter(frame);
  if (embedded < minimumCounter) throw new FrameReplayError(embedded, minimumCounter);
  return openEmbedded(dir, embedded, frame);
}

function readCounter(frame: Uint8Array): number {
  if (frame.length < FRAME_COUNTER_BYTES + FRAME_HEADER_BYTES + AEAD_TAG_BYTES) {
    throw new Error(`frame too short: ${frame.length} bytes`);
  }
  const value = new DataView(frame.buffer, frame.byteOffset, FRAME_COUNTER_BYTES).getBigUint64(
    0,
    false,
  );
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('frame counter exceeds JS range');
  return Number(value);
}

async function openEmbedded(
  dir: DirectionalKey,
  counter: number,
  frame: Uint8Array,
): Promise<OpenedFrame> {
  const aadBytes = FRAME_COUNTER_BYTES + FRAME_HEADER_BYTES;
  const aad = frame.slice(0, aadBytes);
  const header = decodeFrameHeader(aad.subarray(FRAME_COUNTER_BYTES));
  const body = frame.slice(aadBytes);
  if (body.length !== header.len + AEAD_TAG_BYTES) {
    throw new Error(`frame len field ${header.len} disagrees with body ${body.length}`);
  }
  const plaintext = await aesGcmOpen(dir.key, nonce(dir.salt, counter), aad, body);
  return { counter, header, plaintext };
}
