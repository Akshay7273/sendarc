/**
 * SendArc key schedule — derives the transfer keys from the SPAKE2 output.
 *
 * RFC 9382 yields `Ke` (a shared secret) and the confirmation MACs. On top of that,
 * SendArc derives a transcript-bound master key and two directional AEAD keys (one per
 * flow direction), each with a 4-byte nonce salt. All derivations use HKDF-SHA256 via
 * native WebCrypto, mirrored byte-for-byte by Go stdlib in `packages/wire`.
 */

import { AEAD_KEY_BYTES, AEAD_SALT_BYTES, HKDF_INFO } from './constants.js';
import { concatBytes, utf8 } from './bytes.js';
import { hkdfSha256 } from './webcrypto.js';

/** An AEAD key plus the 4-byte salt that prefixes its GCM nonces. */
export interface DirectionalKey {
  readonly key: Uint8Array; // 32 bytes (AES-256)
  readonly salt: Uint8Array; // 4 bytes — nonce = salt || counter_u64_be
}

/** Both directional keys derived from one handshake. */
export interface TransferKeys {
  /** Offerer → joiner. */
  readonly o2j: DirectionalKey;
  /** Joiner → offerer. */
  readonly j2o: DirectionalKey;
}

/**
 * Master key, bound to the full handshake transcript so any tampering that survived key
 * confirmation still changes every downstream key: `HKDF(Ke, "sendarc/1 master" || TT)`.
 */
export function deriveMaster(Ke: Uint8Array, transcript: Uint8Array): Promise<Uint8Array> {
  return hkdfSha256(
    Ke,
    new Uint8Array(0),
    concatBytes(utf8(HKDF_INFO.master), transcript),
    AEAD_KEY_BYTES,
  );
}

/** Derive one directional key + nonce salt from the master key. */
async function deriveDirectional(master: Uint8Array, info: string): Promise<DirectionalKey> {
  const out = await hkdfSha256(
    master,
    new Uint8Array(0),
    utf8(info),
    AEAD_KEY_BYTES + AEAD_SALT_BYTES,
  );
  return { key: out.slice(0, AEAD_KEY_BYTES), salt: out.slice(AEAD_KEY_BYTES) };
}

/** Derive both directional transfer keys from the master key. */
export async function deriveTransferKeys(master: Uint8Array): Promise<TransferKeys> {
  const [o2j, j2o] = await Promise.all([
    deriveDirectional(master, HKDF_INFO.dirOffererToJoiner),
    deriveDirectional(master, HKDF_INFO.dirJoinerToOfferer),
  ]);
  return { o2j, j2o };
}
