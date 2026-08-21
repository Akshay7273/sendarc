/**
 * Remote presence handles, opaque rendezvous discovery, and blinded LAN beacon tags (V15-PR04).
 *
 * Matches Go `packages/wire/presence.go` and `packages/wire/lan_beacon.go` byte-for-byte.
 */

import { bytesToHex, concatBytes, utf8 } from './bytes.js';
import { hmacSha256 } from './webcrypto.js';

export const DOMAIN_RENDEZVOUS_HANDLE = 'sendbeam/2 rendezvous-handle:';
export const DOMAIN_PRESENCE_PROOF = 'sendbeam/2 presence-proof:';
export const DOMAIN_LAN_BEACON_TAG = 'sendbeam/2 lan-beacon:';

export const DEFAULT_RENDEZVOUS_EPOCH_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
export const LAN_BEACON_TAG_SIZE = 16;
export const LAN_BEACON_NONCE_SIZE = 16;

/**
 * Constant-time hex string comparison.
 */
function constantTimeHexEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Derive a 32-byte opaque rendezvous handle for a specific epoch index.
 */
export async function deriveRendezvousHandle(
  kPair: Uint8Array,
  epochIndex: number | bigint,
): Promise<string> {
  const epochStr = epochIndex.toString();
  const data = concatBytes(utf8(DOMAIN_RENDEZVOUS_HANDLE), utf8(epochStr));
  const tag = await hmacSha256(kPair, data);
  return bytesToHex(tag);
}

/**
 * Derive the opaque handle for a given timestamp and window.
 */
export async function deriveRendezvousHandleForTime(
  kPair: Uint8Array,
  t?: Date | number,
  windowMs = DEFAULT_RENDEZVOUS_EPOCH_WINDOW_MS,
): Promise<string> {
  const timeMs = t instanceof Date ? t.getTime() : typeof t === 'number' ? t : Date.now();
  const epochIndex = Math.floor(timeMs / windowMs);
  return deriveRendezvousHandle(kPair, epochIndex);
}

/**
 * Derive current, previous, and next epoch handles to tolerate clock drift.
 */
export async function deriveRendezvousHandlesWithSkew(
  kPair: Uint8Array,
  t?: Date | number,
  windowMs = DEFAULT_RENDEZVOUS_EPOCH_WINDOW_MS,
): Promise<string[]> {
  const timeMs = t instanceof Date ? t.getTime() : typeof t === 'number' ? t : Date.now();
  const epochIndex = Math.floor(timeMs / windowMs);
  return Promise.all([
    deriveRendezvousHandle(kPair, epochIndex - 1),
    deriveRendezvousHandle(kPair, epochIndex),
    deriveRendezvousHandle(kPair, epochIndex + 1),
  ]);
}

/**
 * Compute an HMAC proof of possession for registering or polling a handle.
 */
export async function derivePresenceProof(
  kPair: Uint8Array,
  handle: string,
  nonce: Uint8Array,
): Promise<string> {
  const data = concatBytes(utf8(DOMAIN_PRESENCE_PROOF), utf8(handle), nonce);
  const tag = await hmacSha256(kPair, data);
  return bytesToHex(tag);
}

/**
 * Verify an HMAC proof of possession in constant time.
 */
export async function verifyPresenceProof(
  kPair: Uint8Array,
  handle: string,
  nonce: Uint8Array,
  proofHex: string,
): Promise<boolean> {
  const expected = await derivePresenceProof(kPair, handle, nonce);
  return constantTimeHexEqual(proofHex.toLowerCase(), expected.toLowerCase());
}

/**
 * Derive a 16-byte truncated blinded tag for a paired device in a LAN beacon.
 */
export async function deriveLanBeaconTag(
  kPair: Uint8Array,
  nonce: Uint8Array,
  epochIndex: number | bigint,
): Promise<Uint8Array> {
  const epochStr = epochIndex.toString();
  const data = concatBytes(utf8(DOMAIN_LAN_BEACON_TAG), nonce, utf8(epochStr));
  const full = await hmacSha256(kPair, data);
  return full.slice(0, LAN_BEACON_TAG_SIZE);
}

/**
 * Compute candidate LAN beacon tags for [epoch-1, epoch, epoch+1].
 */
export async function deriveLanBeaconTagsForDevice(
  kPair: Uint8Array,
  nonce: Uint8Array,
  t?: Date | number,
  windowMs = DEFAULT_RENDEZVOUS_EPOCH_WINDOW_MS,
): Promise<Uint8Array[]> {
  const timeMs = t instanceof Date ? t.getTime() : typeof t === 'number' ? t : Date.now();
  const epochIndex = Math.floor(timeMs / windowMs);
  return Promise.all([
    deriveLanBeaconTag(kPair, nonce, epochIndex - 1),
    deriveLanBeaconTag(kPair, nonce, epochIndex),
    deriveLanBeaconTag(kPair, nonce, epochIndex + 1),
  ]);
}

/**
 * Match a candidate beacon against known paired device secrets.
 */
export async function matchLanBeaconTag(
  kPair: Uint8Array,
  beaconNonce: Uint8Array,
  advertisedTag: Uint8Array,
  beaconTimestampMs: number,
  nowMs = Date.now(),
  windowMs = DEFAULT_RENDEZVOUS_EPOCH_WINDOW_MS,
): Promise<boolean> {
  const skew = Math.abs(nowMs - beaconTimestampMs);
  if (skew > 2 * windowMs) {
    return false;
  }
  const candidates = await deriveLanBeaconTagsForDevice(
    kPair,
    beaconNonce,
    beaconTimestampMs,
    windowMs,
  );
  const advHex = bytesToHex(advertisedTag);
  for (const cand of candidates) {
    if (constantTimeHexEqual(bytesToHex(cand), advHex)) {
      return true;
    }
  }
  return false;
}
