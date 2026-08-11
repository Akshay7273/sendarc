/**
 * SPAKE2 over NIST P-256 (RFC 9382), the ciphersuite SPAKE2-P256-SHA256-HKDF-HMAC.
 *
 * SendBeam uses SPAKE2 to turn a short invite code into a mutually authenticated key
 * without revealing the code to the blind server. Only the elliptic-curve point
 * arithmetic uses `@noble/curves`; the hash, KDF and MAC use native WebCrypto (mirrored
 * by Go stdlib in `packages/wire`), so the two implementations stay byte-identical —
 * verified against the RFC 9382 Appendix B vectors.
 *
 * Role mapping: the SendBeam offerer plays RFC party "A" (seed point M); the joiner
 * plays party "B" (seed point N).
 */

import { p256 } from '@noble/curves/nist.js';
import type { Role } from './signaling.js';
import { HKDF_INFO, PROTOCOL_VERSION, SPAKE2_W_HKDF_BYTES } from './constants.js';
import { concatBytes, utf8, withLengthPrefix } from './bytes.js';
import { hkdfSha256, hmacSha256, randomBytes, sha256 } from './webcrypto.js';

type Point = ReturnType<typeof p256.Point.fromHex>;

const Point = p256.Point;
/** P-256 group order n (prime; cofactor 1, so every point has order n). */
const ORDER = Point.Fn.ORDER;

/** RFC 9382 §4 fixed seed points for P-256, given as compressed SEC1. */
const M = Point.fromHex('02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f');
const N = Point.fromHex('03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49');

/** The RFC transcript identity strings SendBeam binds into every handshake. */
export const IDENTITY_OFFERER = utf8(`${PROTOCOL_VERSION} offerer`);
export const IDENTITY_JOINER = utf8(`${PROTOCOL_VERSION} joiner`);

/** The seed point a role adds to its share (offerer→M, joiner→N). */
function seedFor(role: Role): Point {
  return role === 'offerer' ? M : N;
}

/** The peer's seed point (what this role subtracts to recover the shared point). */
function peerSeedFor(role: Role): Point {
  return role === 'offerer' ? N : M;
}

/**
 * A uniformly random scalar in [1, n-1], suitable as the ephemeral SPAKE2 secret
 * (x for the offerer, y for the joiner). Rejection-samples raw randomness mod n.
 */
export function randomScalar(): bigint {
  for (;;) {
    const bytes = randomBytes(48);
    let v = 0n;
    for (const b of bytes) v = (v << 8n) | BigInt(b);
    v %= ORDER;
    if (v !== 0n) return v;
  }
}

/**
 * Map a normalized invite code to the SPAKE2 password scalar w. SendBeam-specific
 * (RFC 9382 leaves the password mapping to the application): w is derived by HKDF over
 * the UTF-8 code, then reduced mod n. 48 bytes before reduction leaves negligible bias.
 */
export async function passwordToScalar(normalizedCode: string): Promise<bigint> {
  const bits = await hkdfSha256(
    utf8(normalizedCode),
    new Uint8Array(0),
    utf8(HKDF_INFO.spake2W),
    SPAKE2_W_HKDF_BYTES,
  );
  let v = 0n;
  for (const b of bits) v = (v << 8n) | BigInt(b);
  return v % ORDER;
}

/**
 * Compute this role's SPAKE2 share element: `w·seed + secret·G`, uncompressed SEC1.
 * Offerer → `pA = w·M + x·G`; joiner → `pB = w·N + y·G`.
 */
export function computeShare(role: Role, w: bigint, secret: bigint): Uint8Array {
  const share = seedFor(role).multiply(mod(w)).add(Point.BASE.multiply(secret));
  return share.toBytes(false);
}

/** Full result of finishing the SPAKE2 exchange (all values as raw bytes). */
export interface Spake2Output {
  /** The shared group element K (uncompressed SEC1). Never used directly as a key. */
  readonly K: Uint8Array;
  /** RFC transcript TT — the input to the hash and both confirmation MACs. */
  readonly transcript: Uint8Array;
  /** Shared secret Ke = Hash(TT)[0:16] — the input to SendBeam's key schedule. */
  readonly Ke: Uint8Array;
  /** Confirmation-key material Ka = Hash(TT)[16:32]. */
  readonly Ka: Uint8Array;
  /** MAC key for the offerer's confirmation (RFC "A"). */
  readonly KcA: Uint8Array;
  /** MAC key for the joiner's confirmation (RFC "B"). */
  readonly KcB: Uint8Array;
  /** Offerer's confirmation MAC cA = HMAC(KcA, TT). */
  readonly confirmA: Uint8Array;
  /** Joiner's confirmation MAC cB = HMAC(KcB, TT). */
  readonly confirmB: Uint8Array;
}

/**
 * Finish the exchange from this role's secret and the peer's share element. Recovers
 * the shared point K, assembles the RFC transcript, and derives Ke/Ka and both
 * confirmation MACs. `w` must be reduced-safe; identities default to SendBeam's.
 */
export async function finish(
  role: Role,
  w: bigint,
  secret: bigint,
  peerShare: Uint8Array,
  identities: { offerer: Uint8Array; joiner: Uint8Array } = {
    offerer: IDENTITY_OFFERER,
    joiner: IDENTITY_JOINER,
  },
): Promise<Spake2Output> {
  const wR = mod(w);
  const peer = Point.fromBytes(peerShare);
  peer.assertValidity();

  // Recover K = secret·(peerShare − w·peerSeed). Negate via the (n−w) scalar since
  // P-256 is prime-order: −w·P ≡ ((n−w) mod n)·P.
  const negWpeerSeed = peerSeedFor(role).multiply(mod(ORDER - wR));
  const K = peer.add(negWpeerSeed).multiply(secret);
  const Kbytes = K.toBytes(false);

  const ownShare = computeShare(role, wR, secret);
  const pA = role === 'offerer' ? ownShare : peerShare;
  const pB = role === 'offerer' ? peerShare : ownShare;

  const transcript = concatBytes(
    withLengthPrefix(identities.offerer),
    withLengthPrefix(identities.joiner),
    withLengthPrefix(pA),
    withLengthPrefix(pB),
    withLengthPrefix(Kbytes),
    withLengthPrefix(scalarToBytes(wR)),
  );

  const hash = await sha256(transcript);
  const Ke = hash.slice(0, 16);
  const Ka = hash.slice(16, 32);

  // KcA || KcB = HKDF(Ka, nil, "ConfirmationKeys", 32) — RFC 9382 §4.
  const kc = await hkdfSha256(Ka, new Uint8Array(0), utf8(HKDF_INFO.confirmationKeys), 32);
  const KcA = kc.slice(0, 16);
  const KcB = kc.slice(16, 32);

  return {
    K: Kbytes,
    transcript,
    Ke,
    Ka,
    KcA,
    KcB,
    confirmA: await hmacSha256(KcA, transcript),
    confirmB: await hmacSha256(KcB, transcript),
  };
}

/** Encode a scalar as a big-endian number padded to the 32-byte field length (RFC §3.3). */
function scalarToBytes(w: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = w;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** Reduce a scalar into [0, n). */
function mod(v: bigint): bigint {
  const r = v % ORDER;
  return r < 0n ? r + ORDER : r;
}
