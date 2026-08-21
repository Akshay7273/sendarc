/**
 * Device Identity primitives and canonical fingerprint derivations for SendBeam.
 *
 * Implements Ed25519 cryptographic identity keys, deterministic DeviceID derivations,
 * formatted human-verifiable fingerprints, and signature verification. Matches Go
 * `packages/wire/identity.go` byte-for-byte.
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, hexToBytes } from './bytes.js';
import { randomBytes, sha256 } from './webcrypto.js';

export const DEVICE_ID_PREFIX = 'sb-dev-';
export const FINGERPRINT_PREFIX = 'SB1-';
export const DEVICE_KEY_ALGORITHM = 'Ed25519';

const RFC4648_BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export interface DeviceIdentity {
  /** Canonical machine-readable device ID string (`sb-dev-` + 64-character lowercase hex). */
  readonly deviceId: string;
  /** Human-verifiable formatted fingerprint (`SB1-XXXX-XXXX-XXXX-XXXX`). */
  readonly fingerprint: string;
  /** Raw 32-byte Ed25519 public key. */
  readonly publicKey: Uint8Array;
  /** Raw 32-byte Ed25519 private seed (never sent over the wire). */
  readonly privateKey: Uint8Array;
}

/**
 * Format a 10-byte slice into the canonical "SB1-XXXX-XXXX-XXXX-XXXX" fingerprint string.
 */
export function formatFingerprint(raw10Bytes: Uint8Array): string {
  if (raw10Bytes.length < 10) {
    throw new Error('raw10Bytes must be at least 10 bytes');
  }
  let str = '';
  let buffer = 0;
  let bitsLeft = 0;
  for (let i = 0; i < 10; i++) {
    buffer = (buffer << 8) | raw10Bytes[i]!;
    bitsLeft += 8;
    while (bitsLeft >= 5) {
      bitsLeft -= 5;
      const index = (buffer >> bitsLeft) & 0x1f;
      str += RFC4648_BASE32_ALPHABET[index];
    }
  }
  return `${FINGERPRINT_PREFIX}${str.slice(0, 4)}-${str.slice(4, 8)}-${str.slice(8, 12)}-${str.slice(12, 16)}`;
}

/**
 * Derive the canonical machine-readable DeviceID from an Ed25519 public key.
 * SHA-256 hash of the 32-byte public key, hex-encoded with "sb-dev-" prefix.
 */
export async function deriveDeviceId(publicKey: Uint8Array): Promise<string> {
  if (publicKey.length !== 32) {
    throw new Error('invalid public key: expected 32-byte Ed25519 public key');
  }
  const digest = await sha256(publicKey);
  return `${DEVICE_ID_PREFIX}${bytesToHex(digest)}`;
}

/**
 * Derive the human-verifiable fingerprint formatted as "SB1-XXXX-XXXX-XXXX-XXXX".
 */
export async function deriveFingerprint(publicKey: Uint8Array): Promise<string> {
  if (publicKey.length !== 32) {
    throw new Error('invalid public key: expected 32-byte Ed25519 public key');
  }
  const digest = await sha256(publicKey);
  return formatFingerprint(digest.subarray(0, 10));
}

/**
 * Generate a fresh cryptographic device identity using cryptographically secure random bytes.
 */
export async function generateDeviceIdentity(): Promise<DeviceIdentity> {
  const seed = randomBytes(32);
  return createDeviceIdentityFromSeed(seed);
}

/**
 * Create a DeviceIdentity from a 32-byte private seed.
 */
export async function createDeviceIdentityFromSeed(seed: Uint8Array): Promise<DeviceIdentity> {
  if (seed.length !== 32) {
    throw new Error('invalid seed: expected 32-byte private seed');
  }
  const publicKey = ed25519.getPublicKey(seed);
  const deviceId = await deriveDeviceId(publicKey);
  const fingerprint = await deriveFingerprint(publicKey);

  return {
    deviceId,
    fingerprint,
    publicKey,
    privateKey: seed,
  };
}

/**
 * Sign a message using the device's private key.
 */
export function signDeviceMessage(identity: DeviceIdentity, message: Uint8Array): Uint8Array {
  return ed25519.sign(message, identity.privateKey);
}

/**
 * Verify a message signature against an Ed25519 public key.
 */
export function verifyDeviceSignature(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) {
    return false;
  }
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

/**
 * Validate whether a string is a canonically formatted DeviceID.
 */
export function validateDeviceId(deviceId: string): boolean {
  if (!deviceId.startsWith(DEVICE_ID_PREFIX)) {
    return false;
  }
  const hexPart = deviceId.slice(DEVICE_ID_PREFIX.length);
  if (hexPart.length !== 64) {
    return false;
  }
  try {
    hexToBytes(hexPart);
    return true;
  } catch {
    return false;
  }
}
