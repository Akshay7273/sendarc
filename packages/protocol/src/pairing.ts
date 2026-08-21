/**
 * Pairing ceremony protocol messages, cryptographic challenges, and pair-specific
 * credential derivations for SendBeam (V15-PR02).
 *
 * Matches Go `packages/wire/pairing.go` byte-for-byte.
 */

import { bytesToHex, concatBytes, hexToBytes, utf8 } from './bytes.js';
import {
  deriveDeviceId,
  signDeviceMessage,
  validateDeviceId,
  verifyDeviceSignature,
  type DeviceIdentity,
} from './identity.js';
import { hkdfSha256, hmacSha256, randomBytes, sha256 } from './webcrypto.js';

export const MSG_PAIRING_REQUEST = 'pairing_request';
export const MSG_PAIRING_RESPONSE = 'pairing_response';
export const MSG_PAIRING_CONFIRM = 'pairing_confirm';

export const DOMAIN_PAIRING_REQUEST = 'sendbeam/1 pairing-request:';
export const DOMAIN_PAIRING_RESPONSE = 'sendbeam/1 pairing-response:';
export const DOMAIN_PAIRING_CONFIRM = 'sendbeam/1 pairing-confirm:';
export const INFO_PAIR_CREDENTIAL = 'sendbeam/1 pair-credential';

export const PAIRING_NONCE_BYTES = 32;

export interface PairingRequest {
  readonly type: typeof MSG_PAIRING_REQUEST;
  readonly protocol_version: string;
  readonly device_id: string;
  readonly public_key: string;
  readonly device_name: string;
  readonly capabilities: string[];
  readonly nonce: string;
  readonly signature: string;
}

export interface PairingResponse {
  readonly type: typeof MSG_PAIRING_RESPONSE;
  readonly protocol_version: string;
  readonly device_id: string;
  readonly public_key: string;
  readonly device_name: string;
  readonly capabilities: string[];
  readonly nonce: string;
  readonly signature: string;
}

export interface PairingConfirm {
  readonly type: typeof MSG_PAIRING_CONFIRM;
  readonly status: 'accepted' | 'rejected';
  readonly auth_tag?: string;
}

export type PairingMessage = PairingRequest | PairingResponse | PairingConfirm;

/**
 * Compare two byte arrays lexicographically.
 */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i]! < b[i]!) return -1;
    if (a[i]! > b[i]!) return 1;
  }
  return a.length - b.length;
}

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
 * Build the domain-separated message challenge for a PairingRequest.
 */
export async function buildPairingRequestChallenge(
  masterKey: Uint8Array,
  reqNonce: Uint8Array,
  deviceId: string,
): Promise<Uint8Array> {
  const masterHash = await sha256(masterKey);
  return concatBytes(utf8(DOMAIN_PAIRING_REQUEST), masterHash, reqNonce, utf8(deviceId));
}

/**
 * Build the domain-separated message challenge for a PairingResponse.
 */
export async function buildPairingResponseChallenge(
  masterKey: Uint8Array,
  reqNonce: Uint8Array,
  respNonce: Uint8Array,
  deviceId: string,
): Promise<Uint8Array> {
  const masterHash = await sha256(masterKey);
  return concatBytes(
    utf8(DOMAIN_PAIRING_RESPONSE),
    masterHash,
    reqNonce,
    respNonce,
    utf8(deviceId),
  );
}

/**
 * Derive the pairwise persistent credential (`kPair`) and its reference ID (`credRef`).
 * Public keys are sorted lexicographically to guarantee deterministic symmetry.
 */
export async function derivePairCredential(
  masterKey: Uint8Array,
  reqNonce: Uint8Array,
  respNonce: Uint8Array,
  pubA: Uint8Array,
  pubB: Uint8Array,
): Promise<{ kPair: Uint8Array; credRef: string }> {
  if (masterKey.length === 0) {
    throw new Error('master key required');
  }
  if (reqNonce.length !== PAIRING_NONCE_BYTES || respNonce.length !== PAIRING_NONCE_BYTES) {
    throw new Error('invalid pairing nonce length');
  }
  if (pubA.length !== 32 || pubB.length !== 32) {
    throw new Error('invalid public key size');
  }

  const salt = concatBytes(reqNonce, respNonce);
  const infoPubs = compareBytes(pubA, pubB) < 0 ? concatBytes(pubA, pubB) : concatBytes(pubB, pubA);
  const info = concatBytes(utf8(INFO_PAIR_CREDENTIAL), infoPubs);

  const kPair = await hkdfSha256(masterKey, salt, info, 32);
  const credHash = await sha256(kPair);
  const credRef = `cred-${bytesToHex(credHash)}`;

  return { kPair, credRef };
}

/**
 * Compute the confirmation HMAC-SHA256 authentication tag for the peer device.
 */
export async function computePairingConfirmTag(
  kPair: Uint8Array,
  peerDeviceId: string,
): Promise<string> {
  const data = concatBytes(utf8(DOMAIN_PAIRING_CONFIRM), utf8(peerDeviceId));
  const tag = await hmacSha256(kPair, data);
  return bytesToHex(tag);
}

/**
 * Verify the confirmation HMAC-SHA256 tag.
 */
export async function verifyPairingConfirmTag(
  kPair: Uint8Array,
  peerDeviceId: string,
  tagHex: string,
): Promise<boolean> {
  const expected = await computePairingConfirmTag(kPair, peerDeviceId);
  return constantTimeHexEqual(tagHex.toLowerCase(), expected.toLowerCase());
}

/**
 * Create a signed PairingRequest message.
 */
export async function createPairingRequest(
  id: DeviceIdentity,
  deviceName: string,
  capabilities: string[],
  masterKey: Uint8Array,
  nonce?: Uint8Array,
): Promise<PairingRequest> {
  const reqNonce =
    nonce && nonce.length === PAIRING_NONCE_BYTES ? nonce : randomBytes(PAIRING_NONCE_BYTES);
  const challenge = await buildPairingRequestChallenge(masterKey, reqNonce, id.deviceId);
  const sig = signDeviceMessage(id, challenge);

  return {
    type: MSG_PAIRING_REQUEST,
    protocol_version: 'sendbeam/1',
    device_id: id.deviceId,
    public_key: bytesToHex(id.publicKey),
    device_name: deviceName,
    capabilities,
    nonce: bytesToHex(reqNonce),
    signature: bytesToHex(sig),
  };
}

/**
 * Verify a PairingRequest message format, DeviceID binding, and Ed25519 signature.
 */
export async function verifyPairingRequest(
  req: PairingRequest,
  masterKey: Uint8Array,
): Promise<{ publicKey: Uint8Array; nonce: Uint8Array }> {
  if (!req || req.type !== MSG_PAIRING_REQUEST) {
    throw new Error('invalid pairing message');
  }
  if (!validateDeviceId(req.device_id)) {
    throw new Error('invalid device id format');
  }

  const pubBytes = hexToBytes(req.public_key);
  if (pubBytes.length !== 32) {
    throw new Error('invalid public key: expected 32-byte Ed25519 public key');
  }

  const expectedId = await deriveDeviceId(pubBytes);
  if (expectedId !== req.device_id) {
    throw new Error('pairing device ID does not match public key');
  }

  const nonceBytes = hexToBytes(req.nonce);
  if (nonceBytes.length !== PAIRING_NONCE_BYTES) {
    throw new Error('invalid pairing nonce length');
  }

  const sigBytes = hexToBytes(req.signature);
  if (sigBytes.length !== 64) {
    throw new Error('pairing signature verification failed');
  }

  const challenge = await buildPairingRequestChallenge(masterKey, nonceBytes, req.device_id);
  const valid = verifyDeviceSignature(pubBytes, challenge, sigBytes);
  if (!valid) {
    throw new Error('pairing signature verification failed');
  }

  return { publicKey: pubBytes, nonce: nonceBytes };
}

/**
 * Create a signed PairingResponse message responding to a verified PairingRequest.
 */
export async function createPairingResponse(
  id: DeviceIdentity,
  deviceName: string,
  capabilities: string[],
  masterKey: Uint8Array,
  reqNonce: Uint8Array,
  respNonce?: Uint8Array,
): Promise<PairingResponse> {
  if (reqNonce.length !== PAIRING_NONCE_BYTES) {
    throw new Error('invalid request nonce length');
  }
  const nonce =
    respNonce && respNonce.length === PAIRING_NONCE_BYTES
      ? respNonce
      : randomBytes(PAIRING_NONCE_BYTES);
  const challenge = await buildPairingResponseChallenge(masterKey, reqNonce, nonce, id.deviceId);
  const sig = signDeviceMessage(id, challenge);

  return {
    type: MSG_PAIRING_RESPONSE,
    protocol_version: 'sendbeam/1',
    device_id: id.deviceId,
    public_key: bytesToHex(id.publicKey),
    device_name: deviceName,
    capabilities,
    nonce: bytesToHex(nonce),
    signature: bytesToHex(sig),
  };
}

/**
 * Verify a PairingResponse message format, DeviceID binding, and Ed25519 signature.
 */
export async function verifyPairingResponse(
  resp: PairingResponse,
  reqNonce: Uint8Array,
  masterKey: Uint8Array,
): Promise<{ publicKey: Uint8Array; nonce: Uint8Array }> {
  if (!resp || resp.type !== MSG_PAIRING_RESPONSE) {
    throw new Error('invalid pairing message');
  }
  if (!validateDeviceId(resp.device_id)) {
    throw new Error('invalid device id format');
  }

  const pubBytes = hexToBytes(resp.public_key);
  if (pubBytes.length !== 32) {
    throw new Error('invalid public key: expected 32-byte Ed25519 public key');
  }

  const expectedId = await deriveDeviceId(pubBytes);
  if (expectedId !== resp.device_id) {
    throw new Error('pairing device ID does not match public key');
  }

  const respNonceBytes = hexToBytes(resp.nonce);
  if (respNonceBytes.length !== PAIRING_NONCE_BYTES) {
    throw new Error('invalid pairing nonce length');
  }

  const sigBytes = hexToBytes(resp.signature);
  if (sigBytes.length !== 64) {
    throw new Error('pairing signature verification failed');
  }

  const challenge = await buildPairingResponseChallenge(
    masterKey,
    reqNonce,
    respNonceBytes,
    resp.device_id,
  );
  const valid = verifyDeviceSignature(pubBytes, challenge, sigBytes);
  if (!valid) {
    throw new Error('pairing signature verification failed');
  }

  return { publicKey: pubBytes, nonce: respNonceBytes };
}

/**
 * Create a PairingConfirm commit message.
 */
export async function createPairingConfirm(
  kPair: Uint8Array,
  peerDeviceId: string,
  accepted: boolean,
): Promise<PairingConfirm> {
  if (!accepted) {
    return {
      type: MSG_PAIRING_CONFIRM,
      status: 'rejected',
    };
  }
  const authTag = await computePairingConfirmTag(kPair, peerDeviceId);
  return {
    type: MSG_PAIRING_CONFIRM,
    status: 'accepted',
    auth_tag: authTag,
  };
}

/**
 * Verify a PairingConfirm commit message.
 */
export async function verifyPairingConfirm(
  confirm: PairingConfirm,
  kPair: Uint8Array,
  peerDeviceId: string,
): Promise<void> {
  if (!confirm || confirm.type !== MSG_PAIRING_CONFIRM) {
    throw new Error('invalid pairing message');
  }
  if (confirm.status !== 'accepted') {
    throw new Error('pairing ceremony was rejected by peer');
  }
  if (
    !confirm.auth_tag ||
    !(await verifyPairingConfirmTag(kPair, peerDeviceId, confirm.auth_tag))
  ) {
    throw new Error('pairing confirmation authentication tag verification failed');
  }
}
