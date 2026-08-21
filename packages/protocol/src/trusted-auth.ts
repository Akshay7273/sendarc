/**
 * Trusted-session authentication messages, forward-secret session key derivation,
 * and mutual challenge verification for paired SendBeam devices (V15-PR03).
 *
 * Matches Go `packages/wire/trusted_auth.go` byte-for-byte.
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

export const MSG_TRUSTED_AUTH_INIT = 'trusted_auth_init';
export const MSG_TRUSTED_AUTH_RESPONSE = 'trusted_auth_response';
export const MSG_TRUSTED_AUTH_CONFIRM = 'trusted_auth_confirm';

export const TRUSTED_AUTH_PROTOCOL_VERSION = 'sendbeam/2';

export const DOMAIN_TRUSTED_INIT = 'sendbeam/2 trusted-init:';
export const DOMAIN_TRUSTED_INIT_MAC = 'sendbeam/2 trusted-init-mac:';
export const DOMAIN_TRUSTED_RESP = 'sendbeam/2 trusted-resp:';
export const DOMAIN_TRUSTED_RESP_MAC = 'sendbeam/2 trusted-resp-mac:';
export const DOMAIN_TRUSTED_MASTER = 'sendbeam/2 session-master:';
export const DOMAIN_TRUSTED_INIT_TO_RESP_KEY = 'sendbeam/2 initiator-to-responder key';
export const DOMAIN_TRUSTED_RESP_TO_INIT_KEY = 'sendbeam/2 responder-to-initiator key';
export const DOMAIN_TRUSTED_CONFIRM_INIT = 'sendbeam/2 confirm-init:';
export const DOMAIN_TRUSTED_CONFIRM_RESP = 'sendbeam/2 confirm-resp:';

export const TRUSTED_AUTH_NONCE_SIZE = 32;
export const TRUSTED_AUTH_EPHEMERAL_SIZE = 32;
export const MAX_TRUSTED_TIMESTAMP_SKEW_MS = 5 * 60 * 1000; // 5 minutes

export interface TrustedAuthInit {
  readonly type: typeof MSG_TRUSTED_AUTH_INIT;
  readonly protocol_version: typeof TRUSTED_AUTH_PROTOCOL_VERSION;
  readonly initiator_device_id: string;
  readonly responder_device_id: string;
  readonly pair_credential_ref: string;
  readonly ephemeral_pub: string;
  readonly nonce: string;
  readonly capabilities: string[];
  readonly timestamp: string;
  readonly signature: string;
  readonly auth_tag: string;
}

export interface TrustedAuthResponse {
  readonly type: typeof MSG_TRUSTED_AUTH_RESPONSE;
  readonly protocol_version: typeof TRUSTED_AUTH_PROTOCOL_VERSION;
  readonly status: 'accepted' | 'rejected' | 'revoked';
  readonly responder_device_id: string;
  readonly ephemeral_pub?: string;
  readonly nonce?: string;
  readonly capabilities?: string[];
  readonly signature?: string;
  readonly auth_tag?: string;
}

export interface TrustedAuthConfirm {
  readonly type: typeof MSG_TRUSTED_AUTH_CONFIRM;
  readonly status: 'ready' | 'rejected';
  readonly auth_tag?: string;
}

export type TrustedAuthMessage = TrustedAuthInit | TrustedAuthResponse | TrustedAuthConfirm;

export interface TrustedSessionKeys {
  readonly sessionMaster: Uint8Array;
  readonly initiatorToResponderKey: Uint8Array;
  readonly responderToInitiatorKey: Uint8Array;
  readonly negotiatedCapabilities: string[];
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
 * Deterministic canonical SHA-256 digest of capability strings.
 */
export async function hashCapabilities(caps: readonly string[]): Promise<Uint8Array> {
  const sorted = [...caps].sort();
  const joined = sorted.join(',');
  return sha256(utf8(joined));
}

/**
 * Intersect two capability lists and sort alphabetically.
 */
export function intersectCapabilities(a: readonly string[], b: readonly string[]): string[] {
  const set = new Set(a);
  const result = b.filter((item) => set.has(item));
  result.sort();
  return result;
}

/**
 * Build the binary payload signed by the initiator in TrustedAuthInit.
 */
export async function buildTrustedInitChallenge(
  kPairHash: Uint8Array,
  ephemPub: Uint8Array,
  nonce: Uint8Array,
  initId: string,
  respId: string,
  capsHash: Uint8Array,
  timestamp: string,
): Promise<Uint8Array> {
  return concatBytes(
    utf8(DOMAIN_TRUSTED_INIT),
    kPairHash,
    ephemPub,
    nonce,
    utf8(initId),
    utf8(respId),
    capsHash,
    utf8(timestamp),
  );
}

/**
 * Build the binary payload signed by the responder in TrustedAuthResponse.
 */
export async function buildTrustedRespChallenge(
  kPairHash: Uint8Array,
  ephemPubInit: Uint8Array,
  ephemPubResp: Uint8Array,
  nonceInit: Uint8Array,
  nonceResp: Uint8Array,
  initId: string,
  respId: string,
  capsHash: Uint8Array,
): Promise<Uint8Array> {
  return concatBytes(
    utf8(DOMAIN_TRUSTED_RESP),
    kPairHash,
    ephemPubInit,
    ephemPubResp,
    nonceInit,
    nonceResp,
    utf8(initId),
    utf8(respId),
    capsHash,
  );
}

/**
 * Compute the HMAC-SHA256 authentication tag over a challenge using k_pair.
 */
export async function computeTrustedMACTag(
  kPair: Uint8Array,
  domain: string,
  challenge: Uint8Array,
): Promise<string> {
  const data = concatBytes(utf8(domain), challenge);
  const tag = await hmacSha256(kPair, data);
  return bytesToHex(tag);
}

/**
 * Verify a MAC tag in constant time.
 */
export async function verifyTrustedMACTag(
  kPair: Uint8Array,
  domain: string,
  challenge: Uint8Array,
  tagHex: string,
): Promise<boolean> {
  const expected = await computeTrustedMACTag(kPair, domain, challenge);
  return constantTimeHexEqual(tagHex.toLowerCase(), expected.toLowerCase());
}

/**
 * Derive forward-secret directional session keys from ephemeral material and k_pair.
 */
export async function deriveTrustedSessionKeys(
  kPair: Uint8Array,
  ephemPubInit: Uint8Array,
  ephemPubResp: Uint8Array,
  nonceInit: Uint8Array,
  nonceResp: Uint8Array,
  initId: string,
  respId: string,
  capsInit: readonly string[],
  capsResp: readonly string[],
): Promise<TrustedSessionKeys> {
  if (kPair.length === 0) {
    throw new Error('k_pair required');
  }
  if (
    ephemPubInit.length !== TRUSTED_AUTH_EPHEMERAL_SIZE ||
    ephemPubResp.length !== TRUSTED_AUTH_EPHEMERAL_SIZE
  ) {
    throw new Error('invalid ephemeral public key size');
  }
  if (
    nonceInit.length !== TRUSTED_AUTH_NONCE_SIZE ||
    nonceResp.length !== TRUSTED_AUTH_NONCE_SIZE
  ) {
    throw new Error('invalid nonce size');
  }

  const negotiated = intersectCapabilities(capsInit, capsResp);
  const capsHash = await hashCapabilities(negotiated);

  const ephemMix = concatBytes(ephemPubInit, ephemPubResp, nonceInit, nonceResp);
  const ikm = await hmacSha256(kPair, ephemMix);
  const salt = concatBytes(nonceInit, nonceResp);

  const kPairHash = await sha256(kPair);
  const transcript = await buildTrustedRespChallenge(
    kPairHash,
    ephemPubInit,
    ephemPubResp,
    nonceInit,
    nonceResp,
    initId,
    respId,
    capsHash,
  );

  const infoMaster = concatBytes(utf8(DOMAIN_TRUSTED_MASTER), transcript);
  const sessionMaster = await hkdfSha256(ikm, salt, infoMaster, 32);

  const kI2R = await hkdfSha256(
    sessionMaster,
    new Uint8Array(0),
    utf8(DOMAIN_TRUSTED_INIT_TO_RESP_KEY),
    32,
  );
  const kR2I = await hkdfSha256(
    sessionMaster,
    new Uint8Array(0),
    utf8(DOMAIN_TRUSTED_RESP_TO_INIT_KEY),
    32,
  );

  return {
    sessionMaster,
    initiatorToResponderKey: kI2R,
    responderToInitiatorKey: kR2I,
    negotiatedCapabilities: negotiated,
  };
}

/**
 * Compute the confirmation tag for the session master.
 */
export async function computeTrustedConfirmTag(
  sessionMaster: Uint8Array,
  domain: string,
  deviceId: string,
): Promise<string> {
  const data = concatBytes(utf8(domain), utf8(deviceId));
  const tag = await hmacSha256(sessionMaster, data);
  return bytesToHex(tag);
}

/**
 * Verify the confirmation tag in constant time.
 */
export async function verifyTrustedConfirmTag(
  sessionMaster: Uint8Array,
  domain: string,
  deviceId: string,
  tagHex: string,
): Promise<boolean> {
  const expected = await computeTrustedConfirmTag(sessionMaster, domain, deviceId);
  return constantTimeHexEqual(tagHex.toLowerCase(), expected.toLowerCase());
}

/**
 * Create a signed and MAC-authenticated TrustedAuthInit message.
 */
export async function createTrustedAuthInit(
  id: DeviceIdentity,
  respDeviceId: string,
  credRef: string,
  kPair: Uint8Array,
  caps: string[],
  ephemPub?: Uint8Array,
  nonce?: Uint8Array,
  now?: Date | string,
): Promise<TrustedAuthInit> {
  const ephem =
    ephemPub && ephemPub.length === TRUSTED_AUTH_EPHEMERAL_SIZE
      ? ephemPub
      : randomBytes(TRUSTED_AUTH_EPHEMERAL_SIZE);
  const n =
    nonce && nonce.length === TRUSTED_AUTH_NONCE_SIZE
      ? nonce
      : randomBytes(TRUSTED_AUTH_NONCE_SIZE);
  const tsStr =
    typeof now === 'string' ? now : (now || new Date()).toISOString().replace(/\.\d{3}Z$/, 'Z');

  const capsHash = await hashCapabilities(caps);
  const kPairHash = await sha256(kPair);

  const challenge = await buildTrustedInitChallenge(
    kPairHash,
    ephem,
    n,
    id.deviceId,
    respDeviceId,
    capsHash,
    tsStr,
  );
  const sig = signDeviceMessage(id, challenge);
  const tag = await computeTrustedMACTag(kPair, DOMAIN_TRUSTED_INIT_MAC, challenge);

  return {
    type: MSG_TRUSTED_AUTH_INIT,
    protocol_version: TRUSTED_AUTH_PROTOCOL_VERSION,
    initiator_device_id: id.deviceId,
    responder_device_id: respDeviceId,
    pair_credential_ref: credRef,
    ephemeral_pub: bytesToHex(ephem),
    nonce: bytesToHex(n),
    capabilities: caps,
    timestamp: tsStr,
    signature: bytesToHex(sig),
    auth_tag: tag,
  };
}

/**
 * Validate format, clock skew, Ed25519 signature, and HMAC tag of a TrustedAuthInit.
 */
export async function verifyTrustedAuthInit(
  init: TrustedAuthInit,
  kPair: Uint8Array,
  initPubKey: Uint8Array,
  localDeviceId: string,
  now?: Date | string,
): Promise<{ ephemeralPub: Uint8Array; nonce: Uint8Array }> {
  if (
    !init ||
    init.type !== MSG_TRUSTED_AUTH_INIT ||
    init.protocol_version !== TRUSTED_AUTH_PROTOCOL_VERSION
  ) {
    throw new Error('invalid trusted-session message');
  }
  if (init.responder_device_id !== localDeviceId) {
    throw new Error('trusted-session peer device ID mismatch');
  }
  if (!validateDeviceId(init.initiator_device_id)) {
    throw new Error('invalid device id format');
  }

  const expectedInitId = await deriveDeviceId(initPubKey);
  if (expectedInitId !== init.initiator_device_id) {
    throw new Error('trusted-session peer device ID mismatch');
  }

  const ts = new Date(init.timestamp).getTime();
  if (Number.isNaN(ts)) {
    throw new Error('invalid trusted-session message');
  }
  const currentTime = (typeof now === 'string' ? new Date(now) : now || new Date()).getTime();
  const skew = Math.abs(currentTime - ts);
  if (skew > MAX_TRUSTED_TIMESTAMP_SKEW_MS) {
    throw new Error('trusted-session timestamp outside acceptable skew window');
  }

  const ephemPub = hexToBytes(init.ephemeral_pub);
  if (ephemPub.length !== TRUSTED_AUTH_EPHEMERAL_SIZE) {
    throw new Error('invalid trusted-session message');
  }

  const nonce = hexToBytes(init.nonce);
  if (nonce.length !== TRUSTED_AUTH_NONCE_SIZE) {
    throw new Error('invalid trusted-session message');
  }

  const sigBytes = hexToBytes(init.signature);
  if (sigBytes.length !== 64) {
    throw new Error('trusted-session signature verification failed');
  }

  const capsHash = await hashCapabilities(init.capabilities);
  const kPairHash = await sha256(kPair);
  const challenge = await buildTrustedInitChallenge(
    kPairHash,
    ephemPub,
    nonce,
    init.initiator_device_id,
    init.responder_device_id,
    capsHash,
    init.timestamp,
  );

  const sigValid = verifyDeviceSignature(initPubKey, challenge, sigBytes);
  if (!sigValid) {
    throw new Error('trusted-session signature verification failed');
  }

  const macValid = await verifyTrustedMACTag(
    kPair,
    DOMAIN_TRUSTED_INIT_MAC,
    challenge,
    init.auth_tag,
  );
  if (!macValid) {
    throw new Error('trusted-session MAC tag verification failed');
  }

  return { ephemeralPub: ephemPub, nonce };
}

/**
 * Create a signed and MAC-authenticated TrustedAuthResponse message.
 */
export async function createTrustedAuthResponse(
  id: DeviceIdentity,
  init: TrustedAuthInit,
  kPair: Uint8Array,
  caps: string[],
  ephemPub?: Uint8Array,
  nonce?: Uint8Array,
): Promise<TrustedAuthResponse> {
  const ephem =
    ephemPub && ephemPub.length === TRUSTED_AUTH_EPHEMERAL_SIZE
      ? ephemPub
      : randomBytes(TRUSTED_AUTH_EPHEMERAL_SIZE);
  const n =
    nonce && nonce.length === TRUSTED_AUTH_NONCE_SIZE
      ? nonce
      : randomBytes(TRUSTED_AUTH_NONCE_SIZE);

  const ephemInit = hexToBytes(init.ephemeral_pub);
  const nonceInit = hexToBytes(init.nonce);

  const negotiated = intersectCapabilities(init.capabilities, caps);
  const capsHash = await hashCapabilities(negotiated);
  const kPairHash = await sha256(kPair);

  const challenge = await buildTrustedRespChallenge(
    kPairHash,
    ephemInit,
    ephem,
    nonceInit,
    n,
    init.initiator_device_id,
    id.deviceId,
    capsHash,
  );
  const sig = signDeviceMessage(id, challenge);
  const tag = await computeTrustedMACTag(kPair, DOMAIN_TRUSTED_RESP_MAC, challenge);

  return {
    type: MSG_TRUSTED_AUTH_RESPONSE,
    protocol_version: TRUSTED_AUTH_PROTOCOL_VERSION,
    status: 'accepted',
    responder_device_id: id.deviceId,
    ephemeral_pub: bytesToHex(ephem),
    nonce: bytesToHex(n),
    capabilities: caps,
    signature: bytesToHex(sig),
    auth_tag: tag,
  };
}

/**
 * Validate format, Ed25519 signature, and HMAC tag of a TrustedAuthResponse.
 */
export async function verifyTrustedAuthResponse(
  resp: TrustedAuthResponse,
  init: TrustedAuthInit,
  kPair: Uint8Array,
  respPubKey: Uint8Array,
  localDeviceId: string,
): Promise<{ ephemeralPub: Uint8Array; nonce: Uint8Array }> {
  if (
    !resp ||
    resp.type !== MSG_TRUSTED_AUTH_RESPONSE ||
    resp.protocol_version !== TRUSTED_AUTH_PROTOCOL_VERSION
  ) {
    throw new Error('invalid trusted-session message');
  }
  if (localDeviceId && init.initiator_device_id !== localDeviceId) {
    throw new Error('trusted-session peer device ID mismatch');
  }
  if (resp.status !== 'accepted') {
    if (resp.status === 'revoked') {
      throw new Error('trusted peer device is revoked');
    }
    throw new Error('trusted session was rejected by peer');
  }
  if (resp.responder_device_id !== init.responder_device_id) {
    throw new Error('trusted-session peer device ID mismatch');
  }

  const expectedRespId = await deriveDeviceId(respPubKey);
  if (expectedRespId !== resp.responder_device_id) {
    throw new Error('trusted-session peer device ID mismatch');
  }

  const ephemInit = hexToBytes(init.ephemeral_pub);
  const nonceInit = hexToBytes(init.nonce);

  if (!resp.ephemeral_pub || !resp.nonce || !resp.signature || !resp.auth_tag) {
    throw new Error('invalid trusted-session message');
  }

  const ephemResp = hexToBytes(resp.ephemeral_pub);
  if (ephemResp.length !== TRUSTED_AUTH_EPHEMERAL_SIZE) {
    throw new Error('invalid trusted-session message');
  }

  const nonceResp = hexToBytes(resp.nonce);
  if (nonceResp.length !== TRUSTED_AUTH_NONCE_SIZE) {
    throw new Error('invalid trusted-session message');
  }

  const sigBytes = hexToBytes(resp.signature);
  if (sigBytes.length !== 64) {
    throw new Error('trusted-session signature verification failed');
  }

  const negotiated = intersectCapabilities(init.capabilities, resp.capabilities || []);
  const capsHash = await hashCapabilities(negotiated);
  const kPairHash = await sha256(kPair);
  const challenge = await buildTrustedRespChallenge(
    kPairHash,
    ephemInit,
    ephemResp,
    nonceInit,
    nonceResp,
    init.initiator_device_id,
    resp.responder_device_id,
    capsHash,
  );

  const sigValid = verifyDeviceSignature(respPubKey, challenge, sigBytes);
  if (!sigValid) {
    throw new Error('trusted-session signature verification failed');
  }

  const macValid = await verifyTrustedMACTag(
    kPair,
    DOMAIN_TRUSTED_RESP_MAC,
    challenge,
    resp.auth_tag,
  );
  if (!macValid) {
    throw new Error('trusted-session MAC tag verification failed');
  }

  return { ephemeralPub: ephemResp, nonce: nonceResp };
}

/**
 * Create a TrustedAuthConfirm message.
 */
export async function createTrustedAuthConfirm(
  sessionMaster: Uint8Array,
  domain: string,
  localDeviceId: string,
  ready: boolean,
): Promise<TrustedAuthConfirm> {
  if (!ready) {
    return {
      type: MSG_TRUSTED_AUTH_CONFIRM,
      status: 'rejected',
    };
  }
  const tag = await computeTrustedConfirmTag(sessionMaster, domain, localDeviceId);
  return {
    type: MSG_TRUSTED_AUTH_CONFIRM,
    status: 'ready',
    auth_tag: tag,
  };
}

/**
 * Verify a TrustedAuthConfirm message.
 */
export async function verifyTrustedAuthConfirm(
  confirm: TrustedAuthConfirm,
  sessionMaster: Uint8Array,
  domain: string,
  peerDeviceId: string,
): Promise<void> {
  if (!confirm || confirm.type !== MSG_TRUSTED_AUTH_CONFIRM) {
    throw new Error('invalid trusted-session message');
  }
  if (confirm.status !== 'ready') {
    throw new Error('trusted session was rejected by peer');
  }
  if (
    !confirm.auth_tag ||
    !(await verifyTrustedConfirmTag(sessionMaster, domain, peerDeviceId, confirm.auth_tag))
  ) {
    throw new Error('trusted-session MAC tag verification failed');
  }
}
