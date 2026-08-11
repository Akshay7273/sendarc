/**
 * Thin typed wrappers over the native WebCrypto primitives SendBeam relies on. Confining
 * them here keeps the one-line buffer normalization (WebCrypto's typings want an
 * ArrayBuffer-backed view) out of the crypto logic, and gives the Go module `packages/
 * wire` a single list of primitives to match: SHA-256, HKDF-SHA256, HMAC-SHA256, and
 * AES-256-GCM. None of these leave WebCrypto — only SPAKE2's point math does.
 */

/**
 * Normalize any Uint8Array to a fresh ArrayBuffer-backed view, satisfying WebCrypto's
 * `BufferSource` typing regardless of whether the input was sliced or shared-backed. The
 * copy is negligible at handshake / single-frame scale.
 */
function src(u: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(u.length);
  out.set(u);
  return out;
}

/** Cryptographically strong random bytes. */
export function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

/** SHA-256 digest. */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', src(data)));
}

/** HKDF-SHA256 (extract-and-expand). A zero-length salt means the RFC 5869 "nil" salt. */
export async function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  lengthBytes: number,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', src(ikm), 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: src(salt), info: src(info) },
    key,
    lengthBytes * 8,
  );
  return new Uint8Array(bits);
}

/** HMAC-SHA256. */
export async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey(
    'raw',
    src(key),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, src(data)));
}

/** AES-256-GCM encrypt with a 128-bit tag; returns ciphertext with the tag appended. */
export async function aesGcmSeal(
  key: Uint8Array,
  iv: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', src(key), { name: 'AES-GCM' }, false, ['encrypt']);
  return new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: src(iv), additionalData: src(aad), tagLength: 128 },
      k,
      src(plaintext),
    ),
  );
}

/** AES-256-GCM decrypt; throws if the tag does not verify. */
export async function aesGcmOpen(
  key: Uint8Array,
  iv: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', src(key), { name: 'AES-GCM' }, false, ['decrypt']);
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: src(iv), additionalData: src(aad), tagLength: 128 },
      k,
      src(ciphertext),
    ),
  );
}
