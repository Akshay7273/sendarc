/**
 * Small byte helpers shared across the crypto and signaling code. Kept dependency-free
 * and isomorphic (browser + Node) so the wire encoding is identical everywhere. The Go
 * module `packages/wire` mirrors the same encodings (hex, base64url, little-endian u64).
 */

const HEX = '0123456789abcdef';

/** Lowercase hex encoding. */
export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += HEX[b >> 4]! + HEX[b & 0x0f]!;
  return out;
}

/** Decode lowercase/uppercase hex. Throws on odd length or non-hex input. */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error(`hex length ${hex.length} is odd`);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error(`invalid hex at offset ${i * 2}`);
    out[i] = byte;
  }
  return out;
}

/** UTF-8 encode a string. */
export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/** Concatenate byte arrays into one fresh buffer. */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/**
 * Encode a non-negative integer as an 8-byte little-endian length prefix — the
 * `len(...)` encoding used by the RFC 9382 SPAKE2 transcript (Section 3.3).
 */
export function lengthPrefixLE(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0) throw new RangeError(`length ${n} is not a u64`);
  const out = new Uint8Array(8);
  let v = n;
  for (let i = 0; i < 8; i++) {
    out[i] = v & 0xff;
    v = Math.floor(v / 256);
  }
  return out;
}

/** `len(x) || x` with an 8-byte little-endian length, per the SPAKE2 transcript. */
export function withLengthPrefix(x: Uint8Array): Uint8Array {
  return concatBytes(lengthPrefixLE(x.length), x);
}

/** base64url without padding (RFC 4648 §5). */
export function bytesToBase64url(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Decode base64url (padding optional). Throws on invalid input. */
export function base64urlToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Constant-time equality for two byte arrays. Length is not secret; contents are.
 * Used for key-confirmation and AEAD tag comparisons.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
