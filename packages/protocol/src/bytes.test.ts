import { describe, it, expect } from 'vitest';
import {
  bytesToHex,
  hexToBytes,
  utf8,
  concatBytes,
  lengthPrefixLE,
  withLengthPrefix,
  bytesToBase64url,
  base64urlToBytes,
  constantTimeEqual,
} from './bytes.js';

describe('hex', () => {
  it('round-trips arbitrary bytes', () => {
    const b = Uint8Array.from([0x00, 0x0f, 0x10, 0xff, 0xa5]);
    expect(bytesToHex(b)).toBe('000f10ffa5');
    expect(hexToBytes(bytesToHex(b))).toEqual(b);
  });

  it('accepts uppercase hex', () => {
    expect(hexToBytes('DEADBEEF')).toEqual(Uint8Array.from([0xde, 0xad, 0xbe, 0xef]));
  });

  it('rejects odd-length hex', () => {
    expect(() => hexToBytes('abc')).toThrow();
  });

  it('rejects non-hex characters', () => {
    expect(() => hexToBytes('zz')).toThrow();
  });
});

describe('concatBytes', () => {
  it('concatenates into one buffer', () => {
    expect(concatBytes(Uint8Array.of(1, 2), Uint8Array.of(3), Uint8Array.of(4, 5))).toEqual(
      Uint8Array.of(1, 2, 3, 4, 5),
    );
  });

  it('handles the empty case', () => {
    expect(concatBytes()).toEqual(new Uint8Array(0));
  });
});

describe('length prefixing (RFC 9382 transcript encoding)', () => {
  it('encodes an 8-byte little-endian length', () => {
    expect(bytesToHex(lengthPrefixLE(0))).toBe('0000000000000000');
    expect(bytesToHex(lengthPrefixLE(1))).toBe('0100000000000000');
    expect(bytesToHex(lengthPrefixLE(65))).toBe('4100000000000000');
    expect(bytesToHex(lengthPrefixLE(256))).toBe('0001000000000000');
  });

  it('prefixes a value with its length', () => {
    const out = withLengthPrefix(Uint8Array.of(0xaa, 0xbb));
    expect(bytesToHex(out)).toBe('0200000000000000aabb');
  });

  it('rejects a negative length', () => {
    expect(() => lengthPrefixLE(-1)).toThrow();
  });
});

describe('base64url', () => {
  it('round-trips without padding characters', () => {
    const b = utf8('sendarc/1 offerer');
    const encoded = bytesToBase64url(b);
    expect(encoded).not.toContain('=');
    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
    expect(base64urlToBytes(encoded)).toEqual(b);
  });

  it('decodes with or without padding', () => {
    expect(new TextDecoder().decode(base64urlToBytes('aGk'))).toBe('hi');
    expect(new TextDecoder().decode(base64urlToBytes('aGk='))).toBe('hi');
  });
});

describe('constantTimeEqual', () => {
  it('is true for identical contents', () => {
    expect(constantTimeEqual(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 3))).toBe(true);
  });

  it('is false for differing contents of equal length', () => {
    expect(constantTimeEqual(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 4))).toBe(false);
  });

  it('is false for differing lengths', () => {
    expect(constantTimeEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 2, 3))).toBe(false);
  });
});
