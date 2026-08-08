import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { deriveMaster, deriveTransferKeys } from './keyschedule.js';
import { seal, open, type FrameHeaderInput } from './aead.js';
import { FrameType } from './transfer.js';
import { bytesToHex, hexToBytes, utf8 } from './bytes.js';

function loadVectors<T>(name: string): T {
  const url = new URL(`../../../test-vectors/${name}`, import.meta.url);
  return JSON.parse(readFileSync(fileURLToPath(url), 'utf8')) as T;
}

interface SendarcVectors {
  spake2: { Ke: string; transcript: string };
  keyschedule: {
    master: string;
    o2jKey: string;
    o2jSalt: string;
    j2oKey: string;
    j2oSalt: string;
  };
  aead: {
    direction: 'o2j' | 'j2o';
    counter: number;
    headerHex: string;
    plaintextUtf8: string;
    frameHex: string;
  };
}
const sa = loadVectors<SendarcVectors>('sendarc-crypto.json');

describe('key schedule — SendArc deterministic vector', () => {
  it('derives the transcript-bound master key from Ke', async () => {
    const master = await deriveMaster(hexToBytes(sa.spake2.Ke), hexToBytes(sa.spake2.transcript));
    expect(bytesToHex(master)).toBe(sa.keyschedule.master);
  });

  it('derives both directional keys and nonce salts from the master key', async () => {
    const { o2j, j2o } = await deriveTransferKeys(hexToBytes(sa.keyschedule.master));
    expect(bytesToHex(o2j.key)).toBe(sa.keyschedule.o2jKey);
    expect(bytesToHex(o2j.salt)).toBe(sa.keyschedule.o2jSalt);
    expect(bytesToHex(j2o.key)).toBe(sa.keyschedule.j2oKey);
    expect(bytesToHex(j2o.salt)).toBe(sa.keyschedule.j2oSalt);
  });

  it('gives the two directions distinct keys and salts', async () => {
    const { o2j, j2o } = await deriveTransferKeys(hexToBytes(sa.keyschedule.master));
    expect(bytesToHex(o2j.key)).not.toBe(bytesToHex(j2o.key));
    expect(bytesToHex(o2j.salt)).not.toBe(bytesToHex(j2o.salt));
  });
});

// The 16-byte header the vector fixture commits to, decoded into caller-supplied fields.
const CAPS_HEADER: FrameHeaderInput = {
  version: 1,
  type: FrameType.Caps,
  flags: 0,
  fileIdx: 0,
  blockIdx: 0,
  frameOff: 0,
};

describe('AEAD frame codec — SendArc deterministic vector', () => {
  it('seals the caps payload to the committed frame bytes', async () => {
    const { o2j } = await deriveTransferKeys(hexToBytes(sa.keyschedule.master));
    const frame = await seal(o2j, sa.aead.counter, CAPS_HEADER, utf8(sa.aead.plaintextUtf8));
    expect(bytesToHex(frame.slice(0, 16))).toBe(sa.aead.headerHex);
    expect(bytesToHex(frame)).toBe(sa.aead.frameHex);
  });

  it('opens the committed frame back to header and plaintext', async () => {
    const { o2j } = await deriveTransferKeys(hexToBytes(sa.keyschedule.master));
    const opened = await open(o2j, sa.aead.counter, hexToBytes(sa.aead.frameHex));
    expect(opened.header.type).toBe(FrameType.Caps);
    expect(opened.header.len).toBe(utf8(sa.aead.plaintextUtf8).length);
    expect(new TextDecoder().decode(opened.plaintext)).toBe(sa.aead.plaintextUtf8);
  });
});

describe('AEAD frame codec — round-trip and tamper detection', () => {
  it('round-trips an arbitrary payload', async () => {
    const { o2j } = await deriveTransferKeys(hexToBytes(sa.keyschedule.master));
    const payload = utf8('the quick brown fox jumps over the lazy dog');
    const frame = await seal(o2j, 7, CAPS_HEADER, payload);
    const opened = await open(o2j, 7, frame);
    expect(new TextDecoder().decode(opened.plaintext)).toBe(
      'the quick brown fox jumps over the lazy dog',
    );
  });

  it('rejects a frame opened under the wrong counter (nonce mismatch)', async () => {
    const { o2j } = await deriveTransferKeys(hexToBytes(sa.keyschedule.master));
    const frame = await seal(o2j, 1, CAPS_HEADER, utf8('payload'));
    await expect(open(o2j, 2, frame)).rejects.toThrow();
  });

  it('rejects a frame opened under the other direction key', async () => {
    const { o2j, j2o } = await deriveTransferKeys(hexToBytes(sa.keyschedule.master));
    const frame = await seal(o2j, 0, CAPS_HEADER, utf8('payload'));
    await expect(open(j2o, 0, frame)).rejects.toThrow();
  });

  it('rejects a frame with a tampered ciphertext byte', async () => {
    const { o2j } = await deriveTransferKeys(hexToBytes(sa.keyschedule.master));
    const frame = await seal(o2j, 0, CAPS_HEADER, utf8('payload'));
    frame[frame.length - 1] ^= 0x01; // flip a tag bit
    await expect(open(o2j, 0, frame)).rejects.toThrow();
  });

  it('rejects a frame with a tampered header (AAD) byte', async () => {
    const { o2j } = await deriveTransferKeys(hexToBytes(sa.keyschedule.master));
    const frame = await seal(o2j, 0, CAPS_HEADER, utf8('payload'));
    frame[1] ^= 0x01; // flip the type byte inside the authenticated header
    await expect(open(o2j, 0, frame)).rejects.toThrow();
  });

  it('rejects a truncated frame', async () => {
    const { o2j } = await deriveTransferKeys(hexToBytes(sa.keyschedule.master));
    const frame = await seal(o2j, 0, CAPS_HEADER, utf8('payload'));
    await expect(open(o2j, 0, frame.slice(0, 20))).rejects.toThrow();
  });
});
