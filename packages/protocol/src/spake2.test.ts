import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  computeShare,
  finish,
  passwordToScalar,
  randomScalar,
  IDENTITY_OFFERER,
  IDENTITY_JOINER,
} from './spake2.js';
import { bytesToHex, hexToBytes, utf8 } from './bytes.js';

function loadVectors<T>(name: string): T {
  const url = new URL(`../../../docs/test-vectors/${name}`, import.meta.url);
  return JSON.parse(readFileSync(fileURLToPath(url), 'utf8')) as T;
}

interface RfcVector {
  A: string;
  B: string;
  w: string;
  x: string;
  y: string;
  pA: string;
  pB: string;
  K: string;
  TT: string;
  Ke: string;
  Ka: string;
  KcA: string;
  KcB: string;
  confirmA: string;
  confirmB: string;
}
const rfc = loadVectors<{ vectors: RfcVector[] }>('rfc9382-p256.json');

const scalar = (hex: string): bigint => BigInt(`0x${hex}`);

describe('SPAKE2 — RFC 9382 Appendix B known-answer vectors', () => {
  for (const [i, v] of rfc.vectors.entries()) {
    const ids = { offerer: utf8(v.A), joiner: utf8(v.B) };

    it(`vector ${i} (A='${v.A}', B='${v.B}') reproduces both shares`, () => {
      expect(bytesToHex(computeShare('offerer', scalar(v.w), scalar(v.x)))).toBe(v.pA);
      expect(bytesToHex(computeShare('joiner', scalar(v.w), scalar(v.y)))).toBe(v.pB);
    });

    it(`vector ${i} offerer derives the RFC transcript, K, and MACs`, async () => {
      const out = await finish('offerer', scalar(v.w), scalar(v.x), hexToBytes(v.pB), ids);
      expect(bytesToHex(out.K)).toBe(v.K);
      expect(bytesToHex(out.transcript)).toBe(v.TT);
      expect(bytesToHex(out.Ke)).toBe(v.Ke);
      expect(bytesToHex(out.Ka)).toBe(v.Ka);
      expect(bytesToHex(out.KcA)).toBe(v.KcA);
      expect(bytesToHex(out.KcB)).toBe(v.KcB);
      expect(bytesToHex(out.confirmA)).toBe(v.confirmA);
      expect(bytesToHex(out.confirmB)).toBe(v.confirmB);
    });

    it(`vector ${i} joiner derives the identical transcript and K`, async () => {
      const out = await finish('joiner', scalar(v.w), scalar(v.y), hexToBytes(v.pA), ids);
      expect(bytesToHex(out.K)).toBe(v.K);
      expect(bytesToHex(out.transcript)).toBe(v.TT);
      expect(bytesToHex(out.confirmA)).toBe(v.confirmA);
      expect(bytesToHex(out.confirmB)).toBe(v.confirmB);
    });
  }
});

interface SendarcVectors {
  code: string;
  spake2: {
    w: string;
    x: string;
    y: string;
    pA: string;
    pB: string;
    K: string;
    transcript: string;
    Ke: string;
    Ka: string;
    confirmA: string;
    confirmB: string;
  };
}
const sa = loadVectors<SendarcVectors>('sendarc-crypto.json');

describe('SPAKE2 — SendArc deterministic vector', () => {
  it('derives w from the invite code via the SendArc mapping', async () => {
    const w = await passwordToScalar(sa.code);
    expect(bytesToHex(hexToBytes(sa.spake2.w))).toBe(sa.spake2.w); // fixture sanity
    expect(w).toBe(scalar(sa.spake2.w));
  });

  it('reproduces the committed shares, K, transcript, and confirmations', async () => {
    const w = scalar(sa.spake2.w);
    expect(bytesToHex(computeShare('offerer', w, scalar(sa.spake2.x)))).toBe(sa.spake2.pA);
    expect(bytesToHex(computeShare('joiner', w, scalar(sa.spake2.y)))).toBe(sa.spake2.pB);
    const out = await finish('offerer', w, scalar(sa.spake2.x), hexToBytes(sa.spake2.pB));
    expect(bytesToHex(out.K)).toBe(sa.spake2.K);
    expect(bytesToHex(out.transcript)).toBe(sa.spake2.transcript);
    expect(bytesToHex(out.Ke)).toBe(sa.spake2.Ke);
    expect(bytesToHex(out.confirmA)).toBe(sa.spake2.confirmA);
    expect(bytesToHex(out.confirmB)).toBe(sa.spake2.confirmB);
  });

  it('uses the documented SendArc identity strings', () => {
    expect(new TextDecoder().decode(IDENTITY_OFFERER)).toBe('sendarc/1 offerer');
    expect(new TextDecoder().decode(IDENTITY_JOINER)).toBe('sendarc/1 joiner');
  });
});

describe('SPAKE2 — handshake behaviour', () => {
  it('both peers reach the same Ke and agreeing confirmations from the same code', async () => {
    const w = await passwordToScalar('4-brave-otter');
    const x = randomScalar();
    const y = randomScalar();
    const pA = computeShare('offerer', w, x);
    const pB = computeShare('joiner', w, y);
    const a = await finish('offerer', w, x, pB);
    const b = await finish('joiner', w, y, pA);
    expect(bytesToHex(a.Ke)).toBe(bytesToHex(b.Ke));
    expect(bytesToHex(a.transcript)).toBe(bytesToHex(b.transcript));
    // Each side verifies the peer's confirmation MAC.
    expect(bytesToHex(a.confirmB)).toBe(bytesToHex(b.confirmB));
    expect(bytesToHex(b.confirmA)).toBe(bytesToHex(a.confirmA));
  });

  it('a wrong code yields different confirmations (fails closed)', async () => {
    const wRight = await passwordToScalar('4-brave-otter');
    const wWrong = await passwordToScalar('4-brave-otten');
    const x = randomScalar();
    const y = randomScalar();
    const pA = computeShare('offerer', wRight, x);
    const pBWrong = computeShare('joiner', wWrong, y);
    const a = await finish('offerer', wRight, x, pBWrong);
    const b = await finish('joiner', wWrong, y, pA);
    expect(bytesToHex(a.Ke)).not.toBe(bytesToHex(b.Ke));
    expect(bytesToHex(a.confirmB)).not.toBe(bytesToHex(b.confirmB));
  });

  it('two sessions with the same code derive different keys (fresh randomness)', async () => {
    const w = await passwordToScalar('4-brave-otter');
    const derive = async () => {
      const x = randomScalar();
      const y = randomScalar();
      const a = await finish('offerer', w, x, computeShare('joiner', w, y));
      return bytesToHex(a.Ke);
    };
    expect(await derive()).not.toBe(await derive());
  });

  it('a tampered peer share breaks agreement', async () => {
    const w = await passwordToScalar('4-brave-otter');
    const x = randomScalar();
    const y = randomScalar();
    const pA = computeShare('offerer', w, x);
    const pB = computeShare('joiner', w, y);
    const tampered = Uint8Array.from(pB);
    tampered[tampered.length - 1] ^= 0x01;
    // A tampered but still on-curve point is astronomically unlikely; if the edited byte
    // makes an invalid point, finish rejects it. Either way the handshake cannot agree.
    let aKe: string | null = null;
    try {
      aKe = bytesToHex((await finish('offerer', w, x, tampered)).Ke);
    } catch {
      aKe = null;
    }
    const bKe = bytesToHex((await finish('joiner', w, y, pA)).Ke);
    expect(aKe).not.toBe(bKe);
  });

  it('rejects an off-curve peer share', async () => {
    const w = await passwordToScalar('4-brave-otter');
    const x = randomScalar();
    const garbage = new Uint8Array(65);
    garbage[0] = 0x04; // claims uncompressed but coordinates are all zero → not on curve
    await expect(finish('offerer', w, x, garbage)).rejects.toThrow();
  });
});
