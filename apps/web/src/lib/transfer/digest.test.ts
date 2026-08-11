import { describe, it, expect } from 'vitest';
import { sha256, bytesToHex } from '@sendbeam/protocol';
import { createSha256DigestFactory } from './digest.js';

/** Reference digest via WebCrypto (available in node 22 and browsers) — an independent impl. */
async function ref(bytes: Uint8Array): Promise<string> {
  return bytesToHex(await sha256(bytes));
}

describe('createSha256DigestFactory', () => {
  it('matches sha256sum for a multi-chunk stream', async () => {
    const make = await createSha256DigestFactory();
    const d = make();
    const a = new Uint8Array(1000).fill(1);
    const b = new Uint8Array(1500).fill(2);
    d.update(a);
    d.update(b);
    const whole = new Uint8Array([...a, ...b]);
    expect(await d.hexDigest()).toBe(await ref(whole));
  });

  it('produces independent, repeatable digests from one factory', async () => {
    const make = await createSha256DigestFactory();
    const d1 = make();
    d1.update(new Uint8Array([1, 2, 3]));
    const h1 = await d1.hexDigest();
    const d2 = make();
    d2.update(new Uint8Array([1, 2, 3]));
    const h2 = await d2.hexDigest();
    expect(h1).toBe(h2);
    expect(h1).toBe(await ref(new Uint8Array([1, 2, 3])));
  });

  it('digests the empty input', async () => {
    const make = await createSha256DigestFactory();
    expect(await make().hexDigest()).toBe(await ref(new Uint8Array()));
  });
});
