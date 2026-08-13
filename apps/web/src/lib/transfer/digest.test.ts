import { describe, it, expect } from 'vitest';
import { sha256, bytesToHex, type DigestState } from '@sendbeam/protocol';
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

  it('saveState restores to exactly the prefix fed so far (V13-PR05)', async () => {
    const make = await createSha256DigestFactory();
    const prefix = new Uint8Array(3000).fill(7); // spans the SHA-256 compression boundary
    const suffix = new Uint8Array(512).fill(9);
    const live = make();
    live.update(prefix);
    const state = (live as unknown as DigestState).saveState();
    expect(state.length).toBeGreaterThan(0);
    // The live digest remains usable after saveState.
    live.update(suffix);
    const oneShot = new Uint8Array([...prefix, ...suffix]);

    const restored = (await createSha256DigestFactory(state))();
    restored.update(suffix);
    const restoredHex = await restored.hexDigest(); // hash-wasm digest() is one-shot
    expect(restoredHex).toBe(await live.hexDigest());
    expect(restoredHex).toBe(await ref(oneShot));
    // A restored digest covering a different prefix differs — only whole-file
    // verification can vouch for the final digest.
    const other = (await createSha256DigestFactory(state))();
    other.update(prefix); // double-fed: same state, extra prefix
    other.update(suffix);
    expect(await other.hexDigest()).not.toBe(await ref(oneShot));
  });

  it('load() rejects foreign state, falling back to a fresh digest (V13-PR05)', async () => {
    const make = await createSha256DigestFactory();
    // A state from a different runtime: the 4-byte wasm prefix is mangled, so load()
    // must throw (never guess) and a fresh digest must still work.
    const bogus = new Uint8Array([1, 2, 3, 4, ...new Uint8Array(112)]);
    const bogusFactory = await createSha256DigestFactory(bogus);
    expect(() => bogusFactory().update(new Uint8Array([1]))).toThrow();
    // Truncated state is rejected too.
    const fresh = make();
    fresh.update(new Uint8Array([5]));
    const state = (fresh as unknown as DigestState).saveState();
    const truncatedFactory = await createSha256DigestFactory(state.subarray(0, 20));
    expect(() => truncatedFactory().update(new Uint8Array([1]))).toThrow();
    // An untouched factory still yields a working digest after all the failed loads.
    expect(await make().hexDigest()).toBe(await ref(new Uint8Array()));
  });
});
