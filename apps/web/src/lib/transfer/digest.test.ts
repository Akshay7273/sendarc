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

    const restored = make.restore(state);
    restored.update(suffix);
    const restoredHex = await restored.hexDigest(); // hash-wasm digest() is one-shot
    expect(restoredHex).toBe(await live.hexDigest());
    expect(restoredHex).toBe(await ref(oneShot));
    // A restored digest covering a different prefix differs — only whole-file
    // verification can vouch for the final digest.
    const other = make.restore(state);
    other.update(prefix); // double-fed: same state, extra prefix
    other.update(suffix);
    expect(await other.hexDigest()).not.toBe(await ref(oneShot));
  });

  it('load() rejects foreign state, falling back to a fresh digest (V13-PR05)', async () => {
    const make = await createSha256DigestFactory();
    // A state from a different runtime: the 4-byte wasm prefix is mangled, so load()
    // must throw (never guess) and a fresh digest must still work.
    const bogus = new Uint8Array([1, 2, 3, 4, ...new Uint8Array(112)]);
    expect(() => make.restore(bogus).update(new Uint8Array([1]))).toThrow();
    // Truncated state is rejected too.
    const fresh = make();
    fresh.update(new Uint8Array([5]));
    const state = (fresh as unknown as DigestState).saveState();
    expect(() => make.restore(state.subarray(0, 20)).update(new Uint8Array([1]))).toThrow();
    // An untouched factory still yields a working digest after all the failed loads.
    expect(await make().hexDigest()).toBe(await ref(new Uint8Array()));
  });

  it('keeps simultaneously-live digests isolated over one scratch hasher (V13-PR05)', async () => {
    const make = await createSha256DigestFactory();
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([4, 5, 6, 7]);
    const d1 = make();
    const d2 = make();
    d1.update(a);
    d2.update(b);
    // Interleaved updates must not alias: each digest covers exactly its own bytes.
    expect(await d1.hexDigest()).toBe(await ref(a));
    expect(await d2.hexDigest()).toBe(await ref(b));
    // Digesting d1 deinitializes the shared scratch hasher; d2 must still finish.
    expect(await d1.hexDigest()).toBe(await ref(a));
    expect(await d2.hexDigest()).toBe(await ref(b));
    // saveState of one digest must not alter the other.
    const s1 = (d1 as unknown as DigestState).saveState();
    expect(await d2.hexDigest()).toBe(await ref(b));
    const restored = make.restore(s1);
    expect(await restored.hexDigest()).toBe(await ref(a));
    // Interleaving a restored digest with a live one stays independent.
    restored.update(new Uint8Array([8]));
    d2.update(new Uint8Array([9]));
    expect(await restored.hexDigest()).toBe(await ref(new Uint8Array([1, 2, 3, 8])));
    expect(await d2.hexDigest()).toBe(await ref(new Uint8Array([4, 5, 6, 7, 9])));
  });
});
