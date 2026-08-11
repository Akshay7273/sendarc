import { describe, it, expect } from 'vitest';
import { authKeys, type Spake2Output } from '@sendbeam/protocol';
import { SignalAuthenticator } from './authed-signaling.js';

function pairKeys() {
  // KcA/KcB are confirmation keys; fabricate a Spake2Output-shaped value with distinct keys.
  const KcA = new Uint8Array(32).fill(1);
  const KcB = new Uint8Array(32).fill(2);
  const spake2 = { KcA, KcB } as unknown as Spake2Output;
  const offerer = authKeys('offerer', spake2);
  const joiner = authKeys('joiner', spake2);
  return { offerer, joiner };
}

describe('SignalAuthenticator', () => {
  it('signs and verifies an SDP across the pair', async () => {
    const { offerer, joiner } = pairKeys();
    const room = 7;
    const a = new SignalAuthenticator(room, offerer);
    const b = new SignalAuthenticator(room, joiner);
    const msg = await a.signSdp('v=0\r\n');
    expect(await b.verify(msg)).toEqual({ ok: true });
  });

  it('rejects a tampered body', async () => {
    const { offerer, joiner } = pairKeys();
    const a = new SignalAuthenticator(3, offerer);
    const b = new SignalAuthenticator(3, joiner);
    const msg = await a.signSdp('v=0\r\n');
    const bad = { ...msg, sdp: 'v=0\r\nmutated' };
    const res = await b.verify(bad);
    expect(res.ok).toBe(false);
  });

  it('rejects a room mismatch', async () => {
    const { offerer, joiner } = pairKeys();
    const a = new SignalAuthenticator(7, offerer);
    const b = new SignalAuthenticator(8, joiner);
    const msg = await a.signSdp('v=0\r\n');
    const res = await b.verify(msg);
    expect(res.ok).toBe(false);
  });

  it('rejects replayed or non-increasing seq', async () => {
    const { offerer, joiner } = pairKeys();
    const a = new SignalAuthenticator(1, offerer);
    const b = new SignalAuthenticator(1, joiner);
    const first = await a.signSdp('a');
    const second = await a.signIce('cand');
    expect(await b.verify(second)).toEqual({ ok: true });
    // `first` has a lower seq than the already-accepted `second`.
    const res = await b.verify(first);
    expect(res.ok).toBe(false);
  });

  it('uses one monotonic seq across sdp and ice', async () => {
    const { offerer } = pairKeys();
    const a = new SignalAuthenticator(1, offerer);
    const m1 = await a.signSdp('a');
    const m2 = await a.signIce('c');
    const m3 = await a.signSdp('b');
    expect([m1.seq, m2.seq, m3.seq]).toEqual([0, 1, 2]);
  });

  it('rejects a malformed mac without throwing', async () => {
    const { offerer, joiner } = pairKeys();
    const a = new SignalAuthenticator(1, offerer);
    const b = new SignalAuthenticator(1, joiner);
    const msg = await a.signSdp('a');
    const res = await b.verify({ ...msg, mac: '!!!not base64url!!!' });
    expect(res.ok).toBe(false);
  });
});
