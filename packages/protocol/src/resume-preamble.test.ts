/**
 * Resume preamble (V13-PR08) tests — deterministic, no sleeps. These pin the TS twin of
 * `packages/wire/resume_preamble.go`: the preamble runs PR07 mutual resume-auth over the
 * sealed session channel strictly before the transfer engine, exposes ONLY the fresh
 * resumed key epoch after mutual authentication, and fails closed on any wrong context,
 * secret, or foreign frame. The fresh-epoch assertion proves a new nonce pair per attempt
 * yields a new key epoch, so no old AES keys/counters are ever read back from disk.
 */

import { describe, expect, it } from 'vitest';
import { openSequenced, seal, type FrameHeaderInput } from './aead.js';
import { bytesToHex, hexToBytes } from './bytes.js';
import { deriveTransferKeys, type DirectionalKey, type TransferKeys } from './keyschedule.js';
import { ResumePreamble, type ResumePreambleOptions } from './resume-preamble.js';
import { FrameType } from './transfer.js';

/** Fixed public test master (never real credentials). */
const TEST_MASTER = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
const TEST_TID = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const TEST_FP = 'b'.repeat(64);

/** Deterministic distinct 32-byte nonce sources (test-only). */
function nonceSource(start: number): (n: number) => Uint8Array {
  let next = start;
  return (n: number) => {
    if (n !== 32) throw new Error(`nonce must be 32 bytes, got ${n}`);
    return Uint8Array.from({ length: 32 }, () => next++);
  };
}

async function sessionKeys(): Promise<TransferKeys> {
  return deriveTransferKeys(TEST_MASTER);
}

function preambleOptions(
  role: 'offerer' | 'joiner',
  secret: Uint8Array,
  keys: TransferKeys,
  over: Partial<ResumePreambleOptions> = {},
): ResumePreambleOptions {
  const sendDir: DirectionalKey = role === 'offerer' ? keys.o2j : keys.j2o;
  const recvDir: DirectionalKey = role === 'offerer' ? keys.j2o : keys.o2j;
  return {
    role,
    transferId: TEST_TID,
    fingerprint: TEST_FP,
    resumeSecret: secret,
    send: () => undefined,
    sendDir,
    recvDir,
    sendCounter: 1, // session handshake consumed one frame per direction
    recvCounter: 1,
    ...over,
  };
}

/** Wires two preambles through in-memory channels and drives them to settle. */
async function preamblePair(
  o: ResumePreambleOptions,
  j: ResumePreambleOptions,
): Promise<{
  resO: Awaited<ReturnType<ResumePreamble['done']>>;
  errO?: Error;
  resJ: Awaited<ReturnType<ResumePreamble['done']>>;
  errJ?: Error;
}> {
  const chO: Uint8Array[] = [];
  const chJ: Uint8Array[] = [];
  o.send = (f) => void chJ.push(f);
  j.send = (f) => void chO.push(f);
  const po = new ResumePreamble(o);
  const pj = new ResumePreamble(j);
  await po.start();
  // Pump until both settle: each handle may produce a frame for the peer, and the final
  // step settles the joiner while its ready frame settles the offerer.
  let rounds = 0;
  while ((!po.isSettled() || !pj.isSettled()) && rounds < 16) {
    rounds++;
    const toO = chO.splice(0);
    const toJ = chJ.splice(0);
    if (toJ.length === 0 && toO.length === 0) {
      // No progress possible without a peer message; if one side already failed, the other
      // waits for the connection teardown (the caller's responsibility in production).
      break;
    }
    await Promise.all([...toJ.map((f) => pj.handle(f)), ...toO.map((f) => po.handle(f))]);
  }
  const resO = await po.done();
  const resJ = await pj.done();
  let errO: Error | undefined;
  let errJ: Error | undefined;
  try {
    po.result();
  } catch (e) {
    errO = e as Error;
  }
  try {
    pj.result();
  } catch (e) {
    errJ = e as Error;
  }
  return { resO, errO, resJ, errJ };
}

describe('resume preamble', () => {
  it('mutual auth happy path exposes the fresh resumed epoch', async () => {
    const keys = await sessionKeys();
    const secret = new Uint8Array(32).fill(0xab);
    const o = preambleOptions('offerer', secret, keys, { nonceSource: nonceSource(1) });
    const j = preambleOptions('joiner', secret, keys, { nonceSource: nonceSource(0x11) });
    const { resO, errO, resJ, errJ } = await preamblePair(o, j);
    expect(errO).toBeUndefined();
    expect(errJ).toBeUndefined();
    expect(resO).toBeDefined();
    expect(resJ).toBeDefined();
    // Both sides derive the same fresh directional keys, distinct from the session keys.
    expect(bytesToHex(resO!.keys.o2j.key)).toBe(bytesToHex(resJ!.keys.o2j.key));
    expect(bytesToHex(resO!.keys.j2o.key)).toBe(bytesToHex(resJ!.keys.j2o.key));
    expect(bytesToHex(resO!.keys.o2j.key)).not.toBe(bytesToHex(keys.o2j.key));
    expect(bytesToHex(resO!.keys.j2o.key)).not.toBe(bytesToHex(keys.j2o.key));
    // Fresh epoch: counters start at 0 only because the keys are new (ADR 0005 §7).
    expect(resO!.sendCounter).toBe(0);
    expect(resO!.recvCounter).toBe(0);
    expect(resJ!.sendCounter).toBe(0);
    expect(resJ!.recvCounter).toBe(0);
    expect(resO!.transferId).toBe(TEST_TID);
    expect(resJ!.transferId).toBe(TEST_TID);
    expect(resO!.role).toBe('offerer');
    expect(resJ!.role).toBe('joiner');
  });

  it('fresh nonces per attempt yield distinct key epochs', async () => {
    const keys = await sessionKeys();
    const secret = new Uint8Array(32).fill(0xcd);
    const a = await preamblePair(
      preambleOptions('offerer', secret, keys, { nonceSource: nonceSource(1) }),
      preambleOptions('joiner', secret, keys, { nonceSource: nonceSource(0x11) }),
    );
    const b = await preamblePair(
      preambleOptions('offerer', secret, keys, { nonceSource: nonceSource(0x21) }),
      preambleOptions('joiner', secret, keys, { nonceSource: nonceSource(0x31) }),
    );
    expect(a.errO).toBeUndefined();
    expect(b.errO).toBeUndefined();
    // Attempt A and attempt B for the same transfer MUST yield different traffic key epochs.
    expect(bytesToHex(a.resO!.keys.o2j.key)).not.toBe(bytesToHex(b.resO!.keys.o2j.key));
    expect(bytesToHex(a.resO!.keys.j2o.key)).not.toBe(bytesToHex(b.resO!.keys.j2o.key));
  });

  it('wrong secret fails closed on both sides', async () => {
    const keys = await sessionKeys();
    const chO: Uint8Array[] = [];
    const chJ: Uint8Array[] = [];
    const o = preambleOptions('offerer', new Uint8Array(32).fill(1), keys, {
      send: (f) => void chJ.push(f),
    });
    const j = preambleOptions('joiner', new Uint8Array(32).fill(2), keys, {
      send: (f) => void chO.push(f),
    });
    const po = new ResumePreamble(o);
    const pj = new ResumePreamble(j);
    await po.start();
    // init -> joiner; joiner replies with its challenge (proof under ITS secret).
    await pj.handle(chJ.shift()!);
    // The offerer verifies the joiner's proof against ITS secret -> mismatch -> fails closed.
    await po.handle(chO.shift()!);
    const resO = await po.done();
    expect(resO).toBeUndefined();
    let errO: Error | undefined;
    try {
      po.result();
    } catch (e) {
      errO = e as Error;
    }
    expect(errO).toBeDefined();
    expect(String(errO)).toContain('resume');
    // The joiner must never expose a result either; in production the connection teardown
    // releases it (the wire-level suite pins that path via cancellation).
    expect(pj.isSettled()).toBe(false);
    expect(() => pj.result()).toThrow('resume: preamble has not settled');
  });

  it('joiner start is a no-op and waits for resume_init', async () => {
    const keys = await sessionKeys();
    let sent = false;
    const p = new ResumePreamble(
      preambleOptions('joiner', new Uint8Array(32).fill(3), keys, {
        send: () => {
          sent = true;
        },
      }),
    );
    await p.start();
    expect(sent).toBe(false);
    expect(p.isSettled()).toBe(false);
  });

  it('rejects a missing resume secret at construction', async () => {
    const keys = await sessionKeys();
    const opts = preambleOptions('offerer', new Uint8Array(0), keys);
    expect(() => new ResumePreamble(opts)).toThrow(/resume secret/);
  });

  it('rejects foreign transfer frames before authentication completes', async () => {
    const keys = await sessionKeys();
    const secret = new Uint8Array(32).fill(7);
    const o = preambleOptions('offerer', secret, keys, { nonceSource: nonceSource(1) });
    const j = preambleOptions('joiner', secret, keys, { nonceSource: nonceSource(0x11) });
    const chO: Uint8Array[] = [];
    const chJ: Uint8Array[] = [];
    o.send = (f) => void chJ.push(f);
    j.send = (f) => void chO.push(f);
    const po = new ResumePreamble(o);
    const pj = new ResumePreamble(j);
    await po.start();
    // Feed a MANIFEST frame (not a resume-auth frame) to the joiner under the session key:
    // it must fail closed, not be routed into the transfer engine. The plaintext is any
    // bytes — the preamble rejects on the frame TYPE before ever parsing it.
    const header: FrameHeaderInput = {
      version: 1,
      type: FrameType.Manifest,
      flags: 0,
      fileIdx: 0,
      blockIdx: 0,
      frameOff: 0,
    };
    const foreign = await seal(j.recvDir, 1, header, new TextEncoder().encode('{"manifest":true}'));
    await pj.handle(foreign);
    const resJ = await pj.done();
    expect(resJ).toBeUndefined();
    let errJ: Error | undefined;
    try {
      pj.result();
    } catch (e) {
      errJ = e as Error;
    }
    expect(errJ).toBeDefined();
    expect(String(errJ)).toContain('resume');
  });

  it('an exact duplicate of the last accepted frame is re-answered idempotently', async () => {
    const keys = await sessionKeys();
    const secret = new Uint8Array(32).fill(0x42);
    const o = preambleOptions('offerer', secret, keys, { nonceSource: nonceSource(1) });
    const j = preambleOptions('joiner', secret, keys, { nonceSource: nonceSource(0x11) });
    const chO: Uint8Array[] = [];
    const chJ: Uint8Array[] = [];
    o.send = (f) => void chJ.push(f);
    j.send = (f) => void chO.push(f);
    const po = new ResumePreamble(o);
    const pj = new ResumePreamble(j);
    await po.start();
    // init -> joiner.
    const initFrames = chJ.splice(0);
    expect(initFrames).toHaveLength(1);
    await pj.handle(initFrames[0]!);
    // challenge -> offerer, delivered twice (a transport-level re-send).
    const challengeFrames = chO.splice(0);
    expect(challengeFrames).toHaveLength(1);
    await po.handle(challengeFrames[0]!);
    await po.handle(challengeFrames[0]!);
    const confirmFrames = chJ.splice(0);
    // The duplicate must be re-answered IDENTICALLY at the MESSAGE level (same confirm
    // snapshot, never a fresh challenge or proof) — two confirms with equal plaintexts,
    // not a new handshake. The frames themselves differ only in the advancing counter.
    expect(confirmFrames).toHaveLength(2);
    // The offerer sent resume_init at counter 1, so its confirms are counters 2 and 3.
    const open1 = await openSequenced(keys.o2j, 2, confirmFrames[0]!);
    const open2 = await openSequenced(keys.o2j, 3, confirmFrames[1]!);
    expect(bytesToHex(open1.plaintext)).toBe(bytesToHex(open2.plaintext));
    // The joiner settles on the first confirm; the second is an idempotent re-answer.
    await pj.handle(confirmFrames[0]!);
    const readyFrames = chO.splice(0);
    expect(readyFrames).toHaveLength(1);
    await po.handle(readyFrames[0]!);
    const resO = await po.done();
    const resJ = await pj.done();
    expect(resO).toBeDefined();
    expect(resJ).toBeDefined();
    expect(bytesToHex(resO!.keys.o2j.key)).toBe(bytesToHex(resJ!.keys.o2j.key));
  });
});
