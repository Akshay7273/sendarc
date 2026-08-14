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

  describe('serialized inbound processing (V13-PR08 Blocker 5)', () => {
    /**
     * Delivers init and its transport re-send to the joiner via Promise.all — WITHOUT
     * awaiting between deliveries. The queue must process them in strict arrival order: the
     * first consumes counter 1 and answers challenge at j2o counter 1; the second is the
     * exact-duplicate re-send (counter 1 again) re-answered idempotently at counter 2. The
     * send counters prove the two inbound frames were consumed exactly once, in order, and
     * no counter was consumed twice. Without serialization the second handle would open at
     * the already-advanced counter and fail as a replay.
     */
    it('two frames delivered without awaiting process in strict arrival order — no counter consumed twice', async () => {
      const keys = await sessionKeys();
      const secret = new Uint8Array(32).fill(0x5a);
      const o = preambleOptions('offerer', secret, keys, { nonceSource: nonceSource(1) });
      const j = preambleOptions('joiner', secret, keys, { nonceSource: nonceSource(0x11) });
      const chO: Uint8Array[] = [];
      const chJ: Uint8Array[] = [];
      o.send = (f) => void chJ.push(f);
      j.send = (f) => void chO.push(f);
      const po = new ResumePreamble(o);
      const pj = new ResumePreamble(j);
      await po.start();
      // The transport re-sends init (the joiner's first challenge was "lost"): both frames
      // are delivered to the joiner at once, without awaiting between the deliveries.
      const init = chJ.shift()!;
      const handled = await Promise.all([pj.handle(init), pj.handle(init)]);
      await Promise.all(handled);
      // Exactly two challenges, at j2o counters 1 and 2, with byte-identical plaintexts:
      // the re-send was re-answered idempotently from the engine snapshot, never with a
      // fresh nonce or proof, and the counters advanced strictly in arrival order.
      expect(chO).toHaveLength(2);
      const open1 = await openSequenced(keys.j2o, 1, chO[0]!);
      const open2 = await openSequenced(keys.j2o, 2, chO[1]!);
      expect(open1.header.type).toBe(FrameType.ResumeAuth);
      expect(open2.header.type).toBe(FrameType.ResumeAuth);
      expect(bytesToHex(open1.plaintext)).toBe(bytesToHex(open2.plaintext));
      expect(pj.isSettled()).toBe(false); // re-answers never settle the joiner

      // Drive the rest of the handshake: both challenges reach the offerer in order (the
      // second is a fresh counter-2 frame, re-answered identically), then confirm reaches
      // the joiner, then ready reaches the offerer. Everything settles successfully.
      await po.handle(chO.shift()!);
      await po.handle(chO.shift()!);
      const confirms = chJ.splice(0);
      expect(confirms).toHaveLength(2);
      const c1 = await openSequenced(keys.o2j, 2, confirms[0]!);
      const c2 = await openSequenced(keys.o2j, 3, confirms[1]!);
      expect(bytesToHex(c1.plaintext)).toBe(bytesToHex(c2.plaintext));
      await pj.handle(confirms[0]!);
      await po.handle(chO.shift()!);
      const resO = await po.done();
      const resJ = await pj.done();
      expect(resO).toBeDefined();
      expect(resJ).toBeDefined();
      expect(bytesToHex(resO!.keys.o2j.key)).toBe(bytesToHex(resJ!.keys.o2j.key));
    });

    it('concurrent exact duplicate stays deterministic and settles successfully', async () => {
      const keys = await sessionKeys();
      const secret = new Uint8Array(32).fill(0x6b);
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
      await pj.handle(chJ.shift()!);
      // The SAME challenge frame delivered twice concurrently: the first consumes counter 1,
      // the second is the exact-duplicate re-send (counter 1 again) re-answered idempotently.
      const challenge = chO.shift()!;
      const handleDup = await Promise.all([po.handle(challenge), po.handle(challenge)]);
      await Promise.all(handleDup);
      const confirms = chJ.splice(0);
      // Two identical message-level confirms (counters 2 and 3), never a fresh handshake.
      expect(confirms).toHaveLength(2);
      const open1 = await openSequenced(keys.o2j, 2, confirms[0]!);
      const open2 = await openSequenced(keys.o2j, 3, confirms[1]!);
      expect(bytesToHex(open1.plaintext)).toBe(bytesToHex(open2.plaintext));
      await pj.handle(confirms[0]!);
      await po.handle(chO.shift()!);
      const resO = await po.done();
      const resJ = await pj.done();
      expect(resO).toBeDefined();
      expect(resJ).toBeDefined();
    });

    it('concurrent conflicting duplicate fails terminally; the queued valid frame observes the failure', async () => {
      const keys = await sessionKeys();
      const secret = new Uint8Array(32).fill(0x7c);
      const o = preambleOptions('offerer', secret, keys, { nonceSource: nonceSource(1) });
      const j = preambleOptions('joiner', secret, keys, { nonceSource: nonceSource(0x11) });
      const chO: Uint8Array[] = [];
      const chJ: Uint8Array[] = [];
      o.send = (f) => void chJ.push(f);
      j.send = (f) => void chO.push(f);
      const po = new ResumePreamble(o);
      const pj = new ResumePreamble(j);
      await po.start();
      await pj.handle(chJ.shift()!);
      const challenge = chO.shift()!;
      // A forged frame sealed at the SAME counter (1) whose plaintext differs from the real
      // challenge: delivered concurrently with the genuine challenge, forged first.
      const header: FrameHeaderInput = {
        version: 1,
        type: FrameType.ResumeAuth,
        flags: 0,
        fileIdx: 0,
        blockIdx: 0,
        frameOff: 0,
      };
      const forged = await seal(
        o.recvDir,
        1,
        header,
        new TextEncoder().encode('forged conflicting replay'),
      );
      const handled = await Promise.all([po.handle(forged), po.handle(challenge)]);
      await Promise.all(handled);
      // First failure is terminal; the queued genuine frame observes the settled state and
      // cannot resurrect the preamble. No handle() promise rejects (no unhandled rejection).
      const resO = await po.done();
      expect(resO).toBeUndefined();
      expect(po.isSettled()).toBe(true);
      expect(() => po.result()).toThrow(/resume/);
      // The peer never receives a confirm: the offerer failed before answering.
      expect(chJ).toHaveLength(0);
    });

    it('malformed first frame settles failed; a later queued valid frame cannot resurrect it', async () => {
      const keys = await sessionKeys();
      const secret = new Uint8Array(32).fill(0x8d);
      const o = preambleOptions('offerer', secret, keys, { nonceSource: nonceSource(1) });
      const j = preambleOptions('joiner', secret, keys, { nonceSource: nonceSource(0x11) });
      const chO: Uint8Array[] = [];
      const chJ: Uint8Array[] = [];
      o.send = (f) => void chJ.push(f);
      j.send = (f) => void chO.push(f);
      const po = new ResumePreamble(o);
      const pj = new ResumePreamble(j);
      await po.start();
      await pj.handle(chJ.shift()!);
      const challenge = chO.shift()!;
      // A MANIFEST frame under the session key at the expected counter: wrong type, so it
      // settles the preamble failed. The genuine challenge queued behind it observes the
      // settled state and is dropped — the failure is terminal.
      const header: FrameHeaderInput = {
        version: 1,
        type: FrameType.Manifest,
        flags: 0,
        fileIdx: 0,
        blockIdx: 0,
        frameOff: 0,
      };
      const foreign = await seal(o.recvDir, 1, header, new TextEncoder().encode('{}'));
      const handled = await Promise.all([po.handle(foreign), po.handle(challenge)]);
      await Promise.all(handled);
      const resO = await po.done();
      expect(resO).toBeUndefined();
      expect(po.isSettled()).toBe(true);
      expect(() => po.result()).toThrow(/resume/);
      expect(chJ).toHaveLength(0);
    });

    it('cancel while the handler is awaiting settles queued work and abandons the attempt', async () => {
      const keys = await sessionKeys();
      const secret = new Uint8Array(32).fill(0x9e);
      const o = preambleOptions('offerer', secret, keys, { nonceSource: nonceSource(1) });
      const j = preambleOptions('joiner', secret, keys, { nonceSource: nonceSource(0x11) });
      const chO: Uint8Array[] = [];
      const chJ: Uint8Array[] = [];
      // The joiner's send is gated so its handle(init) stays in flight across an await while
      // we cancel — the crypto is mid-processing, exactly the reload/teardown race.
      let release!: () => void;
      const gate = new Promise<void>((resolve) => (release = resolve));
      j.send = (f) => {
        chO.push(f);
        return gate;
      };
      o.send = (f) => void chJ.push(f);
      const po = new ResumePreamble(o);
      const pj = new ResumePreamble(j);
      await po.start();
      const inFlight = pj.handle(chJ.shift()!);
      // Cancel while the handler awaits the send gate; then release it so the handler resumes
      // and observes the settled state.
      pj.cancel();
      release();
      await inFlight;
      const resJ = await pj.done();
      expect(resJ).toBeUndefined();
      expect(pj.isSettled()).toBe(true);
      expect(() => pj.result()).toThrow(/canceled/);
      // A frame queued after cancellation is dropped — it cannot resurrect a settled preamble.
      await pj.handle(chJ.shift()!);
      expect(pj.isSettled()).toBe(true);
      expect(() => pj.result()).toThrow(/canceled/);
      // The offerer never settles on its own (production teardown releases it).
      expect(po.isSettled()).toBe(false);
    });
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
