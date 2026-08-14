/**
 * Resume-auth (V13-PR07) tests — deterministic, no sleeps. The committed
 * docs/test-vectors/resume-auth.json is asserted byte-for-byte, so any drift between the Go
 * and TypeScript implementations fails one of the suites.
 */

import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  RESUME_AUTH_CAPABILITY,
  RESUME_AUTH_VERSION,
  RESUME_PROOF_BYTES,
  RESUME_SECRET_BYTES,
  RESUME_MSG_CHALLENGE,
  RESUME_MSG_CONFIRM,
  RESUME_MSG_INIT,
  RESUME_MSG_READY,
  decodeResumeMessage,
  decodeResumeSecretEnvelope,
  deriveResumeRoot,
  deriveResumeSecret,
  encodeResumeMessage,
  encodeResumeSecretEnvelope,
  negotiateResumeAuth,
  resumeJoinerProof,
  resumeOffererProof,
  resumeReadyProof,
  resumeSessionMaster,
  resumeTranscript,
  ResumeAuthSession,
  type ResumeAuthContext,
  type ResumeAuthOutcome,
  type ResumeMessage,
} from './resume-auth.js';
import { bytesToHex, hexToBytes, utf8 } from './bytes.js';
import { deriveTransferKeys } from './keyschedule.js';
import { randomBytes } from './webcrypto.js';

// Fixed public KAT inputs, matching the committed vector (never real credentials).
const VECTOR_MASTER = hexToBytes(
  '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
);
const VECTOR_TRANSFER_ID = '0123456789abcdef0123456789abcdef';
const VECTOR_FINGERPRINT = '0123456789abcdef'.repeat(4);
const VECTOR_OFFERER_NONCE = bytesRange(0x10, 0x30);
const VECTOR_JOINER_NONCE = bytesRange(0x30, 0x50);

function bytesRange(start: number, end: number): Uint8Array {
  return Uint8Array.from({ length: end - start }, (_, i) => start + i);
}

/** Deterministic nonce source: returns exactly `nonce` on every request. */
function fixedNonce(nonce: Uint8Array): (n: number) => Uint8Array {
  return (n: number) => {
    if (n !== nonce.length) throw new Error(`unexpected nonce size ${n}`);
    return nonce.slice();
  };
}

/** The fixed vector secret, shared by the test contexts. */
const VECTOR_SECRET = 'b4588a54a6ea54c8f869a8da4cf72db6a2bf1f36516d7f8960aed7f6b3b6a518';

async function vectorDoc(): Promise<Record<string, string | number>> {
  const path = join(__dirname, '..', '..', '..', 'docs', 'test-vectors', 'resume-auth.json');
  return JSON.parse(readFileSync(path, 'utf8')) as Record<string, string | number>;
}

function context(
  role: 'offerer' | 'joiner',
  over: Partial<ResumeAuthContext> = {},
): ResumeAuthContext {
  return {
    version: RESUME_AUTH_VERSION,
    transferId: VECTOR_TRANSFER_ID,
    manifestFingerprint: VECTOR_FINGERPRINT,
    role,
    resumeSecret: hexToBytes(VECTOR_SECRET),
    nonceSource:
      role === 'offerer' ? fixedNonce(VECTOR_OFFERER_NONCE) : fixedNonce(VECTOR_JOINER_NONCE),
    ...over,
  };
}

/** Drive a full handshake between an offerer and a joiner session; returns both results. */
async function runHandshake(
  offererCtx: ResumeAuthContext,
  joinerCtx: ResumeAuthContext,
): Promise<{
  offererResult: ResumeAuthOutcome['result'];
  joinerResult: ResumeAuthOutcome['result'];
}> {
  const offerer = new ResumeAuthSession(offererCtx);
  const joiner = new ResumeAuthSession(joinerCtx);
  const init = offerer.start();
  const challenge = await joiner.handle(encodeResumeMessage(init));
  const confirm = await offerer.handle(encodeResumeMessage(challenge.out!));
  const ready = await joiner.handle(encodeResumeMessage(confirm.out!));
  const final = await offerer.handle(encodeResumeMessage(ready.out!));
  return { offererResult: final.result, joinerResult: ready.result };
}

describe('resume-auth derivation', () => {
  it('reproduces the committed cross-language vector byte-for-byte', async () => {
    const doc = await vectorDoc();
    expect(doc.version).toBe(RESUME_AUTH_VERSION);
    expect(bytesToHex(VECTOR_MASTER)).toBe(doc.master);
    expect(VECTOR_TRANSFER_ID).toBe(doc.transferId);
    expect(VECTOR_FINGERPRINT).toBe(doc.manifestFingerprint);

    const resumeRoot = await deriveResumeRoot(VECTOR_MASTER);
    expect(bytesToHex(resumeRoot)).toBe(doc.resumeRoot);

    const resumeSecret = await deriveResumeSecret(
      resumeRoot,
      RESUME_AUTH_VERSION,
      VECTOR_TRANSFER_ID,
      VECTOR_FINGERPRINT,
    );
    expect(bytesToHex(resumeSecret)).toBe(doc.resumeSecret);

    const transcript = await resumeTranscript(
      RESUME_AUTH_VERSION,
      VECTOR_TRANSFER_ID,
      VECTOR_FINGERPRINT,
      VECTOR_OFFERER_NONCE,
      VECTOR_JOINER_NONCE,
    );
    expect(bytesToHex(transcript)).toBe(doc.transcript);

    expect(bytesToHex(await resumeJoinerProof(resumeSecret, transcript))).toBe(doc.joinerProof);
    expect(bytesToHex(await resumeOffererProof(resumeSecret, transcript))).toBe(doc.offererProof);
    expect(bytesToHex(await resumeReadyProof(resumeSecret, transcript))).toBe(doc.readyProof);

    const master = await resumeSessionMaster(resumeSecret, transcript);
    expect(bytesToHex(master)).toBe(doc.resumeMaster);
    const keys = await deriveTransferKeys(master);
    expect(bytesToHex(keys.o2j.key)).toBe(doc.o2jKey);
    expect(bytesToHex(keys.o2j.salt)).toBe(doc.o2jSalt);
    expect(bytesToHex(keys.j2o.key)).toBe(doc.j2oKey);
    expect(bytesToHex(keys.j2o.salt)).toBe(doc.j2oSalt);
  });

  it('binds the secret to transferId and manifest fingerprint', async () => {
    const root = await deriveResumeRoot(VECTOR_MASTER);
    const secret = await deriveResumeSecret(
      root,
      RESUME_AUTH_VERSION,
      VECTOR_TRANSFER_ID,
      VECTOR_FINGERPRINT,
    );
    const otherTransfer = await deriveResumeSecret(
      root,
      RESUME_AUTH_VERSION,
      'aa'.repeat(16),
      VECTOR_FINGERPRINT,
    );
    const otherFingerprint = await deriveResumeSecret(
      root,
      RESUME_AUTH_VERSION,
      VECTOR_TRANSFER_ID,
      'f'.repeat(64),
    );
    expect(bytesToHex(otherTransfer)).not.toBe(bytesToHex(secret));
    expect(bytesToHex(otherFingerprint)).not.toBe(bytesToHex(secret));
    expect(otherTransfer.length).toBe(RESUME_SECRET_BYTES);
  });

  it('rejects malformed derivation context', async () => {
    const root = await deriveResumeRoot(VECTOR_MASTER);
    await expect(
      deriveResumeSecret(root, RESUME_AUTH_VERSION, 'not-hex', VECTOR_FINGERPRINT),
    ).rejects.toThrow(/transferId/);
    await expect(
      deriveResumeSecret(root, RESUME_AUTH_VERSION, VECTOR_TRANSFER_ID, 'short'),
    ).rejects.toThrow(/manifestFingerprint/);
    await expect(
      deriveResumeSecret(root, 2, VECTOR_TRANSFER_ID, VECTOR_FINGERPRINT),
    ).rejects.toThrow(/version/);
    await expect(deriveResumeRoot(new Uint8Array(0))).rejects.toThrow(/master/);
  });

  it('persisted envelope is the exact 64-hex credential', () => {
    const secret = randomBytes(RESUME_SECRET_BYTES);
    const envelope = encodeResumeSecretEnvelope(secret);
    expect(envelope).toEqual({ version: RESUME_AUTH_VERSION, value: bytesToHex(secret) });
    expect(decodeResumeSecretEnvelope(envelope)).toEqual(secret);
    expect(() => encodeResumeSecretEnvelope(new Uint8Array(16))).toThrow(/32 bytes/);
    expect(() => decodeResumeSecretEnvelope({ version: 2, value: envelope.value })).toThrow(
      /version/,
    );
    expect(() => decodeResumeSecretEnvelope({ version: 1, value: '00' })).toThrow(
      /64 lowercase hex/,
    );
    expect(() => decodeResumeSecretEnvelope(undefined)).toThrow(/missing/);
  });
});

describe('resume-auth message codec', () => {
  // 'A'.repeat(43) is the canonical base64url of 32 zero bytes (all-zero trailing bits).
  const init: ResumeMessage = {
    type: RESUME_MSG_INIT,
    version: 1,
    role: 'offerer',
    nonce: 'A'.repeat(43),
  };
  const challenge: ResumeMessage = {
    type: RESUME_MSG_CHALLENGE,
    version: 1,
    role: 'joiner',
    nonce: 'A'.repeat(43),
    proof: 'A'.repeat(43),
  };
  const confirm: ResumeMessage = {
    type: RESUME_MSG_CONFIRM,
    version: 1,
    role: 'offerer',
    proof: 'A'.repeat(43),
  };
  const ready: ResumeMessage = {
    type: RESUME_MSG_READY,
    version: 1,
    role: 'joiner',
    proof: 'A'.repeat(43),
  };

  it('round-trips every message canonically', () => {
    for (const msg of [init, challenge, confirm, ready]) {
      expect(decodeResumeMessage(encodeResumeMessage(msg))).toEqual(msg);
    }
  });

  it('rejects malformed, oversized, or non-canonical messages', () => {
    // 'A'.repeat(43) is 32 bytes base64url; 'AA' is 1 byte.
    const cases: Array<[string, Record<string, unknown>]> = [
      [
        'wrong version',
        { type: RESUME_MSG_INIT, version: 2, role: 'offerer', nonce: 'A'.repeat(43) },
      ],
      [
        'wrong role on init',
        { type: RESUME_MSG_INIT, version: 1, role: 'joiner', nonce: 'A'.repeat(43) },
      ],
      ['missing role', { type: RESUME_MSG_INIT, version: 1, nonce: 'A'.repeat(43) }],
      ['short nonce', { type: RESUME_MSG_INIT, version: 1, role: 'offerer', nonce: 'AA' }],
      ['long nonce', { type: RESUME_MSG_INIT, version: 1, role: 'offerer', nonce: 'A'.repeat(44) }],
      ['missing nonce', { type: RESUME_MSG_INIT, version: 1, role: 'offerer' }],
      [
        'non-canonical nonce',
        { type: RESUME_MSG_INIT, version: 1, role: 'offerer', nonce: 'A'.repeat(42) + 'A=' },
      ],
      [
        'init with proof',
        {
          type: RESUME_MSG_INIT,
          version: 1,
          role: 'offerer',
          nonce: 'A'.repeat(43),
          proof: 'B'.repeat(43),
        },
      ],
      ['short proof', { type: RESUME_MSG_CONFIRM, version: 1, role: 'offerer', proof: 'AA' }],
      [
        'long proof',
        { type: RESUME_MSG_CONFIRM, version: 1, role: 'offerer', proof: 'B'.repeat(44) },
      ],
      [
        'confirm with nonce',
        {
          type: RESUME_MSG_CONFIRM,
          version: 1,
          role: 'offerer',
          nonce: 'A'.repeat(43),
          proof: 'C'.repeat(43),
        },
      ],
      [
        'wrong role on ready',
        { type: RESUME_MSG_READY, version: 1, role: 'offerer', proof: 'D'.repeat(43) },
      ],
      ['unknown type', { type: 'resume_unknown', version: 1, role: 'offerer' }],
      [
        'unknown field',
        { type: RESUME_MSG_INIT, version: 1, role: 'offerer', nonce: 'A'.repeat(43), extra: 1 },
      ],
      ['non-string nonce', { type: RESUME_MSG_INIT, version: 1, role: 'offerer', nonce: 123 }],
    ];
    for (const [name, obj] of cases) {
      expect(() => decodeResumeMessage(utf8(JSON.stringify(obj))), name).toThrow();
    }
    // Trailing garbage is rejected.
    const valid = new TextDecoder().decode(encodeResumeMessage(init));
    expect(() => decodeResumeMessage(utf8(valid + '{}'))).toThrow();
  });
});

describe('resume-auth handshake', () => {
  it('completes mutual authentication with fresh keys on both sides', async () => {
    const { offererResult, joinerResult } = await runHandshake(
      context('offerer'),
      context('joiner'),
    );
    expect(offererResult).toBeDefined();
    expect(joinerResult).toBeDefined();
    const offererKeys = offererResult!.keys;
    const joinerKeys = joinerResult!.keys;
    // Both sides derive identical fresh directional keys.
    expect(bytesToHex(offererKeys.o2j.key)).toBe(bytesToHex(joinerKeys.o2j.key));
    expect(bytesToHex(offererKeys.o2j.salt)).toBe(bytesToHex(joinerKeys.o2j.salt));
    expect(bytesToHex(offererKeys.j2o.key)).toBe(bytesToHex(joinerKeys.j2o.key));
    expect(bytesToHex(offererKeys.j2o.salt)).toBe(bytesToHex(joinerKeys.j2o.salt));
    expect(offererResult!.sendCounter).toBe(0);
    expect(offererResult!.recvCounter).toBe(0);
    expect(offererResult!.transferId).toBe(VECTOR_TRANSFER_ID);
  });

  it('derives different keys on every attempt (fresh nonces) and never reuses old keys', async () => {
    // Session A uses the vector nonces; session B uses different nonces.
    const { offererResult: a } = await runHandshake(context('offerer'), context('joiner'));
    const b = await runHandshake(
      { ...context('offerer'), nonceSource: fixedNonce(bytesRange(0x80, 0xa0)) },
      { ...context('joiner'), nonceSource: fixedNonce(bytesRange(0xa0, 0xc0)) },
    );
    expect(bytesToHex(a!.keys.o2j.key)).not.toBe(bytesToHex(b!.offererResult!.keys.o2j.key));
    expect(bytesToHex(a!.keys.o2j.salt)).not.toBe(bytesToHex(b!.offererResult!.keys.o2j.salt));
    expect(bytesToHex(a!.keys.j2o.key)).not.toBe(bytesToHex(b!.offererResult!.keys.j2o.key));
    // The fresh keys differ from the ORIGINAL session keys (the original session's
    // "sendbeam/1 master" derivation) and between directions.
    const original = await deriveTransferKeys(VECTOR_MASTER);
    expect(bytesToHex(a!.keys.o2j.key)).not.toBe(bytesToHex(original.o2j.key));
    expect(bytesToHex(a!.keys.j2o.key)).not.toBe(bytesToHex(original.j2o.key));
    expect(bytesToHex(a!.keys.o2j.key)).not.toBe(bytesToHex(a!.keys.j2o.key));
    expect(bytesToHex(a!.keys.o2j.salt)).not.toBe(bytesToHex(a!.keys.j2o.salt));
  });

  it('fails closed on wrong secret, transferId, fingerprint, or version', async () => {
    const wrongSecret = { ...context('joiner'), resumeSecret: randomBytes(RESUME_SECRET_BYTES) };
    await expect(runHandshake(context('offerer'), wrongSecret)).rejects.toThrow(
      /verification failed/,
    );

    await expect(
      runHandshake(context('offerer'), { ...context('joiner'), transferId: 'aa'.repeat(16) }),
    ).rejects.toThrow(/verification failed/);

    await expect(
      runHandshake(context('offerer'), {
        ...context('joiner'),
        manifestFingerprint: 'f'.repeat(64),
      }),
    ).rejects.toThrow(/verification failed/);

    await expect(
      runHandshake({ ...context('offerer'), version: 2 }, context('joiner')),
    ).rejects.toThrow(/version/);
  });

  it('rejects a session without a secret up front', () => {
    expect(
      () => new ResumeAuthSession(context('offerer', { resumeSecret: new Uint8Array(0) })),
    ).toThrow(/secret/);
    expect(() => new ResumeAuthSession(context('offerer', { transferId: 'bad' }))).toThrow(
      /transferId/,
    );
  });
});

describe('resume-auth replay and reflection resistance', () => {
  it('cannot replay any recorded message into a fresh attempt', async () => {
    // Record a full successful exchange.
    const first = await runHandshake(context('offerer'), context('joiner'));
    void first;

    const freshOfferer = new ResumeAuthSession(
      context('offerer', { nonceSource: fixedNonce(bytesRange(0x60, 0x80)) }),
    );
    const freshJoiner = new ResumeAuthSession(
      context('joiner', { nonceSource: fixedNonce(bytesRange(0x80, 0xa0)) }),
    );

    // Replay the OLD init into a fresh joiner: the joiner answers a challenge with a fresh
    // nonce, and the old offerer's recorded confirm/proof can never match the new transcript.
    const oldInit = encodeResumeMessage({
      type: RESUME_MSG_INIT,
      version: 1,
      role: 'offerer',
      nonce: 'A'.repeat(43),
    });
    const challengeOut = await freshJoiner.handle(oldInit);
    expect(challengeOut.out).toBeDefined();

    // Replay the old challenge (from the recorded attempt) against the fresh offerer: the
    // old joiner nonce + proof is bound to the old transcript and fails.
    freshOfferer.start();
    const recordedChallenge = encodeResumeMessage({
      type: RESUME_MSG_CHALLENGE,
      version: 1,
      role: 'joiner',
      nonce: bytesToBase64url(VECTOR_JOINER_NONCE),
      proof: bytesToBase64url(
        hexToBytes('c6e62f9631da6b0b8276074665536a4013f497db6488d693052585329cad9e09'),
      ),
    });
    await expect(freshOfferer.handle(recordedChallenge)).rejects.toThrow(/verification failed/);
  });

  it('rejects reflection: a valid offerer proof never verifies as a joiner proof', async () => {
    const transcript = await resumeTranscript(
      RESUME_AUTH_VERSION,
      VECTOR_TRANSFER_ID,
      VECTOR_FINGERPRINT,
      VECTOR_OFFERER_NONCE,
      VECTOR_JOINER_NONCE,
    );
    const secret = hexToBytes('b4588a54a6ea54c8f869a8da4cf72db6a2bf1f36516d7f8960aed7f6b3b6a518');
    const offererProof = await resumeOffererProof(secret, transcript);
    const joinerProof = await resumeJoinerProof(secret, transcript);
    const readyProof = await resumeReadyProof(secret, transcript);
    // Distinct tags → the three proofs are pairwise different.
    expect(bytesToHex(offererProof)).not.toBe(bytesToHex(joinerProof));
    expect(bytesToHex(offererProof)).not.toBe(bytesToHex(readyProof));
    expect(bytesToHex(joinerProof)).not.toBe(bytesToHex(readyProof));
    // Proofs keyed by role: an offerer proof must not verify where a joiner proof is expected.
    const joiner = new ResumeAuthSession(context('joiner'));
    const init = encodeResumeMessage({
      type: RESUME_MSG_INIT,
      version: 1,
      role: 'offerer',
      nonce: bytesToBase64url(VECTOR_OFFERER_NONCE),
    });
    const challenge = await joiner.handle(init);
    // Replace the joiner's proof with the offerer's proof from the same transcript — the
    // roles are swapped, so the challenge must fail.
    const reflected = {
      ...challenge.out!,
      proof: bytesToBase64url(offererProof),
    };
    const offerer = new ResumeAuthSession(
      context('offerer', { nonceSource: fixedNonce(VECTOR_OFFERER_NONCE) }),
    );
    offerer.start();
    await expect(offerer.handle(encodeResumeMessage(reflected))).rejects.toThrow(
      /verification failed/,
    );
  });

  it('rejects swapped original roles and role mutation', async () => {
    // The original offerer's recorded proof never verifies in the joiner position, even over
    // the SAME transcript (role-separated keys): feeding the offerer proof back as the
    // joiner's challenge proof fails closed.
    const secret = hexToBytes(VECTOR_SECRET);
    const transcript = await resumeTranscript(
      RESUME_AUTH_VERSION,
      VECTOR_TRANSFER_ID,
      VECTOR_FINGERPRINT,
      VECTOR_OFFERER_NONCE,
      VECTOR_JOINER_NONCE,
    );
    const recordedOffererProof = await resumeOffererProof(secret, transcript);
    const joiner = new ResumeAuthSession(context('joiner'));
    const init = encodeResumeMessage({
      type: RESUME_MSG_INIT,
      version: 1,
      role: 'offerer',
      nonce: bytesToBase64url(VECTOR_OFFERER_NONCE),
    });
    const challenge = await joiner.handle(init);
    const swapped = { ...challenge.out!, proof: bytesToBase64url(recordedOffererProof) };
    const offerer = new ResumeAuthSession(context('offerer'));
    offerer.start();
    await expect(offerer.handle(encodeResumeMessage(swapped))).rejects.toThrow(
      /verification failed/,
    );
    // A peer constructed for the joiner role cannot initiate the handshake as the offerer.
    await expect(runHandshake(context('joiner'), context('offerer'))).rejects.toThrow();
  });

  it('rejects modified challenges and modified proofs', async () => {
    const joiner = new ResumeAuthSession(context('joiner'));
    const init = encodeResumeMessage({
      type: RESUME_MSG_INIT,
      version: 1,
      role: 'offerer',
      nonce: bytesToBase64url(VECTOR_OFFERER_NONCE),
    });
    const challenge = await joiner.handle(init);
    const tampered = { ...challenge.out!, nonce: bytesToBase64url(bytesRange(0x40, 0x60)) };
    const offerer = new ResumeAuthSession(context('offerer'));
    offerer.start();
    await expect(offerer.handle(encodeResumeMessage(tampered))).rejects.toThrow(
      /verification failed/,
    );
  });
});

describe('resume-auth duplicates and idempotency', () => {
  it('re-answers an exact duplicate with the SAME snapshot (never a fresh nonce/proof)', async () => {
    const offerer = new ResumeAuthSession(context('offerer'));
    const joiner = new ResumeAuthSession(context('joiner'));
    const init = offerer.start();
    const initBytes = encodeResumeMessage(init);

    const first = await joiner.handle(initBytes);
    const duplicate = await joiner.handle(initBytes);
    expect(duplicate.out).toEqual(first.out); // identical challenge bytes — same nonce/proof

    const confirm = await offerer.handle(encodeResumeMessage(first.out!));
    const confirmBytes = encodeResumeMessage(confirm.out!);
    const confirmAgain = await offerer.handle(encodeResumeMessage(first.out!));
    expect(confirmAgain.out).toEqual(confirm.out);

    const ready = await joiner.handle(confirmBytes);
    const readyAgain = await joiner.handle(confirmBytes);
    expect(readyAgain.out).toEqual(ready.out);
    expect(ready.result).toBeDefined();
  });

  it('fails closed on conflicting duplicates', async () => {
    const offerer = new ResumeAuthSession(context('offerer'));
    const joiner = new ResumeAuthSession(context('joiner'));
    const init = offerer.start();
    const first = await joiner.handle(encodeResumeMessage(init));
    const confirm = await offerer.handle(encodeResumeMessage(first.out!));
    void (await joiner.handle(encodeResumeMessage(confirm.out!))); // joiner settles
    // A different init after settlement is a conflicting duplicate.
    await expect(
      joiner.handle(
        encodeResumeMessage({
          type: RESUME_MSG_INIT,
          version: 1,
          role: 'offerer',
          nonce: bytesToBase64url(bytesRange(0x70, 0x90)),
        }),
      ),
    ).rejects.toThrow(/conflicting duplicate/);
  });

  it('fails closed on out-of-order messages', async () => {
    const offerer = new ResumeAuthSession(context('offerer'));
    // Confirm before init is impossible.
    await expect(
      offerer.handle(
        encodeResumeMessage({
          type: RESUME_MSG_CONFIRM,
          version: 1,
          role: 'offerer',
          proof: 'A'.repeat(43),
        }),
      ),
    ).rejects.toThrow(/unexpected/);
    // Ready before any challenge is impossible too.
    const joiner = new ResumeAuthSession(context('joiner'));
    await expect(
      joiner.handle(
        encodeResumeMessage({
          type: RESUME_MSG_READY,
          version: 1,
          role: 'joiner',
          proof: 'A'.repeat(43),
        }),
      ),
    ).rejects.toThrow(/unexpected/);
  });
});

describe('resume-auth server forgery harness', () => {
  it('a server that observes, drops, replays, duplicates, reorders, and mutates cannot authenticate', async () => {
    const secret = hexToBytes(VECTOR_SECRET);
    const transcript = await resumeTranscript(
      RESUME_AUTH_VERSION,
      VECTOR_TRANSFER_ID,
      VECTOR_FINGERPRINT,
      VECTOR_OFFERER_NONCE,
      VECTOR_JOINER_NONCE,
    );
    // The server recorded every proof of a prior successful exchange.
    const recordedJoinerProof = await resumeJoinerProof(secret, transcript);
    const recordedOffererProof = await resumeOffererProof(secret, transcript);

    // (a) Replay the RECORDED challenge into a FRESH offerer with a fresh nonce: the
    // recorded proof is bound to the old transcript, so verification must fail.
    const freshOfferer = new ResumeAuthSession(
      context('offerer', { nonceSource: fixedNonce(bytesRange(0x60, 0x80)) }),
    );
    freshOfferer.start();
    const recordedChallenge: ResumeMessage = {
      type: RESUME_MSG_CHALLENGE,
      version: 1,
      role: 'joiner',
      nonce: bytesToBase64url(VECTOR_JOINER_NONCE),
      proof: bytesToBase64url(recordedJoinerProof),
    };
    await expect(freshOfferer.handle(encodeResumeMessage(recordedChallenge))).rejects.toThrow(
      /verification failed/,
    );

    // (b) Fake peer (offerer side): the server starts an offerer session WITHOUT the
    // secret, forwards its init to a real joiner, then mutates the real joiner's valid
    // challenge before relaying it — the real offerer must refuse.
    const fakeOfferer = new ResumeAuthSession(
      context('offerer', {
        resumeSecret: randomBytes(RESUME_SECRET_BYTES),
        nonceSource: fixedNonce(bytesRange(0x70, 0x90)),
      }),
    );
    const fakeInit = fakeOfferer.start();
    const realJoiner = new ResumeAuthSession(context('joiner'));
    const realChallenge = await realJoiner.handle(encodeResumeMessage(fakeInit));
    const mutatedChallenge = {
      ...realChallenge.out!,
      proof: bytesToBase64url(randomBytes(RESUME_PROOF_BYTES)),
    };
    const realOfferer = new ResumeAuthSession(
      context('offerer', { nonceSource: fixedNonce(bytesRange(0x70, 0x90)) }),
    );
    realOfferer.start();
    await expect(realOfferer.handle(encodeResumeMessage(mutatedChallenge))).rejects.toThrow(
      /verification failed/,
    );

    // (c) The server's fake offerer cannot even answer the real joiner's VALID challenge:
    // without the secret, its verification of the joiner proof fails and no confirm is ever
    // produced — an authenticating server must possess the transfer credential.
    await expect(fakeOfferer.handle(encodeResumeMessage(realChallenge.out!))).rejects.toThrow(
      /verification failed/,
    );

    // (d) Fake peer (joiner side): replay the recorded offerer proof (over the OLD
    // transcript) as a confirm for a real joiner whose transcript differs — must fail.
    const freshJoiner = new ResumeAuthSession(
      context('joiner', { nonceSource: fixedNonce(bytesRange(0xb0, 0xd0)) }),
    );
    void (await freshJoiner.handle(
      encodeResumeMessage({
        type: RESUME_MSG_INIT,
        version: 1,
        role: 'offerer',
        nonce: bytesToBase64url(bytesRange(0xa0, 0xc0)),
      }),
    ));
    const forgedConfirm: ResumeMessage = {
      type: RESUME_MSG_CONFIRM,
      version: 1,
      role: 'offerer',
      proof: bytesToBase64url(recordedOffererProof),
    };
    await expect(freshJoiner.handle(encodeResumeMessage(forgedConfirm))).rejects.toThrow(
      /verification failed/,
    );

    // (e) Reordering fails closed: a confirm before any init is impossible, and a peer that
    // drops every message simply never produces a result.
    const reorderOfferer = new ResumeAuthSession(context('offerer'));
    await expect(reorderOfferer.handle(encodeResumeMessage(forgedConfirm))).rejects.toThrow(
      /unexpected/,
    );
  });

  it('an old recorded handshake cannot replay the entire old session', async () => {
    // A full recorded exchange is replayed into a fresh session with a fresh nonce.
    const freshJoiner = new ResumeAuthSession(
      context('joiner', { nonceSource: fixedNonce(bytesRange(0xb0, 0xd0)) }),
    );
    const recordedInit = encodeResumeMessage({
      type: RESUME_MSG_INIT,
      version: 1,
      role: 'offerer',
      nonce: bytesToBase64url(VECTOR_OFFERER_NONCE),
    });
    const challenge = await freshJoiner.handle(recordedInit);
    // The fresh joiner's challenge is bound to ITS fresh nonce; the recorded offerer proof
    // (over the old transcript) cannot answer it.
    const recordedConfirm = encodeResumeMessage({
      type: RESUME_MSG_CONFIRM,
      version: 1,
      role: 'offerer',
      proof: bytesToBase64url(
        hexToBytes('242741b571d18f94f68013787b2b0c023023ddff7df27280309096c95a5465b4'),
      ),
    });
    await expect(freshJoiner.handle(recordedConfirm)).rejects.toThrow(/verification failed/);
    void challenge;
  });
});

describe('resume-auth capability negotiation', () => {
  it('negotiates only when BOTH peers advertise resume-auth-v1', () => {
    expect(negotiateResumeAuth([RESUME_AUTH_CAPABILITY], [RESUME_AUTH_CAPABILITY])).toBe(true);
    expect(negotiateResumeAuth([RESUME_AUTH_CAPABILITY], ['folders'])).toBe(false);
    expect(negotiateResumeAuth(['folders'], [RESUME_AUTH_CAPABILITY])).toBe(false);
    expect(negotiateResumeAuth([], [])).toBe(false);
    // Stripping the capability (a malicious server) makes resume unavailable, never
    // unauthenticated: the negotiation result is the gate.
    expect(negotiateResumeAuth(['folders'], ['folders'])).toBe(false);
  });
});

function bytesToBase64url(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
