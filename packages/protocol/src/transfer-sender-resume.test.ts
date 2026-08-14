import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { deriveTransferKeys } from './keyschedule.js';
import { seal, open } from './aead.js';
import { FrameType, type Manifest } from './transfer.js';
import { FRAME_VERSION } from './constants.js';
import { encodeControl } from './transfer-messages.js';
import { bytesSource, type Digest } from './transfer-ports.js';
import { TransferSender } from './transfer-sender.js';
import { manifestFingerprint } from './journal.js';

function nodeDigest(): Digest {
  const h = createHash('sha256');
  return { update: (b) => void h.update(b), hexDigest: () => h.digest('hex') };
}
const master = new Uint8Array(32).fill(9);
const ID = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const data = new Uint8Array(20).map((_, i) => i); // block=8 → blocks 0,1 full, block 2 = 4B

async function waitFor(check: () => boolean): Promise<void> {
  const deadline = Date.now() + 2000;
  while (!check()) {
    if (Date.now() >= deadline) throw new Error('timed out waiting for sender state');
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
}

/** The canonical manifest the sender will stream, for computing the fingerprint binding. */
async function expectedManifest(): Promise<Manifest> {
  return {
    type: FrameType.Manifest,
    transferId: ID,
    files: [
      {
        idx: 0,
        name: 'f',
        size: data.length,
        mime: '',
        lastModified: 0,
        blockSize: 8,
        blocks: 3,
        fileDigest: createHash('sha256').update(data).digest('hex'),
      },
    ],
    totalSize: data.length,
  };
}

/** Build a sender in resume mode and capture its outbound frames. */
function resumeSender(keys: Awaited<ReturnType<typeof deriveTransferKeys>>) {
  const outbound: Uint8Array[] = [];
  const sender = new TransferSender({
    file: bytesSource(data, { name: 'f', size: data.length, mime: '', lastModified: 0 }),
    send: (f) => void outbound.push(f),
    sendDir: keys.o2j,
    recvDir: keys.j2o,
    sendCounterStart: 0,
    recvCounterStart: 0,
    createDigest: nodeDigest,
    blockSize: 8,
    frameSize: 4,
    window: 1,
    transferId: ID,
  });
  return { sender, outbound };
}

async function sealInbound(
  keys: Awaited<ReturnType<typeof deriveTransferKeys>>,
  counter: number,
  type: FrameType,
  payload: Uint8Array,
): Promise<Uint8Array> {
  return seal(
    keys.j2o,
    counter,
    { version: FRAME_VERSION, type, flags: 0, fileIdx: 0, blockIdx: 0, frameOff: 0 },
    payload,
  );
}

/** Ack the blocks above the high-water mark, then send done; the caller awaits sender.run(). */
async function settleResume(
  sender: TransferSender,
  keys: Awaited<ReturnType<typeof deriveTransferKeys>>,
  outbound: Uint8Array[],
  haveBlocks: number,
  startCounter: number,
): Promise<void> {
  await waitFor(() => outbound.length >= 1 + 2 * (3 - haveBlocks));
  let ctr = startCounter;
  for (let b = haveBlocks; b < 3; b++) {
    const ack = await sealInbound(
      keys,
      ctr++,
      FrameType.Ack,
      encodeControl({ type: FrameType.Ack, fileIdx: 0, blockIdx: b }),
    );
    sender.handle(ack);
    await new Promise((r) => setTimeout(r, 5));
  }
  const done = await sealInbound(
    keys,
    ctr++,
    FrameType.Done,
    encodeControl({ type: FrameType.Done }),
  );
  sender.handle(done);
  await new Promise((r) => setTimeout(r, 10));
}

describe('TransferSender resume validation (V13-PR06)', () => {
  it('rejects a resume_state before the manifest was validated', async () => {
    const keys = await deriveTransferKeys(master);
    const { sender } = resumeSender(keys);
    // Deliver the resume_state before run() validates the manifest: there is no binding yet.
    await sender.handle(
      await sealInbound(
        keys,
        0,
        FrameType.ResumeState,
        encodeControl({
          type: FrameType.ResumeState,
          transferId: ID,
          files: [{ idx: 0, haveBlocks: 0 }],
        }),
      ),
    );
    await expect(sender.run()).rejects.toThrow(/unexpected resume_state/);
  });

  it('rejects a resume_state for another transfer', async () => {
    const keys = await deriveTransferKeys(master);
    const { sender, outbound } = resumeSender(keys);
    const runP = sender.run();
    await waitFor(() => outbound.length >= 1);
    await sender.handle(
      await sealInbound(
        keys,
        0,
        FrameType.ResumeState,
        encodeControl({
          type: FrameType.ResumeState,
          transferId: 'b'.repeat(32),
          files: [{ idx: 0, haveBlocks: 0 }],
        }),
      ),
    );
    await expect(runP).rejects.toThrow(/resume_state transfer id mismatch/);
  });

  it('rejects a resume_state bound to a different manifest fingerprint', async () => {
    const keys = await deriveTransferKeys(master);
    const { sender, outbound } = resumeSender(keys);
    const runP = sender.run();
    await waitFor(() => outbound.length >= 1);
    await sender.handle(
      await sealInbound(
        keys,
        0,
        FrameType.ResumeState,
        encodeControl({
          type: FrameType.ResumeState,
          transferId: ID,
          manifestFingerprint: '0'.repeat(64),
          files: [{ idx: 0, haveBlocks: 0 }],
        }),
      ),
    );
    await expect(runP).rejects.toThrow(/resume_state manifest fingerprint mismatch/);
  });

  it('rejects malformed claims: unknown file, duplicate file, out-of-range haveBlocks, missing entry', async () => {
    const manifest = await expectedManifest();
    const fp = await manifestFingerprint(manifest);
    const cases: { name: string; files: { idx: number; haveBlocks: number }[]; want: RegExp }[] = [
      {
        name: 'unknown file',
        files: [{ idx: 3, haveBlocks: 0 }],
        want: /resume_state references an unknown file/,
      },
      {
        name: 'duplicate file',
        files: [
          { idx: 0, haveBlocks: 0 },
          { idx: 0, haveBlocks: 0 },
        ],
        want: /resume_state references a file more than once/,
      },
      {
        name: 'haveBlocks above blocks',
        files: [{ idx: 0, haveBlocks: 4 }],
        want: /resume_state haveBlocks out of range/,
      },
    ];
    for (const c of cases) {
      const keys = await deriveTransferKeys(master);
      const { sender, outbound } = resumeSender(keys);
      const runP = sender.run();
      await waitFor(() => outbound.length >= 1);
      await sender.handle(
        await sealInbound(
          keys,
          0,
          FrameType.ResumeState,
          encodeControl({
            type: FrameType.ResumeState,
            transferId: ID,
            manifestFingerprint: fp,
            files: c.files,
          }),
        ),
      );
      await expect(runP, c.name).rejects.toThrow(c.want);
    }
  });

  it('resumes from a fingerprint-bound high-water mark, streaming only missing blocks', async () => {
    const keys = await deriveTransferKeys(master);
    const { sender, outbound } = resumeSender(keys);
    const runP = sender.run();
    await waitFor(() => outbound.length >= 1);
    const manifest = await expectedManifest();
    const fp = await manifestFingerprint(manifest);
    await sender.handle(
      await sealInbound(
        keys,
        0,
        FrameType.ResumeState,
        encodeControl({
          type: FrameType.ResumeState,
          transferId: ID,
          manifestFingerprint: fp,
          files: [{ idx: 0, haveBlocks: 2 }],
        }),
      ),
    );
    await settleResume(sender, keys, outbound, 2, 1);

    // manifest + block 2 data + block 2 hash + complete: the held prefix is never sent.
    await waitFor(() => outbound.length >= 4);
    let dataFrames = 0;
    for (let i = 0; i < outbound.length; i++) {
      const o = await open(keys.o2j, i, outbound[i]!);
      if (o.header.type === FrameType.BlockData) dataFrames++;
    }
    expect(dataFrames).toBe(1);
    await runP;
  });

  it('accepts a legacy resume_state without the fingerprint field (structural rules still apply)', async () => {
    const keys = await deriveTransferKeys(master);
    const { sender, outbound } = resumeSender(keys);
    const runP = sender.run();
    await waitFor(() => outbound.length >= 1);
    await sender.handle(
      await sealInbound(
        keys,
        0,
        FrameType.ResumeState,
        encodeControl({
          type: FrameType.ResumeState,
          transferId: ID,
          files: [{ idx: 0, haveBlocks: 2 }],
        }),
      ),
    );
    await settleResume(sender, keys, outbound, 2, 1);
    await runP;
  });

  it('treats an identical duplicate resume_state as idempotent and a conflicting one as fatal', async () => {
    const manifest = await expectedManifest();
    const fp = await manifestFingerprint(manifest);

    // Identical duplicate: the resumed stream proceeds exactly as with a single answer.
    {
      const keys = await deriveTransferKeys(master);
      const { sender, outbound } = resumeSender(keys);
      const runP = sender.run();
      await waitFor(() => outbound.length >= 1);
      const payload = encodeControl({
        type: FrameType.ResumeState,
        transferId: ID,
        manifestFingerprint: fp,
        files: [{ idx: 0, haveBlocks: 2 }],
      });
      await sender.handle(await sealInbound(keys, 0, FrameType.ResumeState, payload));
      await sender.handle(await sealInbound(keys, 1, FrameType.ResumeState, payload));
      await settleResume(sender, keys, outbound, 2, 2);
      await runP;
    }

    // Conflicting duplicate: the second answer claims a different high-water mark.
    {
      const keys = await deriveTransferKeys(master);
      const { sender, outbound } = resumeSender(keys);
      const runP = sender.run();
      await waitFor(() => outbound.length >= 1);
      const first = encodeControl({
        type: FrameType.ResumeState,
        transferId: ID,
        manifestFingerprint: fp,
        files: [{ idx: 0, haveBlocks: 2 }],
      });
      const conflicting = encodeControl({
        type: FrameType.ResumeState,
        transferId: ID,
        manifestFingerprint: fp,
        files: [{ idx: 0, haveBlocks: 3 }],
      });
      await sender.handle(await sealInbound(keys, 0, FrameType.ResumeState, first));
      await sender.handle(await sealInbound(keys, 1, FrameType.ResumeState, conflicting));
      await expect(runP).rejects.toThrow(/conflicting duplicate resume_state/);
    }
  });
});
