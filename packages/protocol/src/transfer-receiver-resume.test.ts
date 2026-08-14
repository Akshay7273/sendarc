import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { deriveTransferKeys } from './keyschedule.js';
import { open, seal, type FrameHeaderInput } from './aead.js';
import { FrameType, type Manifest } from './transfer.js';
import { FRAME_VERSION } from './constants.js';
import { decodeControl, encodeControl } from './transfer-messages.js';
import { bytesToHex } from './bytes.js';
import { sha256 } from './webcrypto.js';
import { MemorySink, type Digest } from './transfer-ports.js';
import { TransferReceiver, type ReceiverResumeState } from './transfer-receiver.js';
import { manifestFingerprint } from './journal.js';

function nodeDigest(): Digest {
  const h = createHash('sha256');
  return { update: (b) => void h.update(b), hexDigest: () => h.digest('hex') };
}
const master = new Uint8Array(32).fill(9);
const ID = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

async function build(keys: Awaited<ReturnType<typeof deriveTransferKeys>>) {
  let ctr = 0;
  const frames: Uint8Array[] = [];
  const push = async (header: FrameHeaderInput, payload: Uint8Array) => {
    frames.push(await seal(keys.o2j, ctr++, header, payload));
  };
  const ctrl = (type: FrameType, msg: Parameters<typeof encodeControl>[0]) =>
    push(
      { version: FRAME_VERSION, type, flags: 0, fileIdx: 0, blockIdx: 0, frameOff: 0 },
      encodeControl(msg),
    );
  return { frames, push, ctrl };
}

async function expectedManifest(): Promise<Manifest> {
  return {
    type: FrameType.Manifest,
    transferId: ID,
    files: [
      {
        idx: 0,
        name: 'f',
        size: 20,
        mime: '',
        lastModified: 0,
        blockSize: 8,
        blocks: 3,
        fileDigest: createHash('sha256').update(new Uint8Array(20)).digest('hex'),
      },
    ],
    totalSize: 20,
  };
}

async function streamFile(b: Awaited<ReturnType<typeof build>>, data: Uint8Array): Promise<void> {
  for (let blk = 0; blk * 8 < data.length; blk++) {
    const start = blk * 8;
    const end = Math.min(start + 8, data.length);
    const block = data.subarray(start, end);
    for (let off = 0; off < block.length; off += 4) {
      const frag = block.subarray(off, Math.min(off + 4, block.length));
      const last = off + frag.length === block.length;
      await b.push(
        {
          version: FRAME_VERSION,
          type: FrameType.BlockData,
          flags: last ? 1 : 0,
          fileIdx: 0,
          blockIdx: blk,
          frameOff: off,
        },
        frag,
      );
    }
    await b.ctrl(FrameType.BlockHash, {
      type: FrameType.BlockHash,
      fileIdx: 0,
      blockIdx: blk,
      sha256: bytesToHex(await sha256(block)),
    });
  }
}

async function runReceiver(
  manifest: Manifest,
  stream: boolean,
  resume: ReceiverResumeState | undefined,
  complete = true,
): Promise<{
  result: Awaited<ReturnType<TransferReceiver['done']['then']>> | undefined;
  err: unknown;
  back: Parameters<typeof decodeControl>[0][];
}> {
  const keys = await deriveTransferKeys(master);
  const b = await build(keys);
  await b.ctrl(FrameType.Manifest, manifest);
  if (stream) {
    await streamFile(b, new Uint8Array(20));
  }
  if (complete) {
    await b.ctrl(FrameType.Complete, {
      type: FrameType.Complete,
      fileDigest: manifest.files[0]!.fileDigest,
    });
  }
  const sink = new MemorySink();
  const backChannel: Uint8Array[] = [];
  const receiver = new TransferReceiver({
    send: (f) => void backChannel.push(f),
    sendDir: keys.j2o,
    recvDir: keys.o2j,
    sendCounterStart: 0,
    recvCounterStart: 0,
    createDigest: nodeDigest,
    sink,
    resume,
  });
  for (const f of b.frames) receiver.handle(f);
  let result: Awaited<ReturnType<TransferReceiver['done']['then']>> | undefined;
  let err: unknown;
  try {
    result = await receiver.done;
  } catch (e) {
    err = e;
  }
  const back: Parameters<typeof decodeControl>[0][] = [];
  let c = 0;
  for (const f of backChannel) {
    const o = await open(keys.j2o, c++, f);
    back.push(decodeControl(o.plaintext));
  }
  return { result, err, back };
}

describe('TransferReceiver resume validation (V13-PR06)', () => {
  it('fails closed on bad resume seeds without advertising any resume_state', async () => {
    const manifest = await expectedManifest();
    const fp = await manifestFingerprint(manifest);
    const base = (mutate: (r: ReceiverResumeState) => void): ReceiverResumeState => {
      const r: ReceiverResumeState = {
        transferId: ID,
        manifestFingerprint: fp,
        files: new Map([[0, { haveBlocks: 0, seedDigest: nodeDigest() }]]),
      };
      mutate(r);
      return r;
    };
    const cases: { name: string; resume: ReceiverResumeState; want: RegExp }[] = [
      {
        name: 'uppercase fingerprint',
        resume: base((r) => (r.manifestFingerprint = r.manifestFingerprint.toUpperCase())),
        want: /resume seed manifestFingerprint must be 64 lowercase hex characters/,
      },
      {
        name: 'short fingerprint',
        resume: base((r) => (r.manifestFingerprint = fp.slice(0, 10))),
        want: /resume seed manifestFingerprint must be 64 lowercase hex characters/,
      },
      {
        name: 'wrong fingerprint',
        resume: base((r) => (r.manifestFingerprint = '0'.repeat(64))),
        want: /resume seed manifest fingerprint does not match the authenticated manifest/,
      },
      {
        name: 'empty file set',
        resume: base((r) => (r.files = new Map())),
        want: /resume seed covers 0 files, manifest has 1/,
      },
      {
        name: 'haveBlocks above blocks',
        resume: base(
          (r) => (r.files = new Map([[0, { haveBlocks: 4, seedDigest: nodeDigest() }]])),
        ),
        want: /resume seed haveBlocks 4 out of range for file 0 \(blocks 3\)/,
      },
    ];
    for (const c of cases) {
      const { err, back } = await runReceiver(manifest, false, c.resume);
      expect(err, c.name).toBeInstanceOf(Error);
      expect(String((err as Error).message), c.name).toMatch(c.want);
      expect((err as Error).message).toMatch(/sink_error/);
      // The only back-channel frame is the terminal fail; no resume_state was advertised.
      expect(back.length, c.name).toBe(1);
      expect(back[0]!.type, c.name).toBe(FrameType.Fail);
    }
  });

  it('advertises a fingerprint-bound resume_state and streams only the missing blocks', async () => {
    const manifest = await expectedManifest();
    const fp = await manifestFingerprint(manifest);
    const prefix = new Uint8Array(16);
    const seed = nodeDigest();
    seed.update(prefix);
    const { err, back } = await runReceiver(manifest, true, {
      transferId: ID,
      manifestFingerprint: fp,
      files: new Map([[0, { haveBlocks: 2, seedDigest: seed }]]),
    });
    expect(err).toBeUndefined();
    expect(back.length).toBe(5); // resume_state, ack ×3, done
    const rs = back[0] as Extract<(typeof back)[number], { type: FrameType.ResumeState }>;
    expect(rs.type).toBe(FrameType.ResumeState);
    expect(rs.manifestFingerprint).toBe(fp);
    expect(rs.files).toEqual([{ idx: 0, haveBlocks: 2 }]);
    expect(back[back.length - 1]!.type).toBe(FrameType.Done);
  });

  it('ignores a resume seed for a different transfer (fresh all-zero resume_state)', async () => {
    const manifest = await expectedManifest();
    const staleSeed = nodeDigest();
    staleSeed.update(new Uint8Array(8));
    const { err, back } = await runReceiver(manifest, true, {
      transferId: 'b'.repeat(32),
      manifestFingerprint: '0'.repeat(64),
      files: new Map([[0, { haveBlocks: 2, seedDigest: staleSeed }]]),
    });
    expect(err).toBeUndefined();
    const rs = back[0] as Extract<(typeof back)[number], { type: FrameType.ResumeState }>;
    expect(rs.files).toEqual([{ idx: 0, haveBlocks: 0 }]);
  });

  it('re-answers an identical resume_state on a duplicate manifest and rejects a different one', async () => {
    const manifest = await expectedManifest();
    const fp = await manifestFingerprint(manifest);
    const seed = nodeDigest();
    seed.update(new Uint8Array(8));

    // Identical duplicate manifest → identical resume_state both times.
    {
      const keys = await deriveTransferKeys(master);
      const b = await build(keys);
      await b.ctrl(FrameType.Manifest, manifest);
      await b.ctrl(FrameType.Manifest, manifest);
      await streamFile(b, new Uint8Array(20));
      await b.ctrl(FrameType.Complete, {
        type: FrameType.Complete,
        fileDigest: manifest.files[0]!.fileDigest,
      });
      const sink = new MemorySink();
      const backChannel: Uint8Array[] = [];
      const receiver = new TransferReceiver({
        send: (f) => void backChannel.push(f),
        sendDir: keys.j2o,
        recvDir: keys.o2j,
        sendCounterStart: 0,
        recvCounterStart: 0,
        createDigest: nodeDigest,
        sink,
        resume: {
          transferId: ID,
          manifestFingerprint: fp,
          files: new Map([[0, { haveBlocks: 1, seedDigest: seed }]]),
        },
      });
      for (const f of b.frames) receiver.handle(f);
      await receiver.done;
      const backs: Parameters<typeof decodeControl>[0][] = [];
      let c = 0;
      for (const f of backChannel)
        backs.push(decodeControl((await open(keys.j2o, c++, f)).plaintext));
      const first = backs[0] as Extract<(typeof backs)[number], { type: FrameType.ResumeState }>;
      const second = backs[1] as Extract<(typeof backs)[number], { type: FrameType.ResumeState }>;
      expect(first.type).toBe(FrameType.ResumeState);
      expect(second).toEqual(first);
    }

    // A different manifest after the first was applied is a protocol violation.
    {
      const other: Manifest = {
        ...manifest,
        files: [
          {
            ...manifest.files[0]!,
            size: 40,
            blocks: 5,
            fileDigest: createHash('sha256').update(new Uint8Array(40)).digest('hex'),
          },
        ],
        totalSize: 40,
      };
      const keys = await deriveTransferKeys(master);
      const b = await build(keys);
      await b.ctrl(FrameType.Manifest, manifest);
      await b.ctrl(FrameType.Manifest, other);
      const sink = new MemorySink();
      const backChannel: Uint8Array[] = [];
      const receiver = new TransferReceiver({
        send: (f) => void backChannel.push(f),
        sendDir: keys.j2o,
        recvDir: keys.o2j,
        sendCounterStart: 0,
        recvCounterStart: 0,
        createDigest: nodeDigest,
        sink,
        resume: {
          transferId: ID,
          manifestFingerprint: fp,
          files: new Map([[0, { haveBlocks: 1, seedDigest: seed }]]),
        },
      });
      for (const f of b.frames) receiver.handle(f);
      await expect(receiver.done).rejects.toThrow(/duplicate manifest/);
    }
  });

  it('settles immediately when the seed already holds the whole file', async () => {
    const manifest = await expectedManifest();
    const fp = await manifestFingerprint(manifest);
    const seed = nodeDigest();
    seed.update(new Uint8Array(20));
    const { err, back } = await runReceiver(manifest, false, {
      transferId: ID,
      manifestFingerprint: fp,
      files: new Map([[0, { haveBlocks: 3, seedDigest: seed }]]),
    });
    expect(err).toBeUndefined();
    expect(back.length).toBe(2); // resume_state, done
    const rs = back[0] as Extract<(typeof back)[number], { type: FrameType.ResumeState }>;
    expect(rs.files).toEqual([{ idx: 0, haveBlocks: 3 }]);
    expect(back[1]!.type).toBe(FrameType.Done);
  });
});
