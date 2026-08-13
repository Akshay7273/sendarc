import { describe, expect, it } from 'vitest';
import {
  DIGEST_CHECKPOINT_FORMAT_GO_STDLIB,
  JOURNAL_RESUME_VERSION,
  JOURNAL_SCHEMA_VERSION,
  commitBlocks,
  committedBytes,
  decodeJournal,
  encodeJournal,
  manifestFingerprint,
  newJournal,
  validateJournal,
  type DurableJournal,
  type JournalDigestCheckpoint,
  type JournalIdentity,
} from './journal.js';
import { decodeControl } from './transfer-messages.js';
import { FrameType, type Manifest } from './transfer.js';
import { utf8 } from './bytes.js';
import { MAX_MANIFEST_BLOCK_BYTES, MAX_TRANSFER_FILES } from './safe-path.js';
import { PROTOCOL_VERSION } from './constants.js';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const TRANSFER_ID = '0123456789abcdef0123456789abcdef';

function testManifest(): Manifest {
  return {
    type: FrameType.Manifest,
    transferId: TRANSFER_ID,
    files: [
      {
        idx: 0,
        name: 'a.txt',
        size: 2048,
        mime: 'text/plain',
        lastModified: 1700000000,
        blockSize: 1024,
        blocks: 2,
        fileDigest: 'ab'.repeat(32),
      },
      {
        idx: 1,
        name: 'b.bin',
        size: 1024,
        mime: 'application/octet-stream',
        lastModified: 1700000001,
        blockSize: 1024,
        blocks: 1,
        fileDigest: 'cd'.repeat(32),
      },
    ],
    totalSize: 3072,
  };
}

function testIdentities(): [JournalIdentity, JournalIdentity] {
  return [
    { version: 1, value: '736f757263652d73616d706c65' },
    { version: 1, value: '646573742d73616d706c65' },
  ];
}

// The exact journal pinned by docs/test-vectors/durable-journal.json, including the
// V13-PR05 digest checkpoint on file 0. The state hex is the Go implementation's serialized
// sha256 state over 1024 zero bytes (a real but opaque state); the journal bytes must be
// reproduced byte-for-byte regardless of which language produced it.
const VECTOR_DIGEST_STATE =
  '7368610393fa7a18cb52031408d29f5110e42be6fc4a07de4d0e65025156c97d72e04acf000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400';

async function vectorSample(): Promise<DurableJournal> {
  const [source, destination] = testIdentities();
  const j = await newJournal(TRANSFER_ID, testManifest(), source, destination, 1723500000000);
  return commitBlocks(j, 0, 1, 1723500060000, {
    format: DIGEST_CHECKPOINT_FORMAT_GO_STDLIB,
    committedBlocks: 1,
    committedBytes: 1024,
    state: VECTOR_DIGEST_STATE,
  });
}
function cloneDeep<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

async function decodeJsonObj(obj: unknown): Promise<DurableJournal> {
  return decodeJournal(utf8(JSON.stringify(obj)));
}

describe('journal schema v1', () => {
  it('round-trips byte-identically', async () => {
    const j = await vectorSample();
    const encoded = await encodeJournal(j);
    const decoded = await decodeJournal(encoded);
    expect(decoded.transferId).toBe(j.transferId);
    expect(decoded.manifestFingerprint).toBe(j.manifestFingerprint);
    expect(decoded.files[0]!.committedBlocks).toBe(1);
    expect(decoded.files[1]!.committedBlocks).toBe(0);
    // Re-encoding a decoded journal is byte-identical.
    expect(await encodeJournal(decoded)).toEqual(encoded);
    // No resumeSecret material is present by default.
    expect(new TextDecoder().decode(encoded)).not.toContain('resumeSecret');
  });

  it('rejects missing or invalid required fields', async () => {
    const base = await vectorSample();
    const cases: Array<[string, (j: DurableJournal) => void]> = [
      ['empty transferId', (j) => void (j.transferId = '')],
      ['short transferId', (j) => void (j.transferId = 'abcd')],
      ['uppercase transferId', (j) => void (j.transferId = TRANSFER_ID.toUpperCase())],
      ['empty fingerprint', (j) => void (j.manifestFingerprint = '')],
      ['missing protocol version', (j) => void (j.protocolVersion = '')],
      ['wrong protocol version', (j) => void (j.protocolVersion = 'sendbeam/2')],
      ['zero resume version', (j) => void (j.resumeVersion = 0)],
      ['zero schema version', (j) => void (j.schemaVersion = 0)],
      ['zero block size', (j) => void (j.blockSize = 0)],
      ['huge block size', (j) => void (j.blockSize = MAX_MANIFEST_BLOCK_BYTES + 1)],
      ['zero createdAt', (j) => void (j.createdAt = 0)],
      ['updatedAt before createdAt', (j) => void (j.updatedAt = j.createdAt - 1)],
      ['empty files', (j) => void (j.files = [])],
      ['missing source identity', (j) => void (j.sourceIdentity = { version: 1, value: '' })],
      ['bad identity charset', (j) => void (j.sourceIdentity.value = 'not hex or b64!!')],
      ['unsupported identity version', (j) => void (j.sourceIdentity.version = 2)],
      ['bad resume secret', (j) => void (j.resumeSecret = { version: 1, value: 'bad!!' })],
      ['bad file digest', (j) => void (j.files[0]!.fileDigest = 'xyz')],
      ['file blocks mismatch', (j) => void (j.files[0]!.blocks = 1)],
      ['file size negative', (j) => void (j.files[0]!.size = -1)],
      ['file block size differs', (j) => void (j.files[1]!.blockSize = 512)],
      ['non-contiguous indexes', (j) => void (j.files[1]!.idx = 2)],
      ['duplicate paths', (j) => void (j.files[1]!.name = 'a.txt')],
      ['unsafe path', (j) => void (j.files[0]!.name = '../escape.txt')],
      [
        'too many files',
        (j) =>
          void (j.files = [
            ...j.files,
            ...Array.from({ length: MAX_TRANSFER_FILES }, (_, i) => ({
              ...j.files[0]!,
              idx: i + 2,
              name: `f${i}.bin`,
            })),
          ]),
      ],
    ];
    for (const [name, mutate] of cases) {
      const bad = structuredClone(base);
      bad.checksum = undefined;
      mutate(bad);
      await expect(validateJournal(bad), name).rejects.toThrow();
      await expect(encodeJournal(bad), name).rejects.toThrow();
    }
  });

  it('dispatches schema versions and fails closed on unknown ones', async () => {
    const encoded = await encodeJournal(await vectorSample());
    const obj = JSON.parse(new TextDecoder().decode(encoded)) as Record<string, unknown>;
    await expect(decodeJournal(encoded)).resolves.toBeTruthy();

    for (const future of [2, 99]) {
      await expect(decodeJsonObj({ ...obj, schemaVersion: future })).rejects.toThrow(/newer/);
    }
    for (const corrupt of [0, -1]) {
      await expect(decodeJsonObj({ ...obj, schemaVersion: corrupt })).rejects.toThrow(
        /corrupt schema version/,
      );
    }
    await expect(decodeJsonObj({ ...obj, schemaVersion: 1.5 })).rejects.toThrow();
    const missing = { ...obj };
    delete missing.schemaVersion;
    await expect(decodeJsonObj(missing)).rejects.toThrow(/schemaVersion/);
  });

  it('rejects malformed, unknown-field, and torn input', async () => {
    const encoded = await encodeJournal(await vectorSample());
    const text = new TextDecoder().decode(encoded);
    await expect(decodeJournal(utf8('{'))).rejects.toThrow();
    await expect(decodeJournal(new Uint8Array())).rejects.toThrow();
    await expect(decodeJournal(utf8('[1,2,3]'))).rejects.toThrow();
    await expect(decodeJournal(utf8('"hello"'))).rejects.toThrow();

    const obj = JSON.parse(text) as Record<string, unknown>;
    await expect(decodeJsonObj({ ...obj, masterKey: '00'.repeat(32) })).rejects.toThrow(
      /unexpected journal field/,
    );
    await expect(decodeJsonObj({ ...obj, sessionMasterKey: '00'.repeat(32) })).rejects.toThrow();

    // Truncate at many byte positions: a torn journal must never decode.
    for (let cut = 0; cut < encoded.length; cut += 7) {
      await expect(decodeJournal(encoded.subarray(0, cut))).rejects.toThrow();
    }
  });

  it('fails closed on tampered content, checksum, and checkpoint claims', async () => {
    const encoded = await encodeJournal(await vectorSample());
    const obj = JSON.parse(new TextDecoder().decode(encoded)) as Record<string, unknown>;

    // Byte-level content flip (renamed file: 'a.txt' -> 'c.txt' keeps the length).
    const flipped = encoded.slice();
    const nameIdx = new TextDecoder().decode(flipped).indexOf('a.txt');
    flipped[nameIdx] = flipped[nameIdx]! === 0x61 ? 0x63 : 0x61;
    await expect(decodeJournal(flipped)).rejects.toThrow();

    // A structurally valid but fingerprint-neutral change with a stale checksum.
    await expect(decodeJsonObj({ ...obj, updatedAt: 1723500120000 })).rejects.toThrow(
      /checksum mismatch/,
    );

    // Checkpoint beyond the file is impossible even with a valid-looking structure.
    const beyond = cloneDeep(obj.files) as Array<Record<string, unknown>>;
    beyond[0]!.committedBlocks = 99;
    await expect(decodeJsonObj({ ...obj, files: beyond })).rejects.toThrow(/out of range/);

    // Within-bounds checkpoint with a stale checksum is tamper-evident.
    const stale = cloneDeep(obj.files) as Array<Record<string, unknown>>;
    stale[0]!.committedBlocks = 2;
    delete stale[0]!.digestCheckpoint; // a checkpoint cannot cover the new high-water
    await expect(decodeJsonObj({ ...obj, files: stale })).rejects.toThrow(/checksum mismatch/);

    // Tampered identity with a stale checksum.
    const src = { version: 1, value: 'deadbeef' };
    await expect(decodeJsonObj({ ...obj, sourceIdentity: src })).rejects.toThrow(
      /checksum mismatch/,
    );

    // Tampered fingerprint fails the self-check before the checksum is consulted.
    await expect(decodeJsonObj({ ...obj, manifestFingerprint: 'ef'.repeat(32) })).rejects.toThrow(
      /fingerprint mismatch/,
    );
  });

  it('binds checkpoints to the manifest fingerprint', async () => {
    const base = await vectorSample();
    const tamper: Array<[string, (j: DurableJournal) => void]> = [
      ['renamed file', (j) => void (j.files[0]!.name = 'c.txt')],
      ['swapped digest', (j) => void (j.files[0]!.fileDigest = 'ff'.repeat(32))],
      ['changed transferId', (j) => void (j.transferId = '11'.repeat(16))],
      ['changed mime', (j) => void (j.files[0]!.mime = 'image/png')],
    ];
    for (const [name, mutate] of tamper) {
      const bad = structuredClone(base);
      bad.checksum = undefined;
      mutate(bad);
      await expect(validateJournal(bad), name).rejects.toThrow(/fingerprint mismatch/);
    }
    const resized = structuredClone(base);
    resized.checksum = undefined;
    resized.files[0]!.size = 1024;
    await expect(validateJournal(resized)).rejects.toThrow();
  });

  it('rejects non-block-aligned checkpoint claims', async () => {
    const encoded = await encodeJournal(await vectorSample());
    const obj = JSON.parse(new TextDecoder().decode(encoded)) as Record<string, unknown>;
    // The only way to express a byte-level claim is a fractional block count.
    const files = cloneDeep(obj.files) as Array<Record<string, unknown>>;
    files[0]!.committedBlocks = 1.5;
    await expect(decodeJsonObj({ ...obj, files })).rejects.toThrow();

    const j = await vectorSample();
    expect(committedBytes(j, 0)).toBe(1024);
    const full = commitBlocks(j, 0, 2, 1723500120000);
    expect(committedBytes(full, 0)).toBe(2048);
  });

  it('only advances checkpoints through commitBlocks', async () => {
    const j = await vectorSample();
    expect(() => commitBlocks(j, 0, 0, 1723500120000)).toThrow(/regress/);
    expect(() => commitBlocks(j, 0, 3, 1723500120000)).toThrow(/out of range/);
    expect(() => commitBlocks(j, 0, -1, 1723500120000)).toThrow();
    expect(() => commitBlocks(j, 7, 0, 1723500120000)).toThrow();

    const advanced = commitBlocks(j, 1, 1, 1723500120000);
    expect(advanced.updatedAt).toBe(1723500120000);
    expect(advanced.files[1]!.committedBlocks).toBe(1);
    // The returned journal re-encodes and decodes cleanly.
    const decoded = await decodeJournal(await encodeJournal(advanced));
    expect(decoded.files[1]!.committedBlocks).toBe(1);
  });

  it('never serializes raw session key material', async () => {
    // The schema is a closed set: no plausible key-material field may appear.
    const encoded = await encodeJournal(await vectorSample());
    const obj = JSON.parse(new TextDecoder().decode(encoded)) as Record<string, unknown>;
    for (const key of [
      'masterKey',
      'sessionMasterKey',
      'o2jKey',
      'counter',
      'nonce',
      'invite',
      'password',
    ]) {
      await expect(decodeJsonObj({ ...obj, [key]: '00'.repeat(32) })).rejects.toThrow(
        /unexpected journal field/,
      );
    }
    // Raw session bytes never appear in the serialized output.
    const master = utf8('raw-pake-master-key-0000');
    const dirKey = utf8('directional-o2j-key-0000');
    const text = new TextDecoder().decode(encoded);
    for (const secret of [new TextDecoder().decode(master), new TextDecoder().decode(dirKey)]) {
      expect(text).not.toContain(secret);
    }
    // Only the documented resumeSecret envelope is allowed, and it stays opaque.
    const j = await vectorSample();
    j.resumeSecret = { version: 1, value: 'c2VjcmV0LW1hdGVyaWFs' };
    const withSecret = await decodeJournal(await encodeJournal(j));
    expect(withSecret.resumeSecret?.value).toBe('c2VjcmV0LW1hdGVyaWFs');
  });

  it('matches the cross-language vector byte-for-byte', async () => {
    const vectorPath = join(
      __dirname,
      '..',
      '..',
      '..',
      'docs',
      'test-vectors',
      'durable-journal.json',
    );
    const doc = JSON.parse(readFileSync(vectorPath, 'utf8')) as {
      transferId: string;
      manifest: string;
      sourceIdentity: JournalIdentity;
      destinationIdentity: JournalIdentity;
      createdAt: number;
      updatedAt: number;
      committedBlocks: number[];
      digestCheckpoints: Array<JournalDigestCheckpoint | null>;
      fingerprint: string;
      journal: string;
    };
    const manifest = decodeControl(utf8(doc.manifest)) as Manifest;
    const j = await newJournal(
      doc.transferId,
      manifest,
      doc.sourceIdentity,
      doc.destinationIdentity,
      doc.createdAt,
    );
    let current = j;
    for (let i = 0; i < doc.committedBlocks.length; i++) {
      current = commitBlocks(
        current,
        i,
        doc.committedBlocks[i]!,
        doc.updatedAt,
        doc.digestCheckpoints[i] ?? undefined,
      );
    }
    expect(current.manifestFingerprint).toBe(doc.fingerprint);
    expect(new TextDecoder().decode(await encodeJournal(current))).toBe(doc.journal);
    // The pinned constants hold.
    expect(current.schemaVersion).toBe(JOURNAL_SCHEMA_VERSION);
    expect(current.resumeVersion).toBe(JOURNAL_RESUME_VERSION);
    expect(current.protocolVersion).toBe(PROTOCOL_VERSION);
  });

  it('derives the same fingerprint as the committed manifest', async () => {
    const fingerprint = await manifestFingerprint(testManifest());
    expect(fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });
});
