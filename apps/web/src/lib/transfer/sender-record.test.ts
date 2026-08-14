import { describe, expect, it } from 'vitest';
import { FrameType, manifestFingerprint, type Manifest } from '@sendbeam/protocol';
import {
  memorySenderRecordStore,
  newSenderRecord,
  refreshSenderRecord,
  senderRecordChecksum,
  SENDER_SCHEMA_VERSION,
  validateSenderRecord,
  type SenderRecord,
} from './sender-record.js';

function testManifest(overrides: Partial<Manifest> = {}): Manifest {
  return {
    type: FrameType.Manifest,
    transferId: 'ab'.repeat(16),
    files: [
      {
        idx: 0,
        name: 'folder/a.bin',
        size: 3,
        mime: 'application/octet-stream',
        lastModified: 1_700_000_000_000,
        blockSize: 64 * 1024,
        blocks: 1,
        fileDigest: 'c1'.repeat(32),
      },
      {
        idx: 1,
        name: 'folder/empty.txt',
        size: 0,
        mime: 'text/plain',
        lastModified: 1_700_000_000_001,
        blockSize: 64 * 1024,
        blocks: 0,
        fileDigest: 'd2'.repeat(32),
      },
    ],
    totalSize: 3,
    ...overrides,
  };
}

describe('sender-record', () => {
  it('builds a schema-v2 record from a manifest with a self-verifying checksum', async () => {
    const manifest = testManifest();
    const record = await newSenderRecord(manifest, { kind: 'reselection' }, 1_234);
    expect(record.schemaVersion).toBe(SENDER_SCHEMA_VERSION);
    expect(record.transferId).toBe(manifest.transferId);
    expect(record.manifestFingerprint).toBe(await manifestFingerprint(manifest));
    expect(record.createdAt).toBe(1_234);
    expect(record.updatedAt).toBe(1_234);
    expect(record.files).toEqual([
      {
        name: 'folder/a.bin',
        size: 3,
        mime: 'application/octet-stream',
        lastModified: 1_700_000_000_000,
      },
      { name: 'folder/empty.txt', size: 0, mime: 'text/plain', lastModified: 1_700_000_000_001 },
    ]);
    expect(record.checksum).toMatch(/^[0-9a-f]{64}$/);
    await expect(validateSenderRecord(record)).resolves.toBe(record);
  });

  it('round-trips through the store, including a persisted handle reattachment', async () => {
    const store = memorySenderRecordStore();
    const manifest = testManifest();
    const handle = { kind: 'directory', name: 'photos' } as unknown as FileSystemHandle;
    const record = await newSenderRecord(
      manifest,
      { kind: 'handle', handleKind: 'directory', handle },
      1_234,
    );
    await store.put(record);
    await expect(store.load(manifest.transferId!)).resolves.toEqual({ kind: 'ok', record });
    await store.remove(manifest.transferId!);
    await expect(store.load(manifest.transferId!)).resolves.toEqual({ kind: 'none' });
  });

  it('fails closed on any structural or checksum deviation', async () => {
    const store = memorySenderRecordStore();
    const record = await newSenderRecord(testManifest(), { kind: 'reselection' }, 1_234);

    const tamper = async (mutate: (r: SenderRecord) => void, name: string): Promise<void> => {
      const value = structuredClone(record) as SenderRecord;
      mutate(value);
      await (store as unknown as { entries: Map<string, unknown> }).entries.set(record.transferId, {
        transferId: record.transferId,
        record: value,
      });
      const loaded = await store.load(record.transferId);
      expect(loaded.kind, name).toBe('corrupt');
    };

    await tamper((r) => (r.files[0]!.size = 99), 'changed file size');
    await tamper((r) => (r.checksum = 'f'.repeat(64)), 'stale checksum');
    await tamper(
      (r) => void ((r as unknown as Record<string, unknown>).extra = 'x'),
      'unknown field',
    );
    await tamper((r) => (r.schemaVersion = 3 as 2), 'future schema version');
    await tamper((r) => (r.transferId = 'zz'.repeat(16)), 'non-hex transfer id');
    await tamper((r) => (r.transferId = 'a'.repeat(31)), 'short transfer id');
    await tamper((r) => (r.manifestFingerprint = 'a'.repeat(63)), 'short fingerprint');
    await tamper((r) => (r.protocolVersion = 'sendbeam/2'), 'unsupported protocol version');
    await tamper((r) => (r.files = []), 'empty file set');
    await tamper((r) => void (r.files[0]!.name = ''), 'empty file name');
    await tamper(
      (r) => (r.reattachment = { kind: 'handle', handleKind: 'file', handle: undefined! }),
      'handle reattachment without a handle',
    );
    await tamper(
      (r) =>
        (r.reattachment = {
          kind: 'handle',
          handleKind: 'nope' as 'file',
          handle: {} as FileSystemHandle,
        }),
      'unknown handle kind',
    );
  });

  it('surfaces corrupt records in list() without deleting them', async () => {
    const store = memorySenderRecordStore();
    const good = await newSenderRecord(
      testManifest({ transferId: '11'.repeat(16) }),
      { kind: 'reselection' },
      1,
    );
    const bad = await newSenderRecord(
      testManifest({ transferId: '22'.repeat(16) }),
      { kind: 'reselection' },
      2,
    );
    await store.put(good);
    await (store as unknown as { entries: Map<string, unknown> }).entries.set(bad.transferId, {
      transferId: bad.transferId,
      record: { ...structuredClone(bad), checksum: '0'.repeat(64) },
    });
    const listed = await store.list();
    expect(listed).toHaveLength(2);
    const badEntry = listed.find((entry) => entry.transferId === bad.transferId)!;
    expect(badEntry.kind).toBe('corrupt');
    const goodEntry = listed.find((entry) => entry.transferId === good.transferId)!;
    expect(goodEntry).toMatchObject({ kind: 'ok' });
  });

  it('refreshes a matching record (updatedAt + newer reattachment) on a verified resume', async () => {
    const manifest = testManifest();
    const prior = await newSenderRecord(manifest, { kind: 'reselection' }, 1_000);
    const refreshed = await refreshSenderRecord(
      prior,
      manifest,
      {
        kind: 'handle',
        handleKind: 'directory',
        handle: { kind: 'directory' } as unknown as FileSystemHandle,
      },
      2_000,
    );
    expect(refreshed.createdAt).toBe(1_000);
    expect(refreshed.updatedAt).toBe(2_000);
    expect(refreshed.manifestFingerprint).toBe(prior.manifestFingerprint);
    expect(refreshed.reattachment).toMatchObject({ kind: 'handle', handleKind: 'directory' });
    expect(refreshed.checksum).toBe(await senderRecordChecksum(refreshed));
    await expect(validateSenderRecord(refreshed)).resolves.toBe(refreshed);
  });

  it('rejects a resume whose canonical source identity changed', async () => {
    const prior = await newSenderRecord(testManifest(), { kind: 'reselection' }, 1_000);
    const changed = testManifest();
    changed.files[0]!.size = 4;
    changed.totalSize = 4;
    await expect(refreshSenderRecord(prior, changed, undefined, 2_000)).rejects.toThrow(
      /does not match interrupted transfer/,
    );
  });

  it('rejects a refresh against a different transfer id', async () => {
    const prior = await newSenderRecord(testManifest(), { kind: 'reselection' }, 1_000);
    const other = testManifest({ transferId: 'ef'.repeat(16) });
    await expect(refreshSenderRecord(prior, other, undefined, 2_000)).rejects.toThrow(
      /belongs to transfer/,
    );
  });

  it('accepts a valid v1 resume-secret envelope and rejects a malformed one', async () => {
    const store = memorySenderRecordStore();
    const manifest = testManifest();
    const record = await newSenderRecord(manifest, { kind: 'reselection' }, 1_234);
    record.resumeSecret = { version: 1, value: 'aa'.repeat(32) };
    record.checksum = await senderRecordChecksum(record);
    await store.put(record);
    await expect(store.load(manifest.transferId!)).resolves.toEqual({ kind: 'ok', record });

    const bad = structuredClone(record) as SenderRecord;
    bad.resumeSecret = { version: 1, value: 'zz'.repeat(32) };
    bad.checksum = await senderRecordChecksum(bad);
    await expect(validateSenderRecord(bad)).rejects.toThrow(/invalid resumeSecret/);

    const wrongLen = structuredClone(record) as SenderRecord;
    wrongLen.resumeSecret = { version: 1, value: 'ab'.repeat(31) };
    wrongLen.checksum = await senderRecordChecksum(wrongLen);
    await expect(validateSenderRecord(wrongLen)).rejects.toThrow(/invalid resumeSecret/);

    const wrongVersion = structuredClone(record) as SenderRecord;
    wrongVersion.resumeSecret = { version: 2, value: 'aa'.repeat(32) };
    wrongVersion.checksum = await senderRecordChecksum(wrongVersion);
    await expect(validateSenderRecord(wrongVersion)).rejects.toThrow(/invalid resumeSecret/);

    // A tampered envelope never survives: the checksum covers it.
    const tampered = structuredClone(record) as SenderRecord;
    tampered.resumeSecret = { version: 1, value: 'bb'.repeat(32) };
    await expect(validateSenderRecord(tampered)).rejects.toThrow(/checksum mismatch/);
  });

  it('migrates a pre-PR07 schema-v1 record with no resume secret and never fabricates one', async () => {
    const store = memorySenderRecordStore();
    const manifest = testManifest();
    const v2 = await newSenderRecord(manifest, { kind: 'reselection' }, 1_234);
    // Rewrite the record exactly as a pre-PR07 v1 build would have stored it: schemaVersion 1
    // with the checksum over the v1 core (the v2 core without the resumeSecret field).
    const legacy = structuredClone(v2) as unknown as Record<string, unknown>;
    delete (legacy as { resumeSecret?: unknown }).resumeSecret;
    legacy.schemaVersion = 1;
    legacy.checksum = '';
    const legacyCore = JSON.stringify({
      schemaVersion: 1,
      transferId: legacy.transferId,
      manifestFingerprint: legacy.manifestFingerprint,
      protocolVersion: legacy.protocolVersion,
      createdAt: legacy.createdAt,
      updatedAt: legacy.updatedAt,
      files: (legacy.files as Array<Record<string, unknown>>).map((f) => ({
        name: f.name,
        size: f.size,
        mime: f.mime,
        lastModified: f.lastModified,
      })),
      reattachment: { kind: 'reselection' },
    });
    const { sha256, bytesToHex, utf8 } = await import('@sendbeam/protocol');
    legacy.checksum = bytesToHex(await sha256(utf8(legacyCore)));
    // The memory store keeps the record itself (structured clone), keyed by transfer id.
    await (store as unknown as { entries: Map<string, unknown> }).entries.set(
      manifest.transferId!,
      legacy,
    );
    const loaded = await store.load(manifest.transferId!);
    expect(loaded.kind).toBe('ok');
    if (loaded.kind !== 'ok') return;
    expect(loaded.record.schemaVersion).toBe(SENDER_SCHEMA_VERSION);
    expect(loaded.record.resumeSecret).toBeUndefined();
    expect(loaded.record.checksum).toBe(await senderRecordChecksum(loaded.record));

    // A tampered v1 body (checksum over the true body) fails closed as corrupt.
    const tamperedLegacy = structuredClone(legacy);
    tamperedLegacy.files = [
      { ...(tamperedLegacy.files as Array<Record<string, unknown>>)[0]!, size: 99 },
    ];
    await (store as unknown as { entries: Map<string, unknown> }).entries.set(
      'ff'.repeat(16),
      tamperedLegacy,
    );
    const tamperedLoad = await store.load('ff'.repeat(16));
    expect(tamperedLoad.kind).toBe('corrupt');
  });
});
