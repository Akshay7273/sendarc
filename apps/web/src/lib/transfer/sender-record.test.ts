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
  it('builds a schema-v1 record from a manifest with a self-verifying checksum', async () => {
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
    await tamper((r) => (r.schemaVersion = 2 as 1), 'future schema version');
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
});
