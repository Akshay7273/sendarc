import { describe, expect, it } from 'vitest';
import {
  canonicalizeFiles,
  cheapSourceCheck,
  ensureReadPermission,
  materializeHandle,
  relName,
} from './sender-reattach.js';
import { newSenderRecord, type SenderRecord } from './sender-record.js';
import { FrameType, type Manifest } from '@sendbeam/protocol';

function manifest(): Manifest {
  return {
    type: FrameType.Manifest,
    transferId: 'ab'.repeat(16),
    files: [
      {
        idx: 0,
        name: 'folder/a.bin',
        size: 3,
        mime: 'application/octet-stream',
        lastModified: 2_000,
        blockSize: 64 * 1024,
        blocks: 1,
        fileDigest: 'd2'.repeat(32),
      },
      {
        idx: 1,
        name: 'folder/b.bin',
        size: 4,
        mime: 'application/octet-stream',
        lastModified: 1_000,
        blockSize: 64 * 1024,
        blocks: 1,
        fileDigest: 'c1'.repeat(32),
      },
    ],
    totalSize: 7,
  };
}

describe('sender-reattach', () => {
  it('uses webkitRelativePath as the canonical rel name when present', () => {
    const file = new File(['x'], 'a.bin');
    Object.defineProperty(file, 'webkitRelativePath', { value: 'folder/a.bin' });
    expect(relName(file)).toBe('folder/a.bin');
    expect(relName(new File(['x'], 'plain.bin'))).toBe('plain.bin');
  });

  it('sorts any selection into canonical relative order', () => {
    const late = new File(['b'], 'b.bin');
    Object.defineProperty(late, 'webkitRelativePath', { value: 'z/late.bin' });
    const early = new File(['a'], 'a.bin');
    Object.defineProperty(early, 'webkitRelativePath', { value: 'a/early.bin' });
    const mid = new File(['c'], 'c.bin');
    Object.defineProperty(mid, 'webkitRelativePath', { value: 'm/mid.bin' });
    expect(canonicalizeFiles([late, mid, early]).map(relName)).toEqual([
      'a/early.bin',
      'm/mid.bin',
      'z/late.bin',
    ]);
    // The input array is not mutated.
    expect([late, mid, early].map(relName)).toEqual(['z/late.bin', 'm/mid.bin', 'a/early.bin']);
  });

  it('materializes a file handle into a canonical File whose name is its relative path', async () => {
    const bytes = new Uint8Array([1, 2, 3]);
    const handle: FileSystemFileHandle = {
      kind: 'file',
      name: 'photo.jpg',
      getFile: async () =>
        new File([bytes], 'photo.jpg', { type: 'image/jpeg', lastModified: 7_000 }),
    } as FileSystemFileHandle;
    const files = await materializeHandle(handle);
    expect(files).toHaveLength(1);
    expect(relName(files[0]!)).toBe('photo.jpg');
    expect(files[0]!.size).toBe(3);
    expect(files[0]!.type).toBe('image/jpeg');
    expect(files[0]!.lastModified).toBe(7_000);
    expect(new Uint8Array(await files[0]!.arrayBuffer())).toEqual(bytes);
  });

  it('materializes a directory handle recursively, in canonical order', async () => {
    const dirEntries = new Map<string, FileSystemHandle>([
      [
        'z.txt',
        {
          kind: 'file',
          name: 'z.txt',
          getFile: async () => new File(['z'], 'z.txt'),
        } as unknown as FileSystemFileHandle,
      ],
      [
        'sub',
        {
          kind: 'directory',
          name: 'sub',
          entries: async function* entries(): AsyncGenerator<[string, FileSystemHandle]> {
            yield [
              'nested.bin',
              {
                kind: 'file',
                name: 'nested.bin',
                getFile: async () => new File(['n'], 'nested.bin'),
              } as unknown as FileSystemFileHandle,
            ];
          },
        } as unknown as FileSystemDirectoryHandle,
      ],
      [
        'a.txt',
        {
          kind: 'file',
          name: 'a.txt',
          getFile: async () => new File(['a'], 'a.txt'),
        } as unknown as FileSystemFileHandle,
      ],
    ]);
    const handle = {
      kind: 'directory',
      name: 'photos',
      entries: async function* entries(): AsyncGenerator<[string, FileSystemHandle]> {
        yield* dirEntries;
      },
    } as unknown as FileSystemDirectoryHandle;

    const files = await materializeHandle(handle);
    expect(files.map(relName)).toEqual(['photos/a.txt', 'photos/sub/nested.bin', 'photos/z.txt']);
    expect(new Uint8Array(await files[2]!.arrayBuffer())).toEqual(new TextEncoder().encode('z'));
  });

  it('grants when the permission API allows it and fails safe otherwise', async () => {
    const permission = (
      query: PermissionState,
      request: PermissionState | undefined = undefined,
    ): FileSystemHandle =>
      ({
        kind: 'file',
        name: 'f',
        queryPermission: async () => query,
        ...(request !== undefined ? { requestPermission: async () => request } : {}),
      }) as unknown as FileSystemHandle;
    await expect(ensureReadPermission(permission('granted'))).resolves.toBe(true);
    await expect(ensureReadPermission(permission('prompt', 'granted'))).resolves.toBe(true);
    await expect(ensureReadPermission(permission('prompt', 'denied'))).resolves.toBe(false);
    await expect(ensureReadPermission(permission('denied'))).resolves.toBe(false);
    // No permission API at all (non-Chromium engine): fail safe, never throw.
    await expect(
      ensureReadPermission({ kind: 'file', name: 'f' } as FileSystemHandle),
    ).resolves.toBe(false);
  });

  it('cheap-check: accepts the recorded source in any order, rejects real differences', async () => {
    const record: SenderRecord = await newSenderRecord(manifest(), { kind: 'reselection' }, 1);
    const pick = (name: string, size: number, mime: string, lastModified: number): File => {
      const file = new File([new Uint8Array(size)], name, { type: mime, lastModified });
      Object.defineProperty(file, 'webkitRelativePath', { value: `folder/${name}` });
      return file;
    };
    const same = [
      pick('b.bin', 4, 'application/octet-stream', 1_000),
      pick('a.bin', 3, 'application/octet-stream', 2_000),
    ];
    expect(cheapSourceCheck(record, same)).toBeUndefined();
    expect(cheapSourceCheck(record, [same[1]!, same[0]!])).toBeUndefined();

    expect(cheapSourceCheck(record, [same[0]!])).toMatch(/1 files/);
    const edited = pick('b.bin', 4, 'application/octet-stream', 9_999);
    expect(cheapSourceCheck(record, [same[1]!, edited])).toMatch(/differs/);
    const renamed = pick('other.bin', 4, 'application/octet-stream', 1_000);
    expect(cheapSourceCheck(record, [same[1]!, renamed])).toMatch(/differs/);
    const resized = pick('b.bin', 99, 'application/octet-stream', 1_000);
    expect(cheapSourceCheck(record, [same[1]!, resized])).toMatch(/differs/);
  });
});
