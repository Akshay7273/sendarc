import { describe, expect, it } from 'vitest';
import { FrameType, type Manifest } from './transfer.js';
import { normalizeTransferPath, validateManifest } from './safe-path.js';

describe('normalizeTransferPath', () => {
  it('normalizes portable nested paths', () => {
    expect(normalizeTransferPath('photos\\2026\\arc.jpg')).toBe('photos/2026/arc.jpg');
    expect(normalizeTransferPath('résumé/猫.txt')).toBe('résumé/猫.txt');
  });

  it.each([
    '',
    '/etc/passwd',
    '\\server\\share',
    'C:\\secret.txt',
    '../secret',
    'safe/../../secret',
    './file',
    'folder//file',
    'folder/',
    'nul',
    'COM1.txt',
    'folder/aux.json',
    'trailing. ',
    'bad\0name',
    'bad:name',
  ])('rejects unsafe path %j', (path) => {
    expect(() => normalizeTransferPath(path)).toThrow();
  });

  it('caps depth and encoded component length', () => {
    expect(() => normalizeTransferPath(Array.from({ length: 33 }, () => 'a').join('/'))).toThrow();
    expect(() => normalizeTransferPath('é'.repeat(128))).toThrow();
  });
});

describe('validateManifest', () => {
  const entry = (idx: number, name: string, size = 9) => ({
    idx,
    name,
    size,
    mime: 'application/octet-stream',
    lastModified: 0,
    blockSize: 8,
    blocks: Math.ceil(size / 8),
    fileDigest: '00',
  });
  const manifest = (files: ReturnType<typeof entry>[], totalSize: number): Manifest => ({
    type: FrameType.Manifest,
    files,
    totalSize,
  });

  it('canonicalizes paths and accepts exact aggregate geometry', () => {
    expect(validateManifest(manifest([entry(0, 'a\\b.bin', 9), entry(1, 'empty', 0)], 9))).toEqual(
      manifest([entry(0, 'a/b.bin', 9), entry(1, 'empty', 0)], 9),
    );
  });

  it.each([
    manifest([], 0),
    manifest([entry(1, 'a')], 9),
    manifest([entry(0, 'a'), entry(1, 'A')], 18),
    manifest([entry(0, '../a')], 9),
    manifest([{ ...entry(0, 'a'), blocks: 99 }], 9),
    manifest([entry(0, 'a')], 8),
  ])('rejects an unsafe manifest', (value) => {
    expect(() => validateManifest(value)).toThrow();
  });
});
