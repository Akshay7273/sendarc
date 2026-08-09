import { FrameType, type FileEntry, type Manifest } from './transfer.js';

export const MAX_TRANSFER_FILES = 4096;
export const MAX_TRANSFER_PATH_BYTES = 1024;
export const MAX_TRANSFER_PATH_DEPTH = 32;
export const MAX_TRANSFER_SEGMENT_BYTES = 255;

const utf8 = new TextEncoder();
const windowsReserved = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i;
const unsafeWindowsChars = /[<>:"|?*]/;

/** Canonicalize an untrusted manifest path or throw before any destination is opened. */
export function normalizeTransferPath(input: string): string {
  if (input.length === 0) throw new Error('manifest path is empty');
  if (input.startsWith('/') || input.startsWith('\\') || /^[A-Za-z]:/.test(input)) {
    throw new Error('manifest path must be relative');
  }
  const canonical = input.replaceAll('\\', '/');
  const segments = canonical.split('/');
  if (segments.length > MAX_TRANSFER_PATH_DEPTH) throw new Error('manifest path is too deep');
  for (const segment of segments) {
    if (segment.length === 0 || segment === '.' || segment === '..') {
      throw new Error('manifest path contains an unsafe segment');
    }
    for (const character of segment) {
      if ((character.codePointAt(0) ?? 0) <= 0x1f || unsafeWindowsChars.test(character)) {
        throw new Error('manifest path contains unsafe characters');
      }
    }
    if (segment.endsWith('.') || segment.endsWith(' ')) {
      throw new Error('manifest path has an unsafe suffix');
    }
    if (windowsReserved.test(segment)) throw new Error('manifest path uses a reserved name');
    if (utf8.encode(segment).length > MAX_TRANSFER_SEGMENT_BYTES) {
      throw new Error('manifest path segment is too long');
    }
  }
  if (utf8.encode(canonical).length > MAX_TRANSFER_PATH_BYTES) {
    throw new Error('manifest path is too long');
  }
  return canonical;
}

/** Validate manifest-wide geometry and return a copy with canonical relative paths. */
export function validateManifest(manifest: Manifest): Manifest {
  if (manifest.files.length === 0 || manifest.files.length > MAX_TRANSFER_FILES) {
    throw new Error('manifest has an invalid file count');
  }
  const paths = new Set<string>();
  let totalSize = 0;
  const files: FileEntry[] = manifest.files.map((file, idx) => {
    if (file.idx !== idx) throw new Error('manifest file indexes must be contiguous');
    for (const [label, value] of [
      ['size', file.size],
      ['lastModified', file.lastModified],
      ['blockSize', file.blockSize],
      ['blocks', file.blocks],
    ] as const) {
      if (!Number.isSafeInteger(value)) throw new Error(`manifest ${label} is not a safe integer`);
    }
    if (file.size < 0 || file.lastModified < 0 || file.blockSize <= 0) {
      throw new Error('manifest has invalid file geometry');
    }
    if (file.blocks !== Math.ceil(file.size / file.blockSize)) {
      throw new Error('manifest has invalid block geometry');
    }
    const name = normalizeTransferPath(file.name);
    const key = name.toLowerCase();
    if (paths.has(key)) throw new Error('manifest contains duplicate paths');
    paths.add(key);
    totalSize += file.size;
    if (!Number.isSafeInteger(totalSize)) throw new Error('manifest total size is too large');
    return { ...file, name };
  });
  if (!Number.isSafeInteger(manifest.totalSize) || manifest.totalSize !== totalSize) {
    throw new Error('manifest total size mismatch');
  }
  return { type: FrameType.Manifest, files, totalSize };
}
