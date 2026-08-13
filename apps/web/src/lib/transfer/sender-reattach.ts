/**
 * Web sender reattachment helpers (V13-PR04) — the browser half of reopening an
 * interrupted send against its original source:
 *
 *  - {@link relName}: the canonical manifest name of a picked File (the same expression
 *    `blobFileSource` uses), so cheap pre-checks and record comparisons agree with the
 *    wire's file identities.
 *  - {@link canonicalizeFiles}: stable sort by rel name — the browser analog of the CLI's
 *    canonical sorted paths. A folder re-picked in any order yields the same manifest, so
 *    the record's fingerprint stays comparable across attempts.
 *  - {@link materializeHandle}: reopen a persisted File System Access handle into the
 *    same canonical File[] (File names carry their relative paths, so the wire manifest
 *    is identical to the original pick).
 *  - {@link ensureReadPermission}: query/request read permission, failing safe (false)
 *    whenever the API is unavailable — handle-based resume then falls back to reselection.
 *  - {@link cheapSourceCheck}: an advisory pre-check mirroring the CLI's cheap meta check;
 *    the authoritative identity check still runs in the worker before the manifest frame.
 */

import type { SenderRecord } from './sender-record.js';

/** The canonical manifest name of a picked File — matches `blobFileSource`'s meta.name. */
export function relName(file: File): string {
  return file.webkitRelativePath || file.name;
}

/**
 * Stable sort by canonical relative name (code-unit order — deterministic across engines
 * and identical to the CLI's sorted-canonical-path ordering). Returns a new array.
 */
export function canonicalizeFiles(files: File[]): File[] {
  return [...files].sort((a, b) => {
    const an = relName(a);
    const bn = relName(b);
    return an < bn ? -1 : an > bn ? 1 : 0;
  });
}

/**
 * Reopen a persisted File System Access handle into canonical Files. Directory handles
 * are walked recursively; every File's name is its relative path (e.g. `photos/a.jpg`),
 * so the manifest is byte-identical to the original selection. Throws when the handle is
 * dead or unreadable — the caller then falls back to reselection.
 */
export async function materializeHandle(handle: FileSystemHandle): Promise<File[]> {
  const out: File[] = [];
  if (handle.kind === 'file') {
    const file = await (handle as FileSystemFileHandle).getFile();
    out.push(relNamedFile(file, handle.name));
  } else {
    await walkDirectory(handle as FileSystemDirectoryHandle, handle.name, out);
  }
  return canonicalizeFiles(out);
}

async function walkDirectory(
  dir: FileSystemDirectoryHandle,
  prefix: string,
  out: File[],
): Promise<void> {
  for await (const [name, entry] of dir.entries()) {
    const rel = `${prefix}/${name}`;
    if (entry.kind === 'directory') {
      await walkDirectory(entry as FileSystemDirectoryHandle, rel, out);
    } else {
      const file = await (entry as FileSystemFileHandle).getFile();
      out.push(relNamedFile(file, rel));
    }
  }
}

/** Wrap a handle-derived File so its name carries the relative path (relName stays intact). */
function relNamedFile(file: File, rel: string): File {
  return new File([file], rel, { type: file.type, lastModified: file.lastModified });
}

/**
 * Best-effort read permission for a persisted handle. Returns false whenever the
 * permission API is unavailable (non-Chromium engines), so the caller falls back to
 * reselection instead of failing. Must run from a user gesture when the state is
 * `prompt` (requestPermission requires one).
 */
export async function ensureReadPermission(handle: FileSystemHandle): Promise<boolean> {
  const h = handle as FileSystemHandle & {
    queryPermission?: (opts: { mode: 'read' }) => Promise<PermissionState>;
    requestPermission?: (opts: { mode: 'read' }) => Promise<PermissionState>;
  };
  if (typeof h.queryPermission !== 'function') return false;
  let state = await h.queryPermission({ mode: 'read' });
  if (state === 'prompt' && typeof h.requestPermission === 'function') {
    state = await h.requestPermission({ mode: 'read' });
  }
  return state === 'granted';
}

/**
 * Advisory pre-check that the picked selection could be the recorded source. Compares
 * count, canonical order, and per-file name/size/mime/lastModified — mirroring the CLI's
 * cheap source check. Returns an error message on a definite mismatch, else undefined.
 * The authoritative fingerprint check still runs in the worker before the manifest frame.
 */
export function cheapSourceCheck(record: SenderRecord, files: File[]): string | undefined {
  const picked = canonicalizeFiles(files);
  if (picked.length !== record.files.length) {
    return `the selected source has ${picked.length} files, but interrupted transfer ${record.transferId} had ${record.files.length}`;
  }
  for (let i = 0; i < picked.length; i++) {
    const have = picked[i]!;
    const want = record.files[i]!;
    if (
      relName(have) !== want.name ||
      have.size !== want.size ||
      have.type !== want.mime ||
      have.lastModified !== want.lastModified
    ) {
      return `file "${want.name}" differs from interrupted transfer ${record.transferId}; resuming requires the original source, unchanged`;
    }
  }
  return undefined;
}
