import { bytesToHex, utf8 } from './bytes.js';
import type { FileEntry } from './transfer.js';
import { sha256 } from './webcrypto.js';

/**
 * Completion token for an ordered file set. A single file retains the original wire value;
 * multiple files hash the newline-delimited canonical per-file digests.
 */
export async function completionDigest(files: readonly FileEntry[]): Promise<string> {
  if (files.length === 1) return files[0]!.fileDigest;
  return bytesToHex(await sha256(utf8(files.map((file) => file.fileDigest).join('\n'))));
}
