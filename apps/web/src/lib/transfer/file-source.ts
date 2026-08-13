/**
 * A {@link FileSource} over a browser {@link File}/{@link Blob}. The sender streams twice — once
 * for the whole-file digest, once to send blocks — so each `stream()` opens a fresh reader; Blob
 * reads are repeatable. We slice into bounded pieces rather than iterating the ReadableStream,
 * since async iteration over a ReadableStream is not supported across all target browsers.
 */

import type { FileMeta, FileSource } from '@sendbeam/protocol';

const DEFAULT_CHUNK = 64 * 1024;

/**
 * Adapt a browser File into a {@link FileSource}. `name` overrides the canonical manifest
 * name — used for handle-derived Files whose relative path lives in their constructed
 * name rather than `webkitRelativePath` (V13-PR04 reattachment).
 */
export function blobFileSource(
  file: File,
  chunk: number = DEFAULT_CHUNK,
  name?: string,
): FileSource {
  const meta: FileMeta = {
    name: name ?? (file.webkitRelativePath || file.name),
    size: file.size,
    mime: file.type,
    lastModified: file.lastModified,
  };
  return {
    meta,
    stream(): AsyncIterable<Uint8Array> {
      return {
        async *[Symbol.asyncIterator](): AsyncGenerator<Uint8Array> {
          for (let off = 0; off < file.size; off += chunk) {
            const slice = file.slice(off, Math.min(off + chunk, file.size));
            yield new Uint8Array(await slice.arrayBuffer());
          }
        },
      };
    },
  };
}
