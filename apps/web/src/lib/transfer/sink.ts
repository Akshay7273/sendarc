/**
 * Opens an OPFS destination for a received file. OPFS needs no user gesture, so it works when the
 * manifest arrives mid-connection. The worker writes verified blocks here; on completion the host
 * reads the file back out for a download. Not unit-tested — exercised by the e2e transfer.
 */

import type { Sink } from '@sendarc/protocol';
import { streamSink, type WritableFileLike } from './stream-sink.js';

export interface OpenedSink {
  sink: Sink;
  /** Read the finished file back (after `sink.close()`), e.g. to trigger a download. */
  file(): Promise<File>;
}

export async function openOpfsSink(name: string): Promise<OpenedSink> {
  const root = await navigator.storage.getDirectory();
  const handle = await root.getFileHandle(sanitize(name), { create: true });
  const writable = (await handle.createWritable({
    keepExistingData: false,
  })) as unknown as WritableFileLike;
  return {
    sink: streamSink(writable),
    async file() {
      const f = await handle.getFile();
      return new File([f], name, { type: f.type, lastModified: f.lastModified });
    },
  };
}

/** OPFS keys are path-like; strip separators so the manifest name can't escape the directory. */
function sanitize(name: string): string {
  const base = name.replace(/^.*[\\/]/, '').trim();
  return base.length > 0 ? base : 'download';
}
