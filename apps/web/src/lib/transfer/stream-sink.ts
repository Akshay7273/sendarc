/**
 * Adapts a `FileSystemWritableFileStream`-shaped writable to the engine's {@link Sink}. Blocks
 * arrive verified and in order, so each write is positioned. On abort we prefer the stream's own
 * abort (discards the partial file) and finalise nothing; only if abort is unavailable do we close.
 */

import type { Sink } from '@sendbeam/protocol';

export interface WritableFileLike {
  write(data: { type: 'write'; position: number; data: Uint8Array }): Promise<void>;
  close(): Promise<void>;
  abort?(reason?: unknown): Promise<void>;
}

export function streamSink(w: WritableFileLike): Sink {
  return {
    write(offset: number, bytes: Uint8Array): Promise<void> {
      return w.write({ type: 'write', position: offset, data: bytes });
    },
    close(): Promise<void> {
      return w.close();
    },
    async abort(reason?: string): Promise<void> {
      if (w.abort) {
        await w.abort(reason);
      } else {
        await w.close();
      }
    },
  };
}
