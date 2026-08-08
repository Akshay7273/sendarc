/**
 * IO ports for the transfer engine (M2 design §5.2, §7). The engine depends only on these
 * async primitives, so the same core runs inline in Node and inside the browser worker with
 * no forked logic. Concrete implementations (OPFS sink, hash-wasm digest, File source) live
 * in the host; this module defines the contracts plus in-memory helpers for tests.
 */

import type { Fail } from './transfer.js';

/** Minimal file metadata carried in the manifest. */
export interface FileMeta {
  name: string;
  size: number;
  mime: string;
  lastModified: number;
}

/**
 * A streamable file. `stream()` yields the bytes in order and MUST be re-callable — the
 * sender reads once to compute the whole-file digest, then again to send blocks.
 */
export interface FileSource {
  readonly meta: FileMeta;
  stream(): AsyncIterable<Uint8Array>;
}

/** A destination for verified, in-order block writes (design §7). */
export interface Sink {
  write(offset: number, bytes: Uint8Array): void | Promise<void>;
  close(): void | Promise<void>;
  abort(reason?: string): void | Promise<void>;
}

/** A streaming whole-file hasher producing a `sha256sum`-identical hex string. */
export interface Digest {
  update(bytes: Uint8Array): void;
  hexDigest(): string | Promise<string>;
}

/**
 * A transfer failure carrying one of the protocol's `fail` reasons. The `reason` is the
 * machine-readable tag sent on the wire; it is always prefixed onto `message` so the reason
 * survives in `error.message` (logs, `toThrow` matchers) even when a detail string is given.
 */
export class TransferError extends Error {
  constructor(
    readonly reason: Fail['reason'],
    message?: string,
  ) {
    super(message ? `${reason}: ${message}` : reason);
    this.name = 'TransferError';
  }
}

/** In-memory sink that reassembles writes into one buffer. For tests and the loopback. */
export class MemorySink implements Sink {
  private chunks: Array<{ offset: number; bytes: Uint8Array }> = [];
  private closed = false;
  private aborted?: string;

  write(offset: number, bytes: Uint8Array): void {
    if (this.closed || this.aborted !== undefined) throw new Error('write after close/abort');
    this.chunks.push({ offset, bytes: bytes.slice() });
  }
  close(): void {
    this.closed = true;
  }
  abort(reason?: string): void {
    this.aborted = reason ?? 'aborted';
  }
  get isClosed(): boolean {
    return this.closed;
  }
  get abortReason(): string | undefined {
    return this.aborted;
  }
  /** The assembled bytes (highest offset + length defines the size). */
  bytes(): Uint8Array {
    let size = 0;
    for (const c of this.chunks) size = Math.max(size, c.offset + c.bytes.length);
    const out = new Uint8Array(size);
    for (const c of this.chunks) out.set(c.bytes, c.offset);
    return out;
  }
}

/** Build an in-memory FileSource over `bytes`, yielding `chunk`-sized pieces (default 64 KiB). */
export function bytesSource(bytes: Uint8Array, meta: FileMeta, chunk = 64 * 1024): FileSource {
  return {
    meta,
    stream(): AsyncIterable<Uint8Array> {
      return {
        async *[Symbol.asyncIterator]() {
          for (let i = 0; i < bytes.length; i += chunk) {
            yield bytes.subarray(i, Math.min(i + chunk, bytes.length));
          }
        },
      };
    },
  };
}
