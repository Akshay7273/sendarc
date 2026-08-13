/**
 * IO ports for the transfer engine. The engine depends only on these
 * async primitives, so the same core runs inline in Node and inside the browser worker with
 * no forked logic. Concrete implementations (OPFS sink, hash-wasm digest, File source) live
 * in the host; this module defines the contracts plus in-memory helpers for tests.
 */

import type { Fail, FileEntry, Manifest } from './transfer.js';
import { ErrorCode, type ErrorCode as ErrorCodeType } from './errors.js';

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

/** A complete transfer destination that owns one streaming sink per manifest file. */
export interface Destination {
  /** Validate capacity and prepare the destination before the first file is opened. */
  prepare(manifest: Manifest): void | Promise<void>;
  /** Open one canonical manifest path. Files are opened in ascending index order. */
  open(file: FileEntry): Sink | Promise<Sink>;
  /** Commit destination-wide metadata after every file has independently verified. */
  close(): void | Promise<void>;
  /** Discard all partial output, including files already completed in this transfer. */
  abort(reason?: string): void | Promise<void>;
}

/** Adapt the original one-file sink contract to the destination API. */
export function singleSinkDestination(sink: Sink): Destination {
  let opened = false;
  return {
    prepare(manifest): void {
      if (manifest.files.length !== 1) throw new Error('single sink cannot receive multiple files');
    },
    open(): Sink {
      if (opened) throw new Error('single sink opened more than once');
      opened = true;
      return sink;
    },
    close(): void {},
    abort(reason?: string): void | Promise<void> {
      return sink.abort(reason);
    },
  };
}

/** A streaming whole-file hasher producing a `sha256sum`-identical hex string. */
export interface Digest {
  update(bytes: Uint8Array): void;
  hexDigest(): string | Promise<string>;
}

/**
 * Optional Digest capability (V13-PR05): the digest's internal state can be serialized to
 * bytes that a compatible Digest can restore, so a durable receiver resumes hashing from a
 * checkpoint instead of re-hashing the persisted prefix. The bytes are opaque to the
 * engine — meaningful only to the implementation that produced them and version-tagged by
 * the host when persisted. A digest without this capability simply never contributes state.
 */
export interface DigestState {
  /** Snapshot of the digest's internal state covering exactly the bytes fed so far. The digest remains usable afterwards. */
  saveState(): Uint8Array;
}

/**
 * Optional Sink capability (V13-PR05): the sink can carry serialized digest state into its
 * next durable checkpoint. The engine calls `setDigestState` with state covering exactly
 * the blocks the following `write` (or `close`, for hosts that commit on close) will
 * checkpoint, so the storage layer persists committedBlocks and the matching digest
 * checkpoint atomically in one journal update. The state is an optimization only; a sink
 * that rejects it (or a digest without state support) journals a checkpoint without digest
 * state and resume re-hashes.
 */
export interface DigestStateSink {
  /**
   * Remember serialized digest state for the blocks the next `write`/`close` commits. A
   * null state clears it (the next checkpoint carries no digest state).
   */
  setDigestState(state: Uint8Array | null): void | Promise<void>;
}

/** Map a wire `fail` reason onto its taxonomy class (ADR 0002). */
const codeForReason: Record<Fail['reason'], ErrorCodeType> = {
  digest_mismatch: ErrorCode.Protocol,
  integrity: ErrorCode.Protocol,
  sink_error: ErrorCode.DestIO,
  canceled: ErrorCode.Canceled,
  quota: ErrorCode.Storage,
  retry_exhausted: ErrorCode.RetryExhausted,
};

/**
 * A transfer failure carrying one of the protocol's `fail` reasons plus its taxonomy
 * class. The `reason` is the machine-readable tag sent on the wire; it is always
 * prefixed onto `message` so the reason survives in `error.message` (logs,
 * `toThrow` matchers) even when a detail string is given.
 */
export class TransferError extends Error {
  readonly code: ErrorCodeType;
  constructor(
    readonly reason: Fail['reason'],
    message?: string,
    code?: ErrorCodeType,
  ) {
    super(message ? `${reason}: ${message}` : reason);
    this.name = 'TransferError';
    this.code = code ?? codeForReason[reason] ?? ErrorCode.Internal;
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
