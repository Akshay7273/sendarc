/**
 * Streaming whole-file SHA-256 for the transfer worker. `hash-wasm` produces a
 * `sha256sum`-identical hex string and hashes synchronously per `update`, so it runs inside
 * the worker (never on the main thread). `createSHA256()` is async — we pay that once, then
 * `init()` a fresh hasher per digest. Loading the wasm requires `'wasm-unsafe-eval'` in the CSP.
 */

import { createSHA256, type IHasher } from 'hash-wasm';
import type { Digest } from '@sendbeam/protocol';

/**
 * Resolve once the SHA-256 wasm is instantiated, returning a factory that yields a fresh,
 * initialised {@link Digest} per call. The engine calls the factory once per transfer.
 */
export async function createSha256DigestFactory(): Promise<() => Digest> {
  const hasher: IHasher = await createSHA256();
  return () => new WasmDigest(hasher);
}

class WasmDigest implements Digest {
  constructor(private readonly hasher: IHasher) {
    this.hasher.init();
  }
  update(bytes: Uint8Array): void {
    this.hasher.update(bytes);
  }
  hexDigest(): string {
    return this.hasher.digest('hex');
  }
}
