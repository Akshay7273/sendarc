/**
 * Streaming whole-file SHA-256 for the transfer worker. `hash-wasm` produces a
 * `sha256sum`-identical hex string and hashes synchronously per `update`, so it runs inside
 * the worker (never on the main thread). `createSHA256()` is async — we pay that once, then
 * `init()` a fresh hasher per digest. Loading the wasm requires `'wasm-unsafe-eval'` in the CSP.
 */

import { createSHA256, type IHasher } from 'hash-wasm';
import type { Digest, DigestState } from '@sendbeam/protocol';

/**
 * Resolve once the SHA-256 wasm is instantiated, returning a factory that yields a fresh,
 * initialised {@link Digest} per call. The engine calls the factory once per transfer.
 * When `restoreState` is given, a digest resumed from that serialized state is produced
 * instead of a fresh one (V13-PR05); the state must have been produced by this exact
 * hash-wasm build (`save()`), and the wasm rejects incompatible state by throwing.
 */
export async function createSha256DigestFactory(restoreState?: Uint8Array): Promise<() => Digest> {
  const hasher: IHasher = await createSHA256();
  return () => (restoreState ? new WasmDigest(hasher, restoreState) : new WasmDigest(hasher));
}

class WasmDigest implements Digest, DigestState {
  constructor(
    private readonly hasher: IHasher,
    restoreState?: Uint8Array,
  ) {
    if (restoreState) {
      this.hasher.load(restoreState);
    } else {
      this.hasher.init();
    }
  }
  update(bytes: Uint8Array): void {
    this.hasher.update(bytes);
  }
  hexDigest(): string {
    return this.hasher.digest('hex');
  }
  /**
   * Serialized snapshot of the internal state covering exactly the bytes fed so far
   * (V13-PR05). The hasher remains usable afterwards. The bytes are only meaningful to
   * this hash-wasm build; the storage layer tags them with DIGEST_CHECKPOINT_FORMAT_HASH_WASM.
   */
  saveState(): Uint8Array {
    return this.hasher.save();
  }
}
