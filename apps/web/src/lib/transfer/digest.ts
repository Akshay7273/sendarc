/**
 * Streaming whole-file SHA-256 for the transfer worker. `hash-wasm` produces a
 * `sha256sum`-identical hex string and hashes synchronously per `update`, so it runs inside
 * the worker (never on the main thread). `createSHA256()` is async — we pay that once, then
 * share a single scratch hasher. Loading the wasm requires `'wasm-unsafe-eval'` in the CSP.
 *
 * Digest isolation (V13-PR05 stabilization): a live `IHasher` is mutable — `init()` wipes
 * prior input and `digest()` deinitializes it, so a single hasher can never serve two
 * simultaneously-live digests (a multi-file resume keeps every seed digest live until the
 * whole transfer verifies). Instead, one factory owns ONE scratch hasher plus a captured
 * fresh-init snapshot, and every wrapper digest is an independent byte snapshot of the
 * internal state (~116 B). Each operation is scratch.load(state) → mutate → save(), all
 * synchronous, so interleaved digests never alias and memory stays bounded: 1 wasm instance
 * + ~116 B per live digest.
 */
import { createSHA256, type IHasher } from 'hash-wasm';
import type { Digest, DigestState } from '@sendbeam/protocol';

/**
 * A digest factory that additionally restores an independent digest from a serialized
 * state snapshot (V13-PR05). All digests from one factory share its scratch hasher and
 * can be live simultaneously; the wasm rejects incompatible restore states by throwing,
 * so a restored digest either covers exactly the checkpointed bytes or fails closed.
 */
export interface Sha256DigestFactory {
  (): Digest;
  restore(state: Uint8Array): Digest;
}

/**
 * Resolve once the SHA-256 wasm is instantiated, returning a factory that yields a fresh,
 * initialised {@link Digest} per call. The engine calls the factory once per transfer.
 */
export async function createSha256DigestFactory(): Promise<Sha256DigestFactory> {
  const scratch: IHasher = await createSHA256();
  const fresh = scratch.save();
  const make = (restoreState?: Uint8Array): Digest => new WasmDigest(scratch, fresh, restoreState);
  const factory = ((): Digest => make()) as Sha256DigestFactory;
  factory.restore = (state: Uint8Array): Digest => make(state);
  return factory;
}

class WasmDigest implements Digest, DigestState {
  private state: Uint8Array;
  constructor(
    private readonly scratch: IHasher,
    private readonly fresh: Uint8Array,
    restoreState?: Uint8Array,
  ) {
    if (restoreState === undefined) {
      // fresh is a read-only snapshot (load() never mutates its input), so all fresh
      // digests may share it until their first update replaces it with their own state.
      this.state = fresh;
    } else {
      // load() throws on foreign/truncated state before mutating the scratch hasher —
      // a restored digest either covers exactly the checkpointed bytes or fails closed.
      this.scratch.load(restoreState);
      this.state = this.scratch.save();
    }
  }
  update(bytes: Uint8Array): void {
    this.scratch.load(this.state);
    this.scratch.update(bytes);
    this.state = this.scratch.save();
  }
  hexDigest(): string {
    this.scratch.load(this.state);
    return this.scratch.digest('hex');
  }
  /**
   * Serialized snapshot of the internal state covering exactly the bytes fed so far
   * (V13-PR05). The digest remains usable afterwards. The bytes are only meaningful to
   * this hash-wasm build; the storage layer tags them with DIGEST_CHECKPOINT_FORMAT_HASH_WASM.
   */
  saveState(): Uint8Array {
    this.scratch.load(this.state);
    return this.scratch.save();
  }
}
