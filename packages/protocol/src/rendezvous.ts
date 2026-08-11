/**
 * Rendezvous state machine — drives one peer through the handshake over the blind
 * signaling channel: `create`/`join` → `peer-joined` → `pake` → `confirm`
 * → an encrypted `caps` round-trip, ending with a shared master key and both directional
 * transfer keys.
 *
 * The machine is transport-agnostic: it is handed a `send` sink for outbound signaling
 * messages and fed inbound ones via {@link RendezvousSession.handle}. That keeps it pure
 * and unit-testable (two sessions can be wired mouth-to-ear with no socket) and lets the
 * browser and any other TS host supply their own transport. The Go CLI mirrors this flow
 * against `packages/wire`.
 *
 * It carries no invite words onto the wire: only the SPAKE2 share, the confirmation MAC,
 * and the AEAD-sealed caps ever leave, so the server it talks through learns only the
 * room number it already allocated. A wrong or edited code fails closed at key
 * confirmation (RFC 9382 §4), never producing a session.
 */

import {
  DEFAULT_BLOCK_BYTES,
  DEFAULT_FRAME_BYTES,
  DEFAULT_WORD_COUNT,
  FRAME_VERSION,
  PROTOCOL_VERSION,
} from './constants.js';
import type { Role, SignalErrorCode, SignalMsg } from './signaling.js';
import { FrameType, type Feature, type SinkHint } from './transfer.js';
import {
  computeShare,
  finish,
  passwordToScalar,
  randomScalar,
  type Spake2Output,
} from './spake2.js';
import {
  deriveMaster,
  deriveTransferKeys,
  type DirectionalKey,
  type TransferKeys,
} from './keyschedule.js';
import { open, seal } from './aead.js';
import { formatCode, generateWords, normalizeCode, parseCode } from './words.js';
import { base64urlToBytes, bytesToBase64url, constantTimeEqual, utf8 } from './bytes.js';

/** Where a session is in the handshake. Advances monotonically until `established` or `failed`. */
export type RendezvousPhase =
  | 'idle' // not started
  | 'allocating' // offerer: sent `create`, awaiting the room number
  | 'waiting' // awaiting the other peer to join
  | 'handshaking' // paired; SPAKE2 share sent, awaiting the peer's
  | 'confirming' // shared point derived; confirmation MAC sent, awaiting the peer's
  | 'exchanging-caps' // key confirmed; encrypted caps sent, awaiting the peer's
  | 'established' // both caps exchanged; keys ready
  | 'failed'; // aborted or rejected

/** The capability announcement each peer seals as its first frame under the session key. */
export interface CapsPayload {
  version: string;
  maxFrame: number;
  blockSize: number;
  features: Feature[];
  sinkHints: SinkHint[];
}

/** Everything a completed handshake yields — enough to run the transfer under the same key. */
export interface RendezvousResult {
  readonly role: Role;
  readonly room: number;
  /** The full normalized invite code (`<room>-<words>`); the SPAKE2 password. */
  readonly code: string;
  /** SendBeam master key, bound to the handshake transcript. */
  readonly master: Uint8Array;
  /** Both directional AEAD keys + nonce salts. */
  readonly keys: TransferKeys;
  /** Raw SPAKE2 output, retained for the SDP/ICE MAC keys (KcA/KcB). */
  readonly spake2: Spake2Output;
  readonly localCaps: CapsPayload;
  readonly remoteCaps: CapsPayload;
  /**
   * Next per-direction frame counters. The caps exchange consumed counter 0 in each
   * direction, so both are 1: the transfer must continue from here without resetting,
   * or it would reuse an AES-GCM nonce.
   */
  readonly sendCounter: number;
  readonly recvCounter: number;
}

/** Reasons a rendezvous can fail: a server `error` code, or a client-side handshake failure. */
export type RendezvousErrorCode =
  | SignalErrorCode
  | 'confirmation_failed'
  | 'bad_peer_message'
  | 'peer_left'
  | 'aborted'
  | 'protocol';

export class RendezvousError extends Error {
  constructor(
    readonly code: RendezvousErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'RendezvousError';
  }
}

/** The outbound half of the signaling channel the session drives. */
export interface SignalingSink {
  send(msg: SignalMsg): void;
}

interface CommonOptions {
  transport: SignalingSink;
  /** Overrides for this peer's announced capabilities. */
  localCaps?: Partial<CapsPayload>;
  onPhase?: (phase: RendezvousPhase) => void;
  /** Fires once the full invite code is known (immediately for a joiner; after `created` for an offerer). */
  onCode?: (code: string) => void;
}

/** Construct an offerer (allocates a room) or a joiner (pairs into an existing one). */
export type RendezvousOptions =
  | (CommonOptions & { role: 'offerer'; words?: string; wordCount?: number })
  | (CommonOptions & { role: 'joiner'; code: string });

function defaultCaps(): CapsPayload {
  return {
    version: PROTOCOL_VERSION,
    maxFrame: DEFAULT_FRAME_BYTES,
    blockSize: DEFAULT_BLOCK_BYTES,
    features: [],
    sinkHints: [],
  };
}

const CAPS_HEADER = {
  version: FRAME_VERSION,
  type: FrameType.Caps,
  flags: 0,
  fileIdx: 0,
  blockIdx: 0,
  frameOff: 0,
} as const;

export class RendezvousSession {
  readonly role: Role;
  /** Resolves with the session keys on success, rejects with a {@link RendezvousError}. */
  readonly done: Promise<RendezvousResult>;

  private readonly opts: RendezvousOptions;
  private readonly localCaps: CapsPayload;
  private resolve!: (r: RendezvousResult) => void;
  private reject!: (e: RendezvousError) => void;

  private _phase: RendezvousPhase = 'idle';
  private _code?: string;
  private settled = false;

  // Handshake state, filled in as the exchange proceeds.
  private room = -1;
  private words = '';
  private w?: bigint; // SPAKE2 password scalar
  private secret?: bigint; // ephemeral secret (x for offerer, y for joiner)
  private shareSent = false;
  private spake2?: Spake2Output;
  private keys?: TransferKeys;
  private master?: Uint8Array;
  private sendCounter = 0;
  private recvCounter = 0;

  /** Serializes all async work so messages are processed strictly in arrival order. */
  private chain: Promise<void> = Promise.resolve();

  constructor(opts: RendezvousOptions) {
    this.opts = opts;
    this.role = opts.role;
    this.localCaps = { ...defaultCaps(), ...opts.localCaps };
    this.done = new Promise<RendezvousResult>((resolve, reject) => {
      this.resolve = resolve;
      this.reject = reject;
    });
    // Surface unhandled rejections only through `done`; callers that ignore it still run.
    this.done.catch(() => {});
  }

  get phase(): RendezvousPhase {
    return this._phase;
  }

  /** The invite code, once known. Undefined for an offerer until the room is allocated. */
  get code(): string | undefined {
    return this._code;
  }

  /** Begin the handshake: an offerer sends `create`, a joiner sends `join`. */
  start(): void {
    this.enqueue(() => this.runStart());
  }

  /** Feed one inbound signaling message. Safe to call before {@link start} resolves it in order. */
  handle(msg: SignalMsg): void {
    this.enqueue(() => this.process(msg));
  }

  /** Abort locally: notify the peer with `bye` and reject `done`. Idempotent. */
  abort(reason = 'aborted'): void {
    if (this.settled) return;
    try {
      this.opts.transport.send({ type: 'bye', reason });
    } catch {
      // best-effort; the transport may already be gone
    }
    this.fail(new RendezvousError('aborted', reason));
  }

  // --- internal ---------------------------------------------------------------

  private enqueue(fn: () => Promise<void>): void {
    this.chain = this.chain.then(fn).catch((err: unknown) => this.fail(toError(err)));
  }

  private setPhase(phase: RendezvousPhase): void {
    this._phase = phase;
    this.opts.onPhase?.(phase);
  }

  private fail(err: RendezvousError): void {
    if (this.settled) return;
    this.settled = true;
    this.setPhase('failed');
    this.reject(err);
  }

  private async runStart(): Promise<void> {
    if (this.settled || this._phase !== 'idle') return;
    this.secret = randomScalar();
    if (this.opts.role === 'joiner') {
      const parsed = parseCode(this.opts.code);
      this.room = parsed.room;
      this.words = parsed.words;
      this._code = formatCode(parsed.room, parsed.words);
      this.w = await passwordToScalar(this._code);
      this.opts.onCode?.(this._code);
      this.opts.transport.send({ type: 'join', room: this.room });
      this.setPhase('waiting');
    } else {
      this.words = this.opts.words ?? generateWords(this.opts.wordCount ?? DEFAULT_WORD_COUNT);
      this.opts.transport.send({ type: 'create' });
      this.setPhase('allocating');
    }
  }

  private async process(msg: SignalMsg): Promise<void> {
    if (this.settled) return;
    switch (msg.type) {
      case 'created':
        return this.onCreated(msg.room);
      case 'peer-joined':
        return this.onPeerJoined(msg.role);
      case 'pake':
        return this.onPake(msg.msg);
      case 'confirm':
        return this.onConfirm(msg.mac);
      case 'caps':
        return this.onCaps(msg.frame);
      case 'bye':
        return this.fail(new RendezvousError('peer_left', msg.reason || 'peer left'));
      case 'error':
        return this.fail(new RendezvousError(msg.code, msg.msg || msg.code));
      default:
        // `create`/`join`/`sdp`/`ice` are not inbound to a client at this stage.
        return this.fail(
          new RendezvousError('protocol', `unexpected ${msg.type} in ${this._phase}`),
        );
    }
  }

  private async onCreated(room: number): Promise<void> {
    if (this.role !== 'offerer' || this._phase !== 'allocating') {
      return this.fail(new RendezvousError('protocol', 'unexpected created'));
    }
    this.room = room;
    this._code = formatCode(room, this.words);
    this.w = await passwordToScalar(normalizeCode(this._code));
    this.opts.onCode?.(this._code);
    this.setPhase('waiting');
  }

  private async onPeerJoined(role: Role): Promise<void> {
    if (this._phase !== 'waiting' || role !== this.role) {
      return this.fail(new RendezvousError('protocol', 'unexpected peer-joined'));
    }
    // Paired. Send our SPAKE2 share; the peer sends theirs independently (one round trip).
    const share = computeShare(this.role, this.w!, this.secret!);
    this.shareSent = true;
    this.opts.transport.send({ type: 'pake', msg: bytesToBase64url(share) });
    this.setPhase('handshaking');
  }

  private async onPake(shareB64: string): Promise<void> {
    if (!this.shareSent) {
      return this.fail(new RendezvousError('protocol', 'pake before pairing'));
    }
    let peerShare: Uint8Array;
    try {
      peerShare = base64urlToBytes(shareB64);
    } catch {
      return this.fail(new RendezvousError('bad_peer_message', 'malformed pake'));
    }
    // finish decodes and validates the peer's point; an off-curve share throws here.
    try {
      this.spake2 = await finish(this.role, this.w!, this.secret!, peerShare);
    } catch {
      return this.fail(new RendezvousError('bad_peer_message', 'invalid pake share'));
    }
    const ownConfirm = this.role === 'offerer' ? this.spake2.confirmA : this.spake2.confirmB;
    this.opts.transport.send({ type: 'confirm', mac: bytesToBase64url(ownConfirm) });
    this.setPhase('confirming');
  }

  private async onConfirm(macB64: string): Promise<void> {
    if (!this.spake2) {
      return this.fail(new RendezvousError('protocol', 'confirm before pake'));
    }
    let got: Uint8Array;
    try {
      got = base64urlToBytes(macB64);
    } catch {
      return this.fail(new RendezvousError('bad_peer_message', 'malformed confirm'));
    }
    const expected = this.role === 'offerer' ? this.spake2.confirmB : this.spake2.confirmA;
    if (!constantTimeEqual(got, expected)) {
      // Wrong code or a MITM: fail closed (RFC 9382 §4).
      return this.fail(new RendezvousError('confirmation_failed', 'key confirmation failed'));
    }
    // Confirmed. Derive the transfer keys and send our encrypted caps.
    this.master = await deriveMaster(this.spake2.Ke, this.spake2.transcript);
    this.keys = await deriveTransferKeys(this.master);
    const frame = await seal(
      this.sendDir(),
      this.sendCounter++,
      CAPS_HEADER,
      utf8(JSON.stringify(this.localCaps)),
    );
    this.opts.transport.send({ type: 'caps', frame: bytesToBase64url(frame) });
    this.setPhase('exchanging-caps');
    // The peer's caps may already be queued; it is processed next, keys now in hand.
  }

  private async onCaps(frameB64: string): Promise<void> {
    if (!this.keys) {
      return this.fail(new RendezvousError('protocol', 'caps before key confirmation'));
    }
    let opened;
    try {
      const frame = base64urlToBytes(frameB64);
      opened = await open(this.recvDir(), this.recvCounter++, frame);
    } catch {
      return this.fail(new RendezvousError('bad_peer_message', 'caps failed to decrypt'));
    }
    if (opened.header.type !== FrameType.Caps) {
      return this.fail(new RendezvousError('bad_peer_message', 'first frame is not caps'));
    }
    const remoteCaps = parseCaps(opened.plaintext);
    if (!remoteCaps) {
      return this.fail(new RendezvousError('bad_peer_message', 'malformed caps payload'));
    }
    this.settled = true;
    this.setPhase('established');
    this.resolve({
      role: this.role,
      room: this.room,
      code: this._code!,
      master: this.master!,
      keys: this.keys,
      spake2: this.spake2!,
      localCaps: this.localCaps,
      remoteCaps,
      sendCounter: this.sendCounter,
      recvCounter: this.recvCounter,
    });
  }

  private sendDir(): DirectionalKey {
    return this.role === 'offerer' ? this.keys!.o2j : this.keys!.j2o;
  }

  private recvDir(): DirectionalKey {
    return this.role === 'offerer' ? this.keys!.j2o : this.keys!.o2j;
  }
}

function parseCaps(plaintext: Uint8Array): CapsPayload | undefined {
  let obj: unknown;
  try {
    obj = JSON.parse(new TextDecoder().decode(plaintext));
  } catch {
    return undefined;
  }
  if (typeof obj !== 'object' || obj === null) return undefined;
  const c = obj as Record<string, unknown>;
  if (
    typeof c.version !== 'string' ||
    typeof c.maxFrame !== 'number' ||
    typeof c.blockSize !== 'number' ||
    !Array.isArray(c.features) ||
    !Array.isArray(c.sinkHints)
  ) {
    return undefined;
  }
  return {
    version: c.version,
    maxFrame: c.maxFrame,
    blockSize: c.blockSize,
    features: c.features as Feature[],
    sinkHints: c.sinkHints as SinkHint[],
  };
}

function toError(err: unknown): RendezvousError {
  if (err instanceof RendezvousError) return err;
  return new RendezvousError('protocol', err instanceof Error ? err.message : String(err));
}
