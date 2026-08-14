/**
 * Resume preamble (V13-PR08): the product integration of the reviewed PR07 resume-auth
 * engine. The TypeScript twin of `packages/wire/resume_preamble.go`.
 *
 * It runs the transport-agnostic mutual-authentication handshake over the sealed session
 * channel — strictly BEFORE the transfer engine starts — so durable progress from a previous
 * authenticated session is never reused under session keys, and no
 * Manifest/ResumeState/BlockData/Complete frame can flow before the peers authenticated
 * continuity with each other.
 *
 * The resume-auth messages travel as FrameResumeAuth frames sealed under the SESSION
 * directional keys (the keys the SPAKE2 handshake just derived): the session key epoch is
 * used ONLY to carry the four resume-auth messages, and the transfer itself runs under the
 * FRESH key epoch derived from the mutually authenticated resume master (ADR 0005 §7). The
 * PR07 engine is unchanged: transferId + manifest fingerprint + role + resume secret are
 * local context (never transmitted), the transcript binds them, and the fresh nonces make
 * every attempt a new key epoch.
 *
 * Fail-closed rules: any inbound frame that is not a well-formed resume-auth frame (wrong
 * type, wrong counter, torn, tampered, oversized, malformed) settles the preamble failed
 * before the transfer could start. An exact duplicate of the last accepted frame (a
 * transport-level re-send with the same counter) is re-opened and re-answered idempotently
 * from the engine's snapshots — never with a fresh nonce or proof. There is no challenge
 * replacement, no nonce/proof/role/version mutation, and no unbounded history.
 */

import { FrameReplayError, openSequenced, seal, type FrameHeaderInput } from './aead.js';
import type { DirectionalKey } from './keyschedule.js';
import {
  ResumeAuthSession,
  encodeResumeMessage,
  type ResumeAuthResult,
  type ResumeMessage,
} from './resume-auth.js';
import { FrameType } from './transfer.js';

/** Options configuring one resume-auth exchange over the sealed session channel. */
export interface ResumePreambleOptions {
  /** This peer's stable role: offerer (sender) or joiner (receiver). */
  role: 'offerer' | 'joiner';
  /** Stable transfer id of the interrupted transfer (local context, never transmitted). */
  transferId: string;
  /** Canonical manifest fingerprint of the interrupted transfer (never transmitted). */
  fingerprint: string;
  /** Decoded 32-byte transfer-scoped credential from the local sender record or journal. */
  resumeSecret: Uint8Array;
  /** Transmits one sealed frame (the same callback the transfer engine will use). */
  send(frame: Uint8Array): Promise<void> | void;
  /** SESSION directional keys; the transfer later uses the fresh resumed epoch. */
  sendDir: DirectionalKey;
  recvDir: DirectionalKey;
  /** Continuing session counters: this peer's next send / expected first receive. */
  sendCounter: number;
  recvCounter: number;
  /** Deterministic fresh nonce source in tests; nil uses crypto.getRandomValues. */
  nonceSource?(n: number): Uint8Array;
}

/**
 * One in-flight resume-auth exchange. The driver wires {@link handle} as the inbound data
 * hook, calls {@link start} (offerer only), and awaits {@link done}; {@link result} exposes
 * the fresh resumed key epoch only after mutual authentication completes. Any failure is
 * terminal and preserved.
 */
export class ResumePreamble {
  private readonly opts: ResumePreambleOptions;
  private readonly sess: ResumeAuthSession;

  private sendCounter: number;
  private recvCounter: number;
  private started = false;
  private resultValue: ResumeAuthResult | undefined;
  private errValue: Error | undefined;
  private settled = false;
  private donePromise: Promise<ResumeAuthResult | undefined>;
  private resolveDone!: (r: ResumeAuthResult | undefined) => void;
  /**
   * Serializes ALL inbound preamble processing in arrival order: every handle() call
   * appends to this chain, so exactly one frame can open/mutate counters at a time even
   * when frames are delivered without awaiting (the worker dispatches `void
   * preamble.handle(frame)` for every inbound frame). The chain swallows rejections so a
   * later queued frame still runs and observes the settled state (failures are recorded
   * via {@link fail}, never thrown through the queue).
   */
  private queue: Promise<void> = Promise.resolve();
  /** Canonical payload of the last accepted inbound message, for idempotent re-answers. */
  private lastAccepted: Uint8Array | undefined;

  constructor(opts: ResumePreambleOptions) {
    const ctx: {
      version: number;
      transferId: string;
      manifestFingerprint: string;
      role: 'offerer' | 'joiner';
      resumeSecret: Uint8Array;
      nonceSource?: (n: number) => Uint8Array;
    } = {
      version: 1,
      transferId: opts.transferId,
      manifestFingerprint: opts.fingerprint,
      role: opts.role,
      resumeSecret: opts.resumeSecret,
    };
    if (opts.nonceSource !== undefined) ctx.nonceSource = opts.nonceSource;
    this.sess = new ResumeAuthSession(ctx);
    if (typeof opts.send !== 'function') {
      throw new Error('resume: preamble requires a send callback');
    }
    this.opts = opts;
    this.sendCounter = opts.sendCounter;
    this.recvCounter = opts.recvCounter;
    this.donePromise = new Promise<ResumeAuthResult | undefined>((resolve) => {
      this.resolveDone = resolve;
    });
  }

  /**
   * Begin the handshake: the offerer emits resume_init (sealed under the session send key at
   * the continuing counter); the joiner has nothing to send.
   */
  async start(): Promise<void> {
    if (this.started) throw new Error('resume: preamble already started');
    this.started = true;
    if (this.opts.role === 'joiner') return;
    let msg: ResumeMessage;
    try {
      msg = this.sess.start();
    } catch (err) {
      this.fail(err as Error);
      throw err;
    }
    await this.sendLocked(msg);
  }

  /**
   * Feed one inbound sealed frame. Called from the read loop; processing is serialized in
   * arrival order through an internal promise chain, so exactly one frame can open/mutate
   * counters at a time even when the caller does not await between deliveries. A
   * malformed, wrong-type, replayed, or otherwise invalid frame settles the preamble failed
   * (terminal) before the transfer could start; frames queued behind a failure observe the
   * settled state and cannot resurrect it.
   */
  handle(frame: Uint8Array): Promise<void> {
    const run = this.queue.then(() => this.handleSerialized(frame));
    // Keep the chain alive regardless of task outcome: failures are recorded via fail()
    // (never thrown through the queue), so later queued frames must still execute and see
    // the settled state. The returned promise is the caller's own task (which cannot
    // reject: every path is caught), so `void preamble.handle(frame)` is safe.
    this.queue = run.catch(() => undefined);
    return run;
  }

  /** One serialized step of inbound processing (guarded by the queue). */
  private async handleSerialized(frame: Uint8Array): Promise<void> {
    if (this.settled) return; // settled: ignore late frames (including queued-after-failure)
    let payload: Uint8Array;
    try {
      payload = await this.openLocked(frame);
    } catch (err) {
      this.fail(err as Error);
      return;
    }
    if (this.settled) return; // canceled while the frame was being opened
    let out: ResumeMessage | undefined;
    let result: ResumeAuthResult | undefined;
    try {
      const outcome = await this.sess.handle(payload);
      out = outcome.out;
      result = outcome.result;
    } catch (err) {
      this.fail(err as Error);
      return;
    }
    if (this.settled) return; // canceled while the engine was handling the frame
    this.lastAccepted = payload;
    // The final step (the joiner's accept of resume_confirm) returns BOTH the outbound
    // resume_ready AND the result: the ready must go out before the side is announced
    // settled, or the offerer would wait forever for a message that was never sent.
    if (out !== undefined) {
      try {
        await this.sendLocked(out);
      } catch (err) {
        this.fail(err as Error);
        return;
      }
    }
    if (this.settled) return; // canceled while the reply was being transmitted
    if (result !== undefined) {
      this.resultValue = result;
      this.settled = true;
      this.resolveDone(result);
    }
  }

  /** Resolves when the preamble settles (mutual authentication succeeded or failed). */
  done(): Promise<ResumeAuthResult | undefined> {
    return this.donePromise;
  }

  /** Reports whether the preamble has settled (success or terminal failure). */
  isSettled(): boolean {
    return this.settled;
  }

  /**
   * Abort an in-flight handshake (peer teardown / driver cancel). Settles the preamble
   * failed and abandons the candidate key material; safe to call more than once and after
   * settlement (no-op then). Mirrors the CLI driver's ctx-bound wait.
   */
  cancel(): void {
    this.fail(new Error('resume: preamble canceled'));
  }

  /**
   * Returns the fresh resumed key epoch after mutual authentication, or throws the terminal
   * error. The keys are exposed only after the handshake completed; a failed attempt
   * abandons the candidate key material (ADR 0005 §7).
   */
  result(): ResumeAuthResult {
    if (this.errValue !== undefined) throw this.errValue;
    if (this.resultValue === undefined) {
      throw new Error('resume: preamble has not settled');
    }
    return this.resultValue;
  }

  /**
   * Opens one inbound frame under the session recv key at the expected counter, requiring the
   * FrameResumeAuth tag. An exact duplicate of the last accepted frame (the same counter as
   * the previous frame, re-sent by the transport) is re-opened and accepted idempotently so a
   * lost response is retransmitted identically; any other replay fails.
   */
  private async openLocked(frame: Uint8Array): Promise<Uint8Array> {
    let opened;
    try {
      opened = await openSequenced(this.opts.recvDir, this.recvCounter, frame);
    } catch (err) {
      if (
        err instanceof FrameReplayError &&
        this.recvCounter > 0 &&
        this.lastAccepted !== undefined
      ) {
        // Exact-duplicate re-send: the frame carries the previous counter and must be
        // byte-identical to the last accepted message to be answered idempotently.
        try {
          const prev = await openSequenced(this.opts.recvDir, this.recvCounter - 1, frame);
          if (
            prev.header.type === FrameType.ResumeAuth &&
            eqBytes(prev.plaintext, this.lastAccepted)
          ) {
            return prev.plaintext;
          }
        } catch {
          // fall through to the rejection below
        }
      }
      throw new Error(`resume: inbound frame rejected: ${(err as Error).message}`);
    }
    if (opened.header.type !== FrameType.ResumeAuth) {
      throw new Error(
        `resume: inbound frame type ${opened.header.type} before resume authentication completed`,
      );
    }
    this.recvCounter = opened.counter + 1;
    return opened.plaintext;
  }

  /** Seals and transmits one resume-auth message under the session send key at the
   * continuing counter. The counter advances exactly once per sent frame. */
  private async sendLocked(msg: ResumeMessage): Promise<void> {
    const payload = encodeResumeMessage(msg);
    const header: FrameHeaderInput = {
      version: 1,
      type: FrameType.ResumeAuth,
      flags: 0,
      fileIdx: 0,
      blockIdx: 0,
      frameOff: 0,
    };
    let frame: Uint8Array;
    try {
      frame = await seal(this.opts.sendDir, this.sendCounter, header, payload);
    } catch (err) {
      throw new Error(`resume: seal preamble frame: ${(err as Error).message}`);
    }
    try {
      await this.opts.send(frame);
    } catch (err) {
      throw new Error(`resume: send preamble frame: ${(err as Error).message}`);
    }
    this.sendCounter++;
  }

  private fail(err: Error): void {
    if (this.errValue === undefined) {
      this.errValue = err;
    }
    if (!this.settled) {
      this.settled = true;
      this.resolveDone(undefined);
    }
  }
}

function eqBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
