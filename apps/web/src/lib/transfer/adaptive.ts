/**
 * Adaptive direct/relay racing policy — the browser twin of the CLI's
 * `apps/cli/internal/transfer/adaptive.go`. It replaces the old blind fixed-duration relay
 * fallback with an ICE-progress-driven decision: warm the encrypted relay only when the direct
 * path is shown (or strongly indicated) not to be viable, then let the two paths race.
 *
 * The logic is intentionally transport-agnostic and mirrors the Go implementation so the two
 * clients agree on the method (not on timing — each race resolves on whichever path becomes
 * ready first locally).
 */

/** ICE gathering state names consumed by the policy. */
export const Gathering = {
  New: 'new',
  Gathering: 'gathering',
  Complete: 'complete',
} as const;
export type Gathering = (typeof Gathering)[keyof typeof Gathering];

/** ICE connection state names consumed by the policy. */
export const Connection = {
  New: 'new',
  Checking: 'checking',
  Connected: 'connected',
  Completed: 'completed',
  Disconnected: 'disconnected',
  Failed: 'failed',
  Closed: 'closed',
} as const;
export type Connection = (typeof Connection)[keyof typeof Connection];

/** A single ICE progress observation fed to the policy. */
export interface AdaptiveEvent {
  gathering?: Gathering;
  connection?: Connection;
  /** True once a srflx/prflx/relay candidate has been gathered (strong direct hint). */
  hasServerReflexive: boolean;
  /** True once any candidate (including host) has been gathered. Zero candidates = no direct path. */
  hasAnyCandidate: boolean;
}

/** AdaptiveDecision is the policy's reasoning for a single observation. */
export type AdaptiveDecision = 'continue' | 'warm-relay' | 'direct-won';

export interface AdaptivePolicyOptions {
  /**
   * How long a direct path with candidates but no server-reflexive hint may stall in
   * "checking" before the relay is warmed. Zero uses the production default. Bounded and
   * cancellable by the caller (the driver cancels via its own context).
   */
  escalationMs?: number;
  /** Injectable clock for deterministic tests (defaults to Date.now). */
  now?: () => number;
}

/** Default escalation window for a stalled no-srflx direct attempt. */
export const DEFAULT_ESCALATION_MS = 5_000;

/**
 * Decides when to warm the relay based on ICE progress. It is a state machine driven by
 * AdaptiveEvent observations and holds no internal timers, so it is safe to feed from any ICE
 * callback; the driver owns cancellation.
 */
export class AdaptivePolicy {
  private readonly now: () => number;
  private readonly escalationMs: number;
  private readonly startedAt: number;

  private directScalable = true;
  private directViableHint = false;
  private anyCandidate = false;
  private escalDeadline = 0;
  private settled: { decision: AdaptiveDecision } | undefined;

  constructor(opts: AdaptivePolicyOptions = {}) {
    this.now = opts.now ?? Date.now;
    this.escalationMs = opts.escalationMs ?? DEFAULT_ESCALATION_MS;
    this.startedAt = this.now();
  }

  /** Scaleable/capable direct boolean accessor, for parity with the Go twin. */
  static getDefaultEscalation(): number {
    return DEFAULT_ESCALATION_MS;
  }

  observe(ev: AdaptiveEvent): AdaptiveDecision {
    if (this.settled) return this.settled.decision;
    if (ev.hasServerReflexive) this.directViableHint = true;
    if (ev.hasAnyCandidate) this.anyCandidate = true;

    switch (ev.connection) {
      case Connection.Connected:
      case Connection.Completed:
        return this.settle('direct-won');
      case Connection.Failed:
        return this.settle('warm-relay');
      default:
        break;
    }

    // Gathering finished with no candidate at all: no direct path to attempt.
    if (!this.anyCandidate && ev.gathering === Gathering.Complete) {
      return this.settle('warm-relay');
    }

    if (this.anyCandidate) {
      if (!this.directViableHint) {
        // Host-only direct is plausible (loopback/LAN) but may not cross NAT: race with a
        // bounded escalation.
        this.escalDeadline = this.armEscalation(this.escalDeadline);
        if (this.now() > this.escalDeadline) return this.settle('warm-relay');
        return 'continue';
      }
      this.escalDeadline = 0;
      return 'continue';
    }

    // No candidates yet and gathering not complete: arm a bounded escalation.
    this.escalDeadline = this.armEscalation(this.escalDeadline);
    if (this.now() > this.escalDeadline) return this.settle('warm-relay');
    return 'continue';
  }

  /** Whether the policy still considers the direct path viable. Informational only. */
  scalableDirect(): boolean {
    return this.directScalable;
  }

  private settle(decision: AdaptiveDecision): AdaptiveDecision {
    this.settled = { decision };
    this.directScalable = decision === 'direct-won';
    return decision;
  }

  private armEscalation(deadline: number): number {
    return deadline !== 0 ? deadline : this.now() + this.escalationMs;
  }
}
