/**
 * Recovery controller — the browser twin of the CLI's transient-disconnect recovery in
 * `apps/cli/internal/rtc/peer.go`. It owns the bounded "recovering connection" observation for
 * an established direct path: once ICE reports `disconnected`, the path enters a recovery window
 * during which an ICE restart is attempted; if the path returns to `connected` the window clears,
 * and if the window elapses (or the restart fails) the controller reports failure so the caller
 * can fall back to the relay without restarting transfer progress.
 *
 * Like `adaptive.ts`, this module is a pure state machine with no DOM/RTCPeerConnection
 * dependency, so it is fully unit-testable with an injected clock/timer; the peer wiring in
 * `peer.ts` drives it from the ICE callbacks.
 */

export interface RecoveryCallbacks {
  /** Entering the transient-disconnect recovery window (a restart is under way). */
  onStart?: () => void;
  /** Recovered: the path returned to connected within the window. */
  onRecover?: () => void;
  /** The window elapsed (or a restart failed) without recovery: fail over to the relay. */
  onFail?: () => void;
}

/** Injectable timer hook for deterministic tests; defaults to setTimeout/clearTimeout. */
export interface RecoveryScheduler {
  schedule(fn: () => void, ms: number): unknown;
  cancel(handle: unknown): void;
}

export interface RecoveryControllerOptions {
  /** Bound on how long to observe a transient disconnect before failing over. */
  windowMs: number;
  callbacks: RecoveryCallbacks;
  scheduler?: RecoveryScheduler;
}

/**
 * Bounds the observation of a transient ICE disconnect. Start/clear are idempotent and pushing
 * a `disconnected` while already recovering does not re-arm the window (mirrors the CLI guard).
 */
export class RecoveryController {
  private readonly windowMs: number;
  private readonly callbacks: RecoveryCallbacks;
  private readonly schedule: (fn: () => void, ms: number) => unknown;
  private readonly cancelFn: (handle: unknown) => void;
  private active = false;
  private timer: unknown | undefined;

  constructor(opts: RecoveryControllerOptions) {
    this.windowMs = opts.windowMs;
    this.callbacks = opts.callbacks;
    const sched = opts.scheduler;
    this.schedule = sched ? sched.schedule.bind(sched) : (fn, ms) => setTimeout(fn, ms);
    this.cancelFn = sched
      ? sched.cancel.bind(sched)
      : (h) => clearTimeout(h as ReturnType<typeof setTimeout>);
  }

  /** Whether the recovery window is currently open. */
  recovering(): boolean {
    return this.active;
  }

  /** Enter the recovery window on a transient disconnect. No-op if already recovering. */
  start(): void {
    if (this.active) return;
    this.active = true;
    this.callbacks.onStart?.();
    this.timer = this.schedule(() => this.fail(), this.windowMs);
  }

  /** Clear the window because the path returned to connected. No-op if not recovering. */
  clear(): void {
    if (!this.active) return;
    this.active = false;
    this.cancelTimer();
    this.callbacks.onRecover?.();
  }

  /** Force a failed recovery (restart failed, or the window elapsed). Idempotent. */
  fail(): void {
    if (!this.active) return;
    this.active = false;
    this.cancelTimer();
    this.callbacks.onFail?.();
  }

  /** Tear down without firing callbacks (caller closed the peer). Idempotent. */
  dispose(): void {
    this.active = false;
    this.cancelTimer();
  }

  private cancelTimer(): void {
    if (this.timer !== undefined) {
      this.cancelFn(this.timer);
      this.timer = undefined;
    }
  }
}
