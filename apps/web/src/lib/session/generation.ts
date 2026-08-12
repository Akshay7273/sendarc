/**
 * A generation guard for async orchestration continuations.
 *
 * Browser transfer orchestration registers many callbacks (signaling, peer, relay,
 * worker, transport switching) that each close over captured state. If a callback
 * fires after the session was torn down (cancel/finish/fail), it must not mutate
 * state, switch transports, send frames, resolve/reject a promise twice, or touch
 * terminated resources.
 *
 * The guard is captured once when a continuation is created, then checked when the
 * continuation actually runs. A naive guard that reads the generation at runtime
 * inside the callback (instead of at capture time) can never detect staleness,
 * because cleanup can advance the generation only between capture and run.
 */
export class GenerationGuard {
  private current = 0;

  /** Capture the current generation for a new continuation (called at creation time). */
  capture(): number {
    return this.current;
  }

  /** True while `captured` is still the current session generation. */
  isCurrent(captured: number): boolean {
    return captured === this.current;
  }

  /** Advance the generation so every previously captured continuation becomes stale. */
  bump(): void {
    this.current++;
  }

  /**
   * Run `fn` only if `captured` is still the current generation (i.e. the session
   * has not been torn down since the continuation was created). Returns its result,
   * or `undefined` if the continuation is stale.
   */
  guard<T>(captured: number, fn: () => T): T | undefined {
    if (captured !== this.current) return undefined;
    return fn();
  }
}
