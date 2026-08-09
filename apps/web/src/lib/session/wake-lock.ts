/**
 * Wake lock — keeps the screen awake for the duration of an active transfer.
 *
 * A transfer can outlive the platform's idle screen timeout, and a blanked screen is a plausible
 * path to an aborted session. This manager holds a screen Wake Lock exactly while a transfer is
 * running (and the page is visible), releases it on pause, completion, or visibility loss, and
 * re-acquires it when the page comes back into view while the transfer is still active. Where the
 * Wake Lock API is unavailable (Firefox, insecure contexts, denied permission) it degrades to a
 * no-op — transfers work without it.
 */
export class WakeLockManager {
  private lock: WakeLockSentinel | undefined;
  private active = false;
  private chain: Promise<void> = Promise.resolve();
  private readonly onVisibility = (): void => this.schedule();

  constructor() {
    document.addEventListener('visibilitychange', this.onVisibility);
  }

  /** Mark whether a transfer is actively running; acquires or releases the screen lock to match. */
  setActive(active: boolean): void {
    this.active = active;
    this.schedule();
  }

  /** Stop listening for visibility changes and release any held lock. */
  dispose(): void {
    document.removeEventListener('visibilitychange', this.onVisibility);
    this.active = false;
    this.schedule();
  }

  private schedule(): void {
    this.chain = this.chain.then(() => this.sync());
  }

  private async sync(): Promise<void> {
    const want = this.active && document.visibilityState === 'visible';
    if (this.lock) {
      if (want) return;
      const lock = this.lock;
      this.lock = undefined;
      await lock.release().catch(() => {});
      return;
    }
    if (!want || !('wakeLock' in navigator)) return;
    try {
      const lock = await navigator.wakeLock.request('screen');
      lock.addEventListener('release', () => {
        if (this.lock === lock) this.lock = undefined;
        this.schedule();
      });
      this.lock = lock;
    } catch {
      // Unavailable (permission denied, denied on this device, …): transfer proceeds without it.
    }
  }
}
