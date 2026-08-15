import type { TransferRunState } from '@sendbeam/protocol';

export interface TransferSnapshot {
  /** Verified high-water (ACKed) bytes; on a resume this includes the reused baseline. */
  bytes: number;
  /** Verified baseline reused from the authenticated durable checkpoint at resume start. */
  reusedBytes: number;
  /** New bytes durably ACKed during THIS session: bytes - reusedBytes (never negative). */
  sessionBytes: number;
  total: number | undefined;
  rateBps: number;
  etaSeconds: number | undefined;
  state: TransferRunState;
}

interface Sample {
  at: number;
  bytes: number;
}

/**
 * Rolling acknowledged-byte progress. A five-second sample window smooths bursty block ACKs,
 * while pause/resume resets the clock so idle time never depresses throughput or inflates ETA.
 */
export class ProgressTracker {
  private bytes = 0;
  // V13-PR08: verified baseline reused from the authenticated durable checkpoint. Anchored
  // by setReused BEFORE the first new block, so the first rate sample sits exactly on the
  // checkpoint and the reused jump is never counted as transferred bytes.
  private reusedBytes = 0;
  private totalBytes: number | undefined;
  private rateBps = 0;
  private state: TransferRunState = 'running';
  private readonly samples: Sample[] = [];

  constructor(
    total?: number,
    private readonly now: () => number = () => performance.now(),
    private readonly windowMs = 5000,
  ) {
    this.totalBytes = total;
  }

  setTotal(total: number): void {
    this.totalBytes = total;
  }

  /**
   * V13-PR08: anchor the verified baseline reused from the authenticated durable
   * checkpoint. The engine reports it once, before the first new block is ACKed, so the
   * session rate measures only this session's advancement (never the reused jump).
   */
  setReused(reused: number): void {
    this.reusedBytes = Math.max(0, reused);
  }

  update(acknowledgedBytes: number): TransferSnapshot {
    this.bytes = Math.max(this.bytes, acknowledgedBytes);
    if (this.state !== 'running') return this.snapshot();

    const sample = { at: this.now(), bytes: this.bytes };
    this.samples.push(sample);
    const cutoff = sample.at - this.windowMs;
    while (this.samples.length > 2 && this.samples[1]!.at <= cutoff) this.samples.shift();

    const first = this.samples[0]!;
    const elapsedMs = sample.at - first.at;
    const advanced = sample.bytes - first.bytes;
    this.rateBps = elapsedMs > 0 && advanced > 0 ? (advanced * 1000) / elapsedMs : 0;
    return this.snapshot();
  }

  setState(state: TransferRunState): TransferSnapshot {
    if (this.state === state) return this.snapshot();
    this.state = state;
    if (state === 'running') {
      this.samples.length = 0;
      this.rateBps = 0;
    }
    return this.snapshot();
  }

  snapshot(): TransferSnapshot {
    const remaining = Math.max(0, (this.totalBytes ?? 0) - this.bytes);
    const etaSeconds =
      this.totalBytes !== undefined && this.rateBps > 0
        ? Math.ceil(remaining / this.rateBps)
        : undefined;
    return {
      bytes: this.bytes,
      reusedBytes: this.reusedBytes,
      sessionBytes: Math.max(0, this.bytes - this.reusedBytes),
      total: this.totalBytes,
      rateBps: this.rateBps,
      etaSeconds,
      state: this.state,
    };
  }
}
