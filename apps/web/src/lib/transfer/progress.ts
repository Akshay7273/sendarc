import type { TransferRunState } from '@sendbeam/protocol';

export interface TransferSnapshot {
  bytes: number;
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
      total: this.totalBytes,
      rateBps: this.rateBps,
      etaSeconds,
      state: this.state,
    };
  }
}
