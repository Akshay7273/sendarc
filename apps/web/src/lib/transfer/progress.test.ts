import { describe, expect, it } from 'vitest';

import { ProgressTracker } from './progress.js';

describe('ProgressTracker', () => {
  it('is monotonic and reports acknowledged throughput and ETA over five seconds', () => {
    let now = 0;
    const tracker = new ProgressTracker(10_000, () => now);
    expect(tracker.update(0).rateBps).toBe(0);

    let snapshot = tracker.snapshot();
    for (let second = 1; second <= 5; second++) {
      now = second * 1000;
      snapshot = tracker.update(second * 1000);
    }
    expect(snapshot.bytes).toBe(5000);
    expect(snapshot.rateBps).toBe(1000);
    expect(snapshot.etaSeconds).toBe(5);

    now = 6000;
    expect(tracker.update(4000).bytes).toBe(5000); // stale callback cannot regress progress
  });

  it('excludes paused time and rebuilds the rate after resume', () => {
    let now = 0;
    const tracker = new ProgressTracker(4000, () => now);
    tracker.update(0);
    now = 1000;
    expect(tracker.update(1000).rateBps).toBe(1000);

    tracker.setState('paused');
    now = 11_000;
    tracker.setState('running');
    expect(tracker.snapshot().rateBps).toBe(0);
    tracker.update(1000);
    now = 12_000;
    const resumed = tracker.update(2000);
    expect(resumed.rateBps).toBe(1000);
    expect(resumed.etaSeconds).toBe(2);
  });
});
