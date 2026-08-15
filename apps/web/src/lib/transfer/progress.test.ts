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

  // V13-PR08 progress contract: verified = reused + session, the checkpoint is surfaced
  // before the first new block, and the rate/ETA measure only this session's advancement.
  describe('resumed transfers (V13-PR08)', () => {
    it('surfaces the verified checkpoint immediately and anchors the session rate on it', () => {
      let now = 0;
      const tracker = new ProgressTracker(100_000, () => now);
      // The engine reports the reused baseline BEFORE the first new block is ACKed.
      now = 1000;
      tracker.setReused(68_000);
      const baseline = tracker.snapshot();
      expect(baseline.bytes).toBe(0); // no verified bytes reported yet
      expect(baseline.reusedBytes).toBe(68_000);
      expect(baseline.sessionBytes).toBe(0);
      // The first verified sample lands exactly on the checkpoint.
      now = 2000;
      const first = tracker.update(68_000);
      expect(first.bytes).toBe(68_000);
      expect(first.reusedBytes).toBe(68_000);
      expect(first.sessionBytes).toBe(0);
      expect(first.rateBps).toBe(0); // the reused jump is NOT a transfer rate
      // A new block is durably ACKed this session.
      now = 3000;
      const second = tracker.update(69_000);
      expect(second.bytes).toBe(69_000);
      expect(second.reusedBytes).toBe(68_000);
      expect(second.sessionBytes).toBe(1000);
      // 1000 bytes over 1s: the rate measures ONLY the session advancement.
      expect(second.rateBps).toBe(1000);
      expect(second.etaSeconds).toBe(31); // remaining verified / session rate
    });

    it('never regresses below the verified checkpoint and never counts stale callbacks', () => {
      let now = 0;
      const tracker = new ProgressTracker(100_000, () => now);
      now = 1000;
      tracker.setReused(68_000);
      tracker.update(68_000);
      now = 2000;
      tracker.update(69_000);
      // A stale callback below the checkpoint cannot move verified backwards.
      now = 3000;
      expect(tracker.update(50_000).bytes).toBe(69_000);
      expect(tracker.snapshot().sessionBytes).toBe(1000);
    });

    it('zero-byte resume: 100% verified, 0 session bytes before terminal presentation', () => {
      let now = 0;
      const tracker = new ProgressTracker(68_000, () => now);
      now = 1000;
      tracker.setReused(68_000);
      const snapshot = tracker.update(68_000);
      expect(snapshot.bytes).toBe(68_000);
      expect(snapshot.reusedBytes).toBe(68_000);
      expect(snapshot.sessionBytes).toBe(0);
      expect(snapshot.rateBps).toBe(0);
      // ETA: no remaining verified bytes and no session rate — nothing left to transfer.
      expect(snapshot.etaSeconds).toBeUndefined();
    });

    it('fresh transfers keep reusedBytes at zero and unchanged semantics', () => {
      let now = 0;
      const tracker = new ProgressTracker(1000, () => now);
      tracker.update(0);
      now = 1000;
      const snapshot = tracker.update(500);
      expect(snapshot.reusedBytes).toBe(0);
      expect(snapshot.sessionBytes).toBe(500);
    });
  });
});
