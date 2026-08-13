import { describe, expect, it } from 'vitest';
import { RecoveryController, type RecoveryScheduler } from './recovery.js';

/** Manual scheduler for deterministic tests: fires callbacks only when advanced. */
class FakeScheduler implements RecoveryScheduler {
  private tasks: { handle: number; fn: () => void; at: number }[] = [];
  private clock = 0;
  private nextHandle = 1;

  schedule(fn: () => void, ms: number): unknown {
    const handle = this.nextHandle++;
    this.tasks.push({ handle, fn, at: this.clock + ms });
    return handle;
  }

  cancel(handle: unknown): void {
    this.tasks = this.tasks.filter((t) => t.handle !== handle);
  }

  /** Advance the clock by ms, firing any due tasks in order. */
  advance(ms: number): void {
    this.clock += ms;
    const due = this.tasks.filter((t) => t.at <= this.clock).sort((a, b) => a.at - b.at);
    this.tasks = this.tasks.filter((t) => t.at > this.clock);
    for (const t of due) t.fn();
  }

  get pending(): number {
    return this.tasks.length;
  }
}

function make(opts: { windowMs?: number } = {}) {
  const sched = new FakeScheduler();
  const started: boolean[] = [];
  const failed: boolean[] = [];
  let recoveredCount = 0;
  const ctrl = new RecoveryController({
    windowMs: opts.windowMs ?? 5000,
    callbacks: {
      onStart: () => started.push(true),
      onRecover: () => recoveredCount++,
      onFail: () => failed.push(true),
    },
    scheduler: sched,
  });
  return { sched, ctrl, started, failed, recovered: () => recoveredCount };
}

describe('RecoveryController — transient disconnect recovery', () => {
  it('enters recovery on start and reports recovering', () => {
    const { sched, ctrl, started } = make();
    expect(ctrl.recovering()).toBe(false);
    ctrl.start();
    expect(ctrl.recovering()).toBe(true);
    expect(started).toEqual([true]);
    expect(sched.pending).toBe(1); // bounded observation timer armed
  });

  it('repeated disconnects do not re-arm the window', () => {
    const { sched, ctrl, started } = make();
    ctrl.start();
    ctrl.start();
    expect(started).toEqual([true]);
    expect(sched.pending).toBe(1);
  });

  it('clears recovery on reconnect within the window', () => {
    const { sched, ctrl, recovered } = make();
    ctrl.start();
    ctrl.clear();
    expect(ctrl.recovering()).toBe(false);
    expect(sched.pending).toBe(0);
    expect(recovered()).toBe(1);
  });

  it('fails over when the window elapses without recovery', () => {
    const { sched, ctrl, failed } = make({ windowMs: 5000 });
    ctrl.start();
    sched.advance(4999);
    expect(failed).toEqual([]);
    sched.advance(1);
    expect(failed).toEqual([true]);
    expect(ctrl.recovering()).toBe(false);
    expect(sched.pending).toBe(0);
  });

  it('fails at most once (idempotent)', () => {
    const { sched, ctrl, failed } = make({ windowMs: 100 });
    ctrl.start();
    sched.advance(100);
    ctrl.fail();
    ctrl.fail();
    expect(failed).toEqual([true]);
  });

  it('ignore further transition events after a failed recovery', () => {
    const { sched, ctrl, failed, recovered } = make({ windowMs: 100 });
    ctrl.start();
    sched.advance(100);
    ctrl.clear(); // stale "connected" after failure is ignored
    expect(recovered()).toBe(0);
    expect(failed).toEqual([true]);
  });

  it('dispose cancels the timer and does not fire callbacks', () => {
    const { sched, ctrl, failed, started } = make({ windowMs: 100 });
    ctrl.start();
    expect(started).toEqual([true]);
    ctrl.dispose();
    expect(sched.pending).toBe(0);
    sched.advance(200);
    expect(failed).toEqual([]);
  });

  it('force-fail from a failed restart is idempotent', () => {
    const { sched, ctrl, failed } = make({ windowMs: 5000 });
    ctrl.start();
    ctrl.fail();
    expect(failed).toEqual([true]);
    expect(sched.pending).toBe(0);
    expect(ctrl.recovering()).toBe(false);
  });
});
