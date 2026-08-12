import { describe, it, expect } from 'vitest';
import { GenerationGuard } from './generation.js';

describe('GenerationGuard stale-continuation rejection', () => {
  it('runs work while current and rejects it after a bump', () => {
    const guard = new GenerationGuard();
    const captured = guard.capture();
    let ran = 0;

    // Continuation fires before any teardown: expected to run.
    expect(guard.isCurrent(captured)).toBe(true);
    guard.guard(captured, () => ran++);
    expect(ran).toBe(1);

    // Tear down the session (cancel/finish/fail all bump), then fire the same
    // captured continuation: it must be rejected before running.
    guard.bump();
    expect(guard.isCurrent(captured)).toBe(false);
    guard.guard(captured, () => ran++);
    expect(ran).toBe(1); // not incremented — the stale continuation was dropped
  });

  it('a late continuation cannot switch transports after cleanup', () => {
    const guard = new GenerationGuard();
    const captured = guard.capture();
    let transport: 'direct' | 'relay' = 'direct';
    const assumeItCanSwitch = () => (transport = 'relay');

    // The continuation is registered while direct; cleanup then bumps.
    guard.bump();
    guard.guard(captured, assumeItCanSwitch);

    // The transport must not have been switched by the late continuation.
    expect(transport).toBe('direct');
  });

  it('a late continuation cannot send frames after cleanup', () => {
    const guard = new GenerationGuard();
    const captured = guard.capture();
    const frames: number[] = [];
    const sendOutbound = (frame: number, generation: number) =>
      guard.guard(generation, () => frames.push(frame));

    // Send while current.
    sendOutbound(1, captured);
    expect(frames).toEqual([1]);

    // Cleanup, then a late outbound frame is dropped.
    guard.bump();
    sendOutbound(2, captured);
    expect(frames).toEqual([1]);
    // A continuation captured after the bump is still live.
    const later = guard.capture();
    sendOutbound(3, later);
    expect(frames).toEqual([1, 3]);
  });

  it('a late continuation cannot resolve/reject the same promise twice', async () => {
    const guard = new GenerationGuard();
    let resolveFn!: (v: string) => void;
    const promise = new Promise<string>((resolve) => {
      resolveFn = resolve;
    });
    let resolveCount = 0;
    const safeResolve = (value: string, generation: number) => {
      if (guard.isCurrent(generation)) {
        resolveCount++;
        resolveFn(value);
      }
    };

    const captured = guard.capture();
    safeResolve('first', captured);
    expect(resolveCount).toBe(1);
    expect(await promise).toBe('first');

    // A stale second resolution attempt (holding the OLD captured generation)
    // is dropped: the promise was already settled, resolveCount stays at 1.
    guard.bump();
    safeResolve('stale', captured);
    expect(resolveCount).toBe(1);
    expect(await promise).toBe('first');
  });

  it('a stale continuation cannot touch terminated resources', () => {
    const generation = new GenerationGuard();
    const captured = generation.capture();
    let terminated = false;
    const peerCloseCalls: Array<number> = [];
    let peerTouched = 0;
    // The guard check runs before touching the resource, so a stale continuation
    // can never reach the terminated-resource body.
    const closePeer = (id: number, gen: number) => {
      if (!generation.isCurrent(gen)) return;
      if (terminated) throw new Error('resource already terminated');
      peerCloseCalls.push(id);
      peerTouched++;
    };

    closePeer(1, captured);
    expect(peerCloseCalls).toEqual([1]);

    // Terminate the resource and bump the generation: a stale close attempt is
    // dropped before it can touch the terminated peer.
    terminated = true;
    generation.bump();
    closePeer(2, captured);
    expect(peerCloseCalls).toEqual([1]);
    expect(peerTouched).toBe(1);
  });

  it('capture points taken after a bump are distinct and live', () => {
    const guard = new GenerationGuard();
    const a = guard.capture();
    guard.bump();
    const b = guard.capture();
    expect(guard.isCurrent(a)).toBe(false);
    expect(guard.isCurrent(b)).toBe(true);
    expect(a).not.toBe(b);
  });
});
