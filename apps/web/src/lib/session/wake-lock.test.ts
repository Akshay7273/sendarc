/** @vitest-environment jsdom */

import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest';

import { WakeLockManager } from './wake-lock.js';

interface FakeSentinel {
  release: Mock<() => Promise<void>>;
  addEventListener: Mock<(type: string, fn: () => void) => void>;
}

function makeSentinel(): FakeSentinel {
  const listeners: Record<string, Array<() => void>> = {};
  return {
    release: vi.fn(() => {
      for (const fn of listeners['release'] ?? []) fn();
      return Promise.resolve();
    }),
    addEventListener: vi.fn((type: string, fn: () => void) => {
      (listeners[type] ??= []).push(fn);
    }),
  };
}

function setVisibility(state: 'visible' | 'hidden'): void {
  Object.defineProperty(document, 'visibilityState', {
    configurable: true,
    value: state,
  });
}

function withWakeLock(request: Mock<() => Promise<WakeLockSentinel>>): void {
  Object.defineProperty(navigator, 'wakeLock', { configurable: true, value: { request } });
}

function withoutWakeLock(): void {
  delete (navigator as { wakeLock?: unknown }).wakeLock;
}

function navigatorRequest(): Mock<() => Promise<WakeLockSentinel>> {
  return (
    navigator as unknown as {
      wakeLock: { request: Mock<() => Promise<WakeLockSentinel>> };
    }
  ).wakeLock.request;
}

async function settle(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
}

const managers: WakeLockManager[] = [];

function makeManager(): WakeLockManager {
  const manager = new WakeLockManager();
  managers.push(manager);
  return manager;
}

beforeEach(() => {
  setVisibility('visible');
});

afterEach(() => {
  for (const manager of managers) manager.dispose();
  managers.length = 0;
  setVisibility('visible');
  withoutWakeLock();
});

describe('WakeLockManager', () => {
  it('acquires while active and releases when it stops', async () => {
    const sentinel = makeSentinel();
    withWakeLock(vi.fn().mockResolvedValue(sentinel));
    const manager = makeManager();

    manager.setActive(true);
    await settle();
    expect(navigatorRequest()).toHaveBeenCalledOnce();
    expect(sentinel.release).not.toHaveBeenCalled();

    manager.setActive(false);
    await settle();
    expect(sentinel.release).toHaveBeenCalledOnce();
  });

  it('does not request twice while already held', async () => {
    const sentinel = makeSentinel();
    withWakeLock(vi.fn().mockResolvedValue(sentinel));
    const manager = makeManager();

    manager.setActive(true);
    await settle();
    manager.setActive(true);
    await settle();
    expect(navigatorRequest()).toHaveBeenCalledOnce();
  });

  it('does not acquire when never activated', async () => {
    const sentinel = makeSentinel();
    withWakeLock(vi.fn().mockResolvedValue(sentinel));
    makeManager();

    await settle();
    expect(navigatorRequest()).not.toHaveBeenCalled();
  });

  it('releases on visibility loss and re-acquires when visible again', async () => {
    const sentinel = makeSentinel();
    withWakeLock(vi.fn().mockResolvedValue(sentinel));
    const manager = makeManager();
    manager.setActive(true);
    await settle();
    expect(navigatorRequest()).toHaveBeenCalledOnce();

    setVisibility('hidden');
    document.dispatchEvent(new Event('visibilitychange'));
    await settle();
    expect(sentinel.release).toHaveBeenCalledOnce();

    setVisibility('visible');
    document.dispatchEvent(new Event('visibilitychange'));
    await settle();
    expect(navigatorRequest()).toHaveBeenCalledTimes(2);
  });

  it('re-acquires when the browser drops the lock while still active', async () => {
    const sentinel = makeSentinel();
    withWakeLock(vi.fn().mockResolvedValue(sentinel));
    const manager = makeManager();
    manager.setActive(true);
    await settle();
    expect(navigatorRequest()).toHaveBeenCalledOnce();

    sentinel.release();
    await settle();
    expect(navigatorRequest()).toHaveBeenCalledTimes(2);
  });

  it('is a no-op where the Wake Lock API is missing', async () => {
    withoutWakeLock();
    const manager = makeManager();

    manager.setActive(true);
    await settle();
    expect('wakeLock' in navigator).toBe(false);
  });

  it('keeps working when the request is denied', async () => {
    const sentinel = makeSentinel();
    withWakeLock(vi.fn().mockRejectedValue(new Error('denied')));
    const manager = makeManager();

    manager.setActive(true);
    await settle();
    expect(navigatorRequest()).toHaveBeenCalledOnce();
    expect(sentinel.release).not.toHaveBeenCalled();
  });
});
