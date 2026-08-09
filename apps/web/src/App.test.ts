/** @vitest-environment jsdom */

import { mount, tick, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import App from './App.svelte';

const mocks = vi.hoisted(() => ({
  offer: vi.fn(),
  join: vi.fn(),
  runSend: vi.fn(),
  runReceive: vi.fn(),
}));

vi.mock('./lib/session/rendezvous.js', () => ({
  offer: mocks.offer,
  join: mocks.join,
}));

vi.mock('./lib/session/transfer.js', () => ({
  runSend: mocks.runSend,
  runReceive: mocks.runReceive,
}));

vi.mock('./lib/session/present.js', async () => {
  const actual = await vi.importActual<typeof import('./lib/session/present.js')>(
    './lib/session/present.js',
  );
  return { ...actual, sasFingerprint: vi.fn().mockResolvedValue('abcd 1234') };
});

interface Deferred<T> {
  promise: Promise<T>;
  resolve(value: T): void;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

async function settle(): Promise<void> {
  await Promise.resolve();
  await tick();
  await Promise.resolve();
  await tick();
}

describe('App transfer completion', () => {
  let target: HTMLDivElement;
  let component: ReturnType<typeof mount>;

  beforeEach(() => {
    mocks.offer.mockReset();
    mocks.join.mockReset();
    mocks.runSend.mockReset();
    mocks.runReceive.mockReset();
    target = document.createElement('div');
    document.body.append(target);
  });

  afterEach(async () => {
    if (component) await unmount(component);
    target.remove();
  });

  it('renders the verified outcome when the active transfer resolves', async () => {
    const handshake = deferred<unknown>();
    const completed = deferred<unknown>();
    const signaling = { send: vi.fn(), onMessage: vi.fn(), close: vi.fn() };
    const rendezvous = {
      code: undefined,
      phase: 'idle',
      done: handshake.promise,
      cancel: vi.fn(),
      adoptSignaling: vi.fn(() => signaling),
    };
    const transfer = {
      progress: vi.fn(() => 3),
      total: vi.fn(() => 3),
      done: completed.promise,
      cancel: vi.fn(),
    };
    mocks.offer.mockReturnValue(rendezvous);
    mocks.runSend.mockReturnValue(transfer);

    component = mount(App, { target });
    const sendButton = [...target.querySelectorAll('button')].find(
      (button) => button.textContent?.trim() === 'Send a file',
    );
    expect(sendButton).toBeDefined();
    sendButton!.click();

    handshake.resolve({
      master: new Uint8Array(32),
      remoteCaps: {
        version: 'sendarc/1',
        maxFrame: 16 * 1024,
        blockSize: 1024 * 1024,
        features: [],
        sinkHints: ['opfs'],
      },
      role: 'offerer',
    });
    await settle();

    const input = target.querySelector<HTMLInputElement>('input[type="file"]');
    expect(input).not.toBeNull();
    const file = new File([new Uint8Array([1, 2, 3])], 'proof.bin');
    Object.defineProperty(input, 'files', { configurable: true, value: [file] });
    input!.dispatchEvent(new Event('change', { bubbles: true }));
    await settle();
    expect(mocks.runSend).toHaveBeenCalledOnce();

    completed.resolve({
      name: 'proof.bin',
      size: 3,
      digest: '039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81',
    });
    await settle();

    expect(target.textContent).toContain('Sent proof.bin — verified by the receiver.');
  });
});
