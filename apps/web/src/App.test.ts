/** @vitest-environment jsdom */

import { mount, tick, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import App from './App.svelte';

const mocks = vi.hoisted(() => ({
  offer: vi.fn(),
  join: vi.fn(),
  runSend: vi.fn(),
  runReceive: vi.fn(),
  listJournals: vi.fn(),
  discardDurableTransfer: vi.fn(),
  durableOpfsFiles: vi.fn(),
  indexedDbDurableStore: vi.fn(),
  listSenderRecords: vi.fn(),
  removeSenderRecord: vi.fn(),
  senderRecordStoreWhenAvailable: vi.fn(),
  ensureReadPermission: vi.fn(),
  materializeHandle: vi.fn(),
  canonicalizeFiles: vi.fn(),
  cheapSourceCheck: vi.fn(),
}));

// V13-PR08 (Blocker 3/4): interrupted-sends surface + handle reattachment. The sender record
// store and the File System Access helpers are mocked so the real App flow can be driven.
vi.mock('./lib/transfer/sender-record.js', () => ({
  senderRecordStoreWhenAvailable: mocks.senderRecordStoreWhenAvailable,
}));

vi.mock('./lib/transfer/sender-reattach.js', () => ({
  canonicalizeFiles: mocks.canonicalizeFiles,
  cheapSourceCheck: mocks.cheapSourceCheck,
  ensureReadPermission: mocks.ensureReadPermission,
  materializeHandle: mocks.materializeHandle,
}));

// V13-PR08 (Blocker 2): the interrupted-receives surface reads the durable store. Mock it
// with a controllable journal list so the App component test can drive the real flow.
vi.mock('./lib/transfer/durable-store.js', () => ({
  discardDurableTransfer: mocks.discardDurableTransfer,
  durableOpfsFiles: mocks.durableOpfsFiles,
  indexedDbDurableStore: mocks.indexedDbDurableStore,
}));

/** A fake durable journal entry (safe metadata + credential envelope, never secrets). */
function journalEntry(transferId: string, label: string): unknown {
  return {
    transferId,
    kind: 'ok',
    journal: {
      transferId,
      files: [{ name: label, size: 24, committedBlocks: 2, blockSize: 8 }],
      manifestFingerprint: 'f'.repeat(64),
      resumeSecret: { format: 1, bytes: new Uint8Array([1, 2, 3, 4]) },
      updatedAt: 1_700_000_000_000,
    },
  };
}

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
    mocks.listJournals.mockReset();
    mocks.discardDurableTransfer.mockReset();
    mocks.durableOpfsFiles.mockReset();
    mocks.indexedDbDurableStore.mockReset();
    mocks.listSenderRecords.mockReset();
    mocks.removeSenderRecord.mockReset();
    mocks.senderRecordStoreWhenAvailable.mockReset();
    mocks.ensureReadPermission.mockReset();
    mocks.materializeHandle.mockReset();
    mocks.canonicalizeFiles.mockReset();
    mocks.cheapSourceCheck.mockReset();
    // Default: no durable store (no journals), matching a fresh profile.
    mocks.indexedDbDurableStore.mockReturnValue({ listJournals: mocks.listJournals });
    mocks.listJournals.mockResolvedValue([]);
    // Default: no sender-record store (no interrupted sends).
    mocks.senderRecordStoreWhenAvailable.mockReturnValue(undefined);
    mocks.canonicalizeFiles.mockImplementation((files: File[]) => [...files]);
    mocks.cheapSourceCheck.mockReturnValue(undefined);
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
    const signaling = {
      send: vi.fn(),
      sendBinary: vi.fn(),
      onMessage: vi.fn(),
      onBinary: vi.fn(),
      onClose: vi.fn(),
      close: vi.fn(),
    };
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
      snapshot: vi.fn(() => ({
        bytes: 3,
        total: 3,
        rateBps: 1024,
        etaSeconds: 0,
        state: 'running',
      })),
      transport: vi.fn(() => 'direct'),
      done: completed.promise,
      pause: vi.fn(),
      resume: vi.fn(),
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
        version: 'sendbeam/1',
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

    const pauseButton = [...target.querySelectorAll('button')].find(
      (button) => button.textContent?.trim() === 'Pause',
    );
    expect(pauseButton).toBeDefined();
    pauseButton!.click();
    expect(transfer.pause).toHaveBeenCalledOnce();

    completed.resolve({
      name: 'proof.bin',
      size: 3,
      digest: '039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81',
    });
    await settle();

    expect(target.textContent).toContain('Sent proof.bin — verified by the receiver.');
  });

  it('receives the exact selected journal attempt once (V13-PR08 Blocker 2)', async () => {
    const entry = journalEntry('a'.repeat(32), 'archive.bin');
    mocks.listJournals.mockResolvedValue([entry]);
    const handshake = deferred<unknown>();
    const signaling = {
      send: vi.fn(),
      sendBinary: vi.fn(),
      onMessage: vi.fn(),
      onBinary: vi.fn(),
      onClose: vi.fn(),
      close: vi.fn(),
    };
    const rendezvous = {
      code: undefined,
      phase: 'idle',
      done: handshake.promise,
      cancel: vi.fn(),
      adoptSignaling: vi.fn(() => signaling),
    };
    const transfer = {
      progress: vi.fn(() => 0),
      total: vi.fn(() => undefined),
      snapshot: vi.fn(() => ({
        bytes: 0,
        reusedBytes: 0,
        sessionBytes: 0,
        total: undefined,
        rateBps: 0,
        etaSeconds: undefined,
        state: 'running' as const,
      })),
      transport: vi.fn(() => 'direct'),
      done: deferred<unknown>().promise,
      pause: vi.fn(),
      resume: vi.fn(),
      cancel: vi.fn(),
    };
    mocks.join.mockReturnValue(rendezvous);
    mocks.runReceive.mockReturnValue(transfer);

    component = mount(App, { target });
    await settle();
    await settle();
    await settle();
    // The interrupted receive is listed on the home screen.
    const resumeButton = [...target.querySelectorAll('button')].find(
      (button) => button.textContent?.trim() === 'Resume',
    );
    expect(resumeButton).toBeDefined();
    resumeButton!.click();
    await settle();

    // The ordinary save-to selector is disabled while a resume is armed (Blocker 7).
    const select = target.querySelector<HTMLSelectElement>('#destination');
    expect(select?.disabled).toBe(true);

    // Submit the fresh invite code.
    const input = target.querySelector<HTMLInputElement>('#code');
    expect(input).not.toBeNull();
    input!.value = 'fresh-code-1234';
    input!.dispatchEvent(new Event('input', { bubbles: true }));
    await settle();
    const receiveButton = [...target.querySelectorAll('button')].find(
      (button) => button.textContent?.trim() === 'Receive',
    );
    receiveButton!.click();
    await settle();

    // The rendezvous advertises resume-auth-v1 ONLY for this armed attempt.
    expect(mocks.join).toHaveBeenCalledOnce();
    const joinOpts = mocks.join.mock.calls[0]![0] as {
      code: string;
      localCaps: { features: string[] };
    };
    expect(joinOpts.code).toBe('fresh-code-1234');
    expect(joinOpts.localCaps.features).toContain('resume-auth-v1');

    // Rendezvous completes as the joiner; the peer supports authenticated resume.
    handshake.resolve({
      master: new Uint8Array(32),
      remoteCaps: {
        version: 'sendbeam/1',
        maxFrame: 16 * 1024,
        blockSize: 1024 * 1024,
        features: ['resume-auth-v1'],
        sinkHints: ['opfs'],
      },
      role: 'joiner',
    });
    await settle();
    await settle();

    // runReceive receives entry A's exact transferId/fingerprint/credential EXACTLY once,
    // and the destination is the forced durable auto spec (Blocker 7).
    expect(mocks.runReceive).toHaveBeenCalledOnce();
    const [rendezvousArg, , destination, opts] = mocks.runReceive.mock.calls[0]!;
    // The receiver starts the worker with the settled rendezvous (the resolved value).
    expect((rendezvousArg as { role: string }).role).toBe('joiner');
    expect(destination).toEqual({ kind: 'auto' });
    const attempt = (opts as { resumeAttempt?: unknown }).resumeAttempt;
    expect(attempt).toEqual({
      transferId: 'a'.repeat(32),
      manifestFingerprint: 'f'.repeat(64),
      role: 'joiner',
      envelope: (entry as { journal: { resumeSecret: unknown } }).journal.resumeSecret,
    });
  });

  it('cancel clears the armed resume; a later ordinary receive has no attempt (V13-PR08 Blocker 2)', async () => {
    const entry = journalEntry('b'.repeat(32), 'notes.bin');
    mocks.listJournals.mockResolvedValue([entry]);
    const handshake = deferred<unknown>();
    const signaling = {
      send: vi.fn(),
      sendBinary: vi.fn(),
      onMessage: vi.fn(),
      onBinary: vi.fn(),
      onClose: vi.fn(),
      close: vi.fn(),
    };
    const rendezvous = {
      code: undefined,
      phase: 'idle',
      done: handshake.promise,
      cancel: vi.fn(),
      adoptSignaling: vi.fn(() => signaling),
    };
    const transfer = {
      progress: vi.fn(() => 0),
      total: vi.fn(() => undefined),
      snapshot: vi.fn(() => ({
        bytes: 0,
        reusedBytes: 0,
        sessionBytes: 0,
        total: undefined,
        rateBps: 0,
        etaSeconds: undefined,
        state: 'running' as const,
      })),
      transport: vi.fn(() => 'direct'),
      done: deferred<unknown>().promise,
      pause: vi.fn(),
      resume: vi.fn(),
      cancel: vi.fn(),
    };
    mocks.join.mockReturnValue(rendezvous);
    mocks.runReceive.mockReturnValue(transfer);

    component = mount(App, { target });
    await settle();
    await settle();
    await settle();
    const resumeButton = [...target.querySelectorAll('button')].find(
      (button) => button.textContent?.trim() === 'Resume',
    );
    resumeButton!.click();
    await settle();

    // Submit the code and land on the receiving screen, then Cancel (back home).
    const input = target.querySelector<HTMLInputElement>('#code');
    input!.value = 'code-cancel';
    input!.dispatchEvent(new Event('input', { bubbles: true }));
    await settle();
    const receiveButton = [...target.querySelectorAll('button')].find(
      (button) => button.textContent?.trim() === 'Receive',
    );
    receiveButton!.click();
    await settle();
    const cancelButton = [...target.querySelectorAll('button')].find(
      (button) => button.textContent?.trim() === 'Cancel',
    );
    cancelButton!.click();
    await settle();
    await settle();
    // The armed resume is gone: the save-to selector is re-enabled and no attempt is armed.
    const select = target.querySelector<HTMLSelectElement>('#destination');
    expect(select?.disabled).toBe(false);

    // A later ORDINARY receive (no resume selected) joins without resume-auth-v1 and passes
    // no resumeAttempt to the worker.
    mocks.listJournals.mockResolvedValue([]);
    mocks.join.mockClear();
    const handshake2 = deferred<unknown>();
    const rendezvous2 = {
      code: undefined,
      phase: 'idle',
      done: handshake2.promise,
      cancel: vi.fn(),
      adoptSignaling: vi.fn(() => signaling),
    };
    mocks.join.mockReturnValue(rendezvous2);
    // The home screen re-rendered after backHome: re-query the live code input.
    const input2 = target.querySelector<HTMLInputElement>('#code');
    expect(input2).not.toBeNull();
    input2!.value = 'fresh-code-2';
    input2!.dispatchEvent(new Event('input', { bubbles: true }));
    await settle();
    const receiveButton2 = [...target.querySelectorAll('button')].find(
      (button) => button.textContent?.trim() === 'Receive',
    );
    receiveButton2!.click();
    await settle();
    const joinOpts = mocks.join.mock.calls[0]![0] as { localCaps: { features: string[] } };
    expect(joinOpts.localCaps.features).not.toContain('resume-auth-v1');
    handshake2.resolve({
      master: new Uint8Array(32),
      remoteCaps: {
        version: 'sendbeam/1',
        maxFrame: 16 * 1024,
        blockSize: 1024 * 1024,
        features: [],
        sinkHints: ['opfs'],
      },
      role: 'joiner',
    });
    await settle();
    await settle();
    // The FIRST receive was canceled before its rendezvous resolved, so no worker started
    // for it; the later ordinary receive is the only one that reached runReceive, and it
    // carries no resume attempt.
    expect(mocks.runReceive).toHaveBeenCalledOnce();
    const opts = mocks.runReceive.mock.calls[0]![3] as { resumeAttempt?: unknown };
    expect(opts.resumeAttempt).toBeUndefined();
  });

  it('persistent-handle sender resume runs the preamble (V13-PR08 Blocker 3)', async () => {
    // The interrupted send holds a credential and a reopenable directory handle.
    const envelope = { format: 1, bytes: new Uint8Array([9, 9, 9]) };
    const record = {
      transferId: 'c'.repeat(32),
      manifestFingerprint: 'd'.repeat(64),
      files: [{ name: 'photo.bin', size: 8 }],
      reattachment: { kind: 'handle', handleKind: 'directory', handle: {} },
      resumeSecret: envelope,
      updatedAt: 1_700_000_000_000,
    };
    mocks.listSenderRecords.mockResolvedValue([
      { transferId: record.transferId, kind: 'ok', record },
    ]);
    mocks.senderRecordStoreWhenAvailable.mockReturnValue({
      list: mocks.listSenderRecords,
      remove: mocks.removeSenderRecord,
    });
    const file = new File([new Uint8Array([1, 2, 3])], 'photo.bin');
    mocks.ensureReadPermission.mockResolvedValue(true);
    mocks.materializeHandle.mockResolvedValue([file]);

    const handshake = deferred<unknown>();
    const signaling = {
      send: vi.fn(),
      sendBinary: vi.fn(),
      onMessage: vi.fn(),
      onBinary: vi.fn(),
      onClose: vi.fn(),
      close: vi.fn(),
    };
    const rendezvous = {
      code: undefined,
      phase: 'idle',
      done: handshake.promise,
      cancel: vi.fn(),
      adoptSignaling: vi.fn(() => signaling),
    };
    const transfer = {
      progress: vi.fn(() => 0),
      total: vi.fn(() => 8),
      snapshot: vi.fn(() => ({
        bytes: 0,
        reusedBytes: 0,
        sessionBytes: 0,
        total: 8,
        rateBps: 0,
        etaSeconds: undefined,
        state: 'running' as const,
      })),
      transport: vi.fn(() => 'direct'),
      done: deferred<unknown>().promise,
      pause: vi.fn(),
      resume: vi.fn(),
      cancel: vi.fn(),
    };
    mocks.offer.mockReturnValue(rendezvous);
    mocks.runSend.mockReturnValue(transfer);

    component = mount(App, { target });
    await settle();
    await settle();
    await settle();
    // The interrupted send is listed on the home screen; Resume creates the fresh offer
    // and advertises resume-auth-v1 for this rendezvous.
    const resumeButton = [...target.querySelectorAll('button')].find(
      (button) => button.textContent?.trim() === 'Resume',
    );
    expect(resumeButton).toBeDefined();
    resumeButton!.click();
    await settle();
    const offerOpts = mocks.offer.mock.calls[0]![0] as { localCaps: { features: string[] } };
    expect(offerOpts.localCaps.features).toContain('resume-auth-v1');

    // The fresh rendezvous completes as the offerer; the peer supports authenticated resume.
    handshake.resolve({
      master: new Uint8Array(32),
      remoteCaps: {
        version: 'sendbeam/1',
        maxFrame: 16 * 1024,
        blockSize: 1024 * 1024,
        features: ['resume-auth-v1'],
        sinkHints: ['opfs'],
      },
      role: 'offerer',
    });
    await settle();
    await settle();

    // "Send again" on the record reopens the persisted handle and starts the authenticated
    // resume: the stored transferId + fingerprint + offerer role + credential all reach
    // runSend (the worker then runs the resume preamble before any progress reuse).
    const sendAgainButton = [...target.querySelectorAll('button')].find(
      (button) => button.textContent?.trim() === 'Send again',
    );
    expect(sendAgainButton).toBeDefined();
    sendAgainButton!.click();
    await settle();
    await settle();
    expect(mocks.materializeHandle).toHaveBeenCalledOnce();
    expect(mocks.runSend).toHaveBeenCalledOnce();
    const [, , opts] = mocks.runSend.mock.calls[0]! as [unknown, unknown, Record<string, unknown>];
    expect(opts.transferId).toBe(record.transferId);
    expect(opts.reattachment).toEqual(record.reattachment);
    expect(opts.resumeAttempt).toEqual({
      transferId: record.transferId,
      manifestFingerprint: record.manifestFingerprint,
      role: 'offerer',
      envelope,
    });
  });

  it('legacy sender record without a credential cannot send again (V13-PR08 Blocker 3)', async () => {
    const record = {
      transferId: 'e'.repeat(32),
      manifestFingerprint: 'f'.repeat(64),
      files: [{ name: 'old.bin', size: 8 }],
      reattachment: { kind: 'reselection' },
      resumeSecret: undefined,
      updatedAt: 1_700_000_000_000,
    };
    mocks.listSenderRecords.mockResolvedValue([
      { transferId: record.transferId, kind: 'ok', record },
    ]);
    mocks.senderRecordStoreWhenAvailable.mockReturnValue({
      list: mocks.listSenderRecords,
      remove: mocks.removeSenderRecord,
    });
    component = mount(App, { target });
    await settle();
    await settle();
    await settle();
    // On the home screen the pre-rendezvous action is "Resume"; a legacy no-secret record
    // cannot resume — the button is disabled and the reason is stated.
    const resumeButton = [...target.querySelectorAll('button')].find(
      (button) => button.textContent?.trim() === 'Resume',
    );
    expect(resumeButton).toBeDefined();
    expect((resumeButton as HTMLButtonElement).disabled).toBe(true);
    expect(target.textContent).toContain('restart required (no credential)');
  });

  it('sender resume fails closed before the worker when the peer lacks resume-auth-v1 (V13-PR08 Blocker 4)', async () => {
    const record = {
      transferId: 'c'.repeat(32),
      manifestFingerprint: 'd'.repeat(64),
      files: [{ name: 'photo.bin', size: 8 }],
      reattachment: { kind: 'reselection' },
      resumeSecret: { format: 1, bytes: new Uint8Array([1]) },
      updatedAt: 1_700_000_000_000,
    };
    mocks.listSenderRecords.mockResolvedValue([
      { transferId: record.transferId, kind: 'ok', record },
    ]);
    mocks.senderRecordStoreWhenAvailable.mockReturnValue({
      list: mocks.listSenderRecords,
      remove: mocks.removeSenderRecord,
    });
    const handshake = deferred<unknown>();
    const signaling = {
      send: vi.fn(),
      sendBinary: vi.fn(),
      onMessage: vi.fn(),
      onBinary: vi.fn(),
      onClose: vi.fn(),
      close: vi.fn(),
    };
    mocks.offer.mockReturnValue({
      code: undefined,
      phase: 'idle',
      done: handshake.promise,
      cancel: vi.fn(),
      adoptSignaling: vi.fn(() => signaling),
    });
    component = mount(App, { target });
    await settle();
    await settle();
    await settle();
    const resumeButton = [...target.querySelectorAll('button')].find(
      (button) => button.textContent?.trim() === 'Resume',
    );
    resumeButton!.click();
    await settle();
    // The peer is a normal/old peer: NO resume-auth-v1 in this rendezvous.
    handshake.resolve({
      master: new Uint8Array(32),
      remoteCaps: {
        version: 'sendbeam/1',
        maxFrame: 16 * 1024,
        blockSize: 1024 * 1024,
        features: [],
        sinkHints: ['opfs'],
      },
      role: 'offerer',
    });
    await settle();
    await settle();
    const input = target.querySelector<HTMLInputElement>('input[type="file"]');
    const file = new File([new Uint8Array([1, 2, 3])], 'photo.bin');
    Object.defineProperty(input, 'files', { configurable: true, value: [file] });
    input!.dispatchEvent(new Event('change', { bubbles: true }));
    await settle();
    await settle();
    // The old transferId never reaches the transfer engine: runSend was NOT called and the
    // failure screen explains the capability gap.
    expect(mocks.runSend).not.toHaveBeenCalled();
    expect(target.textContent).toContain('did not advertise authenticated resume');
  });

  it('receiver resume with a peer lacking resume-auth-v1 proceeds fresh, journal preserved (V13-PR08 Blocker 4)', async () => {
    const entry = journalEntry('d'.repeat(32), 'kept.bin');
    mocks.listJournals.mockResolvedValue([entry]);
    const handshake = deferred<unknown>();
    const signaling = {
      send: vi.fn(),
      sendBinary: vi.fn(),
      onMessage: vi.fn(),
      onBinary: vi.fn(),
      onClose: vi.fn(),
      close: vi.fn(),
    };
    const rendezvous = {
      code: undefined,
      phase: 'idle',
      done: handshake.promise,
      cancel: vi.fn(),
      adoptSignaling: vi.fn(() => signaling),
    };
    const transfer = {
      progress: vi.fn(() => 0),
      total: vi.fn(() => undefined),
      snapshot: vi.fn(() => ({
        bytes: 0,
        reusedBytes: 0,
        sessionBytes: 0,
        total: undefined,
        rateBps: 0,
        etaSeconds: undefined,
        state: 'running' as const,
      })),
      transport: vi.fn(() => 'direct'),
      done: deferred<unknown>().promise,
      pause: vi.fn(),
      resume: vi.fn(),
      cancel: vi.fn(),
    };
    mocks.join.mockReturnValue(rendezvous);
    mocks.runReceive.mockReturnValue(transfer);
    component = mount(App, { target });
    await settle();
    await settle();
    await settle();
    const resumeButton = [...target.querySelectorAll('button')].find(
      (button) => button.textContent?.trim() === 'Resume',
    );
    resumeButton!.click();
    await settle();
    const input = target.querySelector<HTMLInputElement>('#code');
    input!.value = 'fresh-code';
    input!.dispatchEvent(new Event('input', { bubbles: true }));
    await settle();
    [...target.querySelectorAll('button')]
      .find((b) => b.textContent?.trim() === 'Receive')!
      .click();
    await settle();
    // The peer is a fresh/normal sender: no resume-auth-v1.
    handshake.resolve({
      master: new Uint8Array(32),
      remoteCaps: {
        version: 'sendbeam/1',
        maxFrame: 16 * 1024,
        blockSize: 1024 * 1024,
        features: [],
        sinkHints: ['opfs'],
      },
      role: 'joiner',
    });
    await settle();
    await settle();
    // The receive proceeds as genuinely fresh — no resumeAttempt is passed to the worker,
    // and the kept journal is never touched (the durable gate would refuse any reuse).
    expect(mocks.runReceive).toHaveBeenCalledOnce();
    const opts = mocks.runReceive.mock.calls[0]![3] as { resumeAttempt?: unknown };
    expect(opts.resumeAttempt).toBeUndefined();
  });
});
