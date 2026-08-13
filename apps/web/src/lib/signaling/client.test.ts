import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { SignalMsg } from '@sendbeam/protocol';
import { SignalingClient, type SignalingClientOptions } from './client.js';

/**
 * Minimal fake WebSocket with a hand-triggered lifecycle, so the signaling client's
 * connect, post-open drop, and resume-reconnect paths are fully deterministic in unit tests
 * (no real sockets, no real timers beyond the injectable backoff).
 */
class FakeWebSocket {
  static OPEN = 1;
  readyState = 0; // CONNECTING
  binaryType = 'blob';
  onopen: (() => void) | null = null;
  onclose: ((ev: { wasClean: boolean; code: number; reason: string }) => void) | null = null;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onerror: (() => void) | null = null;
  sent: string[] = [];

  constructor(
    readonly url: string,
    private readonly onSocket?: (socket: FakeWebSocket) => void,
  ) {}

  static instances: FakeWebSocket[] = [];

  send(payload: string): void {
    this.sent.push(payload);
  }

  close(code = 1000, reason = ''): void {
    this.dispatchClose(true, code, reason);
  }

  /** Test helper: open the fake socket.
   */
  _open(): void {
    this.readyState = FakeWebSocket.OPEN;
    this.onopen?.();
  }

  /** Test helper: simulate a network (unclean) drop.
   */
  _drop(): void {
    this.readyState = 3; // CLOSED
    this.onclose?.({ wasClean: false, code: 1006, reason: 'network' });
  }

  /** Test helper: simulate a clean server close.
   */
  _cleanClose(code = 1000, reason = ''): void {
    this.readyState = 3;
    this.onclose?.({ wasClean: true, code, reason });
  }

  /** Test helper: push a text frame to the client.
   */
  _receiveText(payload: string): void {
    this.onmessage?.({ data: payload });
  }

  private dispatchClose(wasClean: boolean, code: number, reason: string): void {
    if (this.readyState === 3) return;
    this.readyState = 3;
    this.onclose?.({ wasClean, code, reason });
  }
}

function installFakeWebSocket(onSocket?: (socket: FakeWebSocket) => void): void {
  const Ws = class extends FakeWebSocket {
    constructor(url: string) {
      super(url, onSocket);
      FakeWebSocket.instances.push(this);
      onSocket?.(this);
    }
  } as unknown as typeof WebSocket;
  vi.stubGlobal('WebSocket', Ws);
}

function client(overrides: Partial<SignalingClientOptions> = {}) {
  const onMessage = vi.fn<(msg: SignalMsg) => void>();
  const onClose = vi.fn<(err: Error) => void>();
  const c = new SignalingClient({
    url: 'ws://example.test/ws',
    onMessage,
    onClose: (clean, code, reason) => onClose(new Error(`${clean} ${code} ${reason}`)),
    backoff: { retries: 5, baseMs: 1, maxMs: 2, factor: 1, jitter: 0 },
    ...overrides,
  });
  return { c, onMessage, onClose };
}

beforeEach(() => {
  FakeWebSocket.instances = [];
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe('SignalingClient — post-establishment reconnect/resume', () => {
  it('keeps a post-open drop terminal until resume is armed', async () => {
    installFakeWebSocket();
    const { c, onClose } = client();
    const connect = c.connect();
    const sock = FakeWebSocket.instances[0]!;
    sock._open();
    await connect;
    sock._drop();
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('does not attempt resume on a clean server close even when armed', async () => {
    installFakeWebSocket();
    const { c, onClose } = client();
    const connect = c.connect();
    c.setResume(7, 'offerer');
    const sock = FakeWebSocket.instances[0]!;
    sock._open();
    await connect;
    sock._cleanClose(1000, 'peer left');
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(FakeWebSocket.instances.length).toBe(1);
  });

  it('reconnects with resume on an unclean drop when armed, and consumes the resumed ack', async () => {
    // Second socket (the reconnect) is created automatically by the client; capture its sends.
    installFakeWebSocket();
    const { c, onMessage } = client();
    const connect = c.connect();
    c.setResume(7, 'offerer');
    const first = FakeWebSocket.instances[0]!;
    first._open();
    await connect;
    first._drop();

    // Give the (near-instant) backoff timer a chance to re-dial.
    await vi.waitFor(() => {
      expect(FakeWebSocket.instances.length).toBeGreaterThanOrEqual(2);
    });
    const resumed = FakeWebSocket.instances[1]!;
    resumed._open();
    expect(resumed.sent).toContain(JSON.stringify({ type: 'resume', room: 7, role: 'offerer' }));

    // The server's resumed ack must never reach the app layer.
    resumed._receiveText(JSON.stringify({ type: 'resumed', room: 7 }));
    expect(onMessage).not.toHaveBeenCalled();

    // Ordinary frames keep flowing after reconnect.
    resumed._receiveText('{"type":"sdp","sdp":"hi"}');
    expect(onMessage).toHaveBeenCalledWith(expect.objectContaining({ type: 'sdp', sdp: 'hi' }));
  });

  it('gives up reconnecting after the retry budget and surfaces a terminal close', async () => {
    installFakeWebSocket();
    const { c, onClose } = client({ resumeRetries: 1 });
    const connect = c.connect();
    c.setResume(7, 'joiner');
    const first = FakeWebSocket.instances[0]!;
    first._open();
    await connect;
    first._drop();

    // The first reconnect opens, then drops again — exhausting the single retry budget.
    await vi.waitFor(() => {
      expect(FakeWebSocket.instances.length).toBeGreaterThanOrEqual(2);
    });
    const rejoined = FakeWebSocket.instances[1]!;
    rejoined._open();
    rejoined._drop();

    expect(onClose).toHaveBeenCalledTimes(1);
    expect((onClose.mock.calls[0]![0] as Error).message).toContain('1006');
  });

  it('forwards peer_left/peer_rejoined intact (resume bookkeeping is server control, not hidden)', async () => {
    installFakeWebSocket();
    const { c, onMessage } = client();
    const connect = c.connect();
    const sock = FakeWebSocket.instances[0]!;
    sock._open();
    await connect;
    sock._receiveText('{"type":"peer_left","resumable":true}');
    sock._receiveText('{"type":"peer_rejoined"}');
    expect(onMessage).toHaveBeenCalledTimes(2);
  });

  it('cancels a pending reconnect on close', async () => {
    installFakeWebSocket();
    const { c, onClose } = client();
    const connect = c.connect();
    c.setResume(7, 'offerer');
    const sock = FakeWebSocket.instances[0]!;
    sock._open();
    await connect;
    // An unclean drop arms the reconnect timer; closing before it fires must cancel it and not
    // surface any terminal close.
    sock._drop();
    c.close();
    await new Promise((r) => setTimeout(r, 10));
    expect(onClose).not.toHaveBeenCalled();
    expect(FakeWebSocket.instances.length).toBe(1);
  });
});
