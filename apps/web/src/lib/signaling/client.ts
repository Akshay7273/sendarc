/**
 * Browser signaling transport — a thin, typed wrapper over the native `WebSocket` that
 * speaks the SendArc signaling messages (`@sendarc/protocol`). It JSON-encodes outbound
 * frames, parses inbound ones back into {@link SignalMsg}, and retries the *initial*
 * connection with exponential backoff so a briefly-unreachable server (cold start, a
 * flaky network) does not fail the session before it begins.
 *
 * Reconnection is deliberately limited to that first connect. Once the socket has opened,
 * the server holds this session's room and pairing on *this* connection; a drop tears the
 * room down and notifies the peer with `bye`, so a fresh socket cannot resume it — it
 * would only allocate a new, unrelated room. Recovering a dropped session by
 * re-handshaking under the same code is a later milestone (plan.md §M6); here a
 * post-open close is surfaced as a terminal event for the caller to handle.
 */

import type { SignalMsg } from '@sendarc/protocol';

/**
 * A live, bidirectional signaling channel with a swappable inbound handler. The rendezvous layer
 * hands one of these to the M2 transfer layer (via `adoptSignaling`) once the handshake settles,
 * so the SDP/ICE exchange can reuse the still-open socket instead of opening a second one.
 */
export interface SignalChannel {
  send(msg: SignalMsg): void;
  onMessage(handler: (msg: SignalMsg) => void): void;
  close(): void;
}

/** Backoff schedule for the initial connect. Delays are `base * factor^n`, capped at `maxMs`. */
export interface BackoffOptions {
  /** Number of retries after the first attempt before giving up. */
  retries: number;
  baseMs: number;
  maxMs: number;
  factor: number;
  /** Random 0..jitter fraction added to each delay to avoid thundering herds. */
  jitter: number;
}

export const DEFAULT_BACKOFF: BackoffOptions = {
  retries: 5,
  baseMs: 250,
  maxMs: 4000,
  factor: 2,
  jitter: 0.25,
};

export interface SignalingClientOptions {
  url: string;
  /** A parsed inbound signaling message. */
  onMessage: (msg: SignalMsg) => void;
  /** The socket closed after having opened. `clean` is the WebSocket close cleanliness. */
  onClose?: (clean: boolean, code: number, reason: string) => void;
  /** A transport-level problem (connect exhausted, malformed inbound frame). */
  onError?: (err: Error) => void;
  backoff?: Partial<BackoffOptions>;
}

export class SignalingClient {
  private readonly opts: SignalingClientOptions;
  private readonly backoff: BackoffOptions;
  private ws?: WebSocket;
  private opened = false;
  private closedByUser = false;
  private retryTimer?: ReturnType<typeof setTimeout>;

  constructor(opts: SignalingClientOptions) {
    this.opts = opts;
    this.backoff = { ...DEFAULT_BACKOFF, ...opts.backoff };
  }

  /** True once the underlying socket is open and accepting sends. */
  get isOpen(): boolean {
    return this.opened && this.ws?.readyState === WebSocket.OPEN;
  }

  /**
   * Open the socket, retrying with backoff until the first successful open. Resolves when
   * open; rejects if every attempt fails or {@link close} is called first.
   */
  connect(): Promise<void> {
    return new Promise((resolve, reject) => this.attempt(0, resolve, reject));
  }

  private attempt(n: number, resolve: () => void, reject: (e: Error) => void): void {
    if (this.closedByUser) {
      reject(new Error('signaling: closed before connect'));
      return;
    }
    let ws: WebSocket;
    try {
      ws = new WebSocket(this.opts.url);
    } catch (err) {
      this.retryOrFail(n, resolve, reject, toError(err));
      return;
    }
    this.ws = ws;

    ws.onopen = () => {
      this.opened = true;
      resolve();
    };
    ws.onmessage = (ev: MessageEvent) => this.dispatch(ev);
    ws.onerror = () => {
      // The error event carries no detail; the following close event has the code.
      if (!this.opened) return; // handled by onclose → retry
    };
    ws.onclose = (ev: CloseEvent) => {
      if (this.opened) {
        // A drop after opening is terminal for this session (see the file header).
        this.opts.onClose?.(ev.wasClean, ev.code, ev.reason);
        return;
      }
      this.retryOrFail(
        n,
        resolve,
        reject,
        new Error(`signaling: connect failed (code ${ev.code})`),
      );
    };
  }

  private retryOrFail(
    n: number,
    resolve: () => void,
    reject: (e: Error) => void,
    err: Error,
  ): void {
    if (this.closedByUser || n >= this.backoff.retries) {
      reject(err);
      return;
    }
    const raw = Math.min(this.backoff.maxMs, this.backoff.baseMs * this.backoff.factor ** n);
    const delay = raw * (1 + Math.random() * this.backoff.jitter);
    this.retryTimer = setTimeout(() => this.attempt(n + 1, resolve, reject), delay);
  }

  private dispatch(ev: MessageEvent): void {
    if (typeof ev.data !== 'string') {
      this.opts.onError?.(new Error('signaling: non-text frame'));
      return;
    }
    let msg: SignalMsg;
    try {
      const parsed: unknown = JSON.parse(ev.data);
      if (
        typeof parsed !== 'object' ||
        parsed === null ||
        typeof (parsed as { type?: unknown }).type !== 'string'
      ) {
        throw new Error('missing type');
      }
      msg = parsed as SignalMsg;
    } catch (err) {
      this.opts.onError?.(new Error(`signaling: malformed frame: ${toError(err).message}`));
      return;
    }
    this.opts.onMessage(msg);
  }

  /** JSON-encode and send a signaling message. Throws if the socket is not open. */
  send(msg: SignalMsg): void {
    if (!this.isOpen) throw new Error('signaling: socket not open');
    this.ws!.send(JSON.stringify(msg));
  }

  /** Close the socket and cancel any pending reconnect. Idempotent. */
  close(code = 1000, reason = ''): void {
    this.closedByUser = true;
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.ws?.close(code, reason);
  }
}

function toError(err: unknown): Error {
  return err instanceof Error ? err : new Error(String(err));
}
