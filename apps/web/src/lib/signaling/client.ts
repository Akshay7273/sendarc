/**
 * Browser signaling transport — a thin, typed wrapper over the native `WebSocket` that
 * speaks the SendBeam signaling messages (`@sendbeam/protocol`). It JSON-encodes outbound
 * frames, parses inbound ones back into {@link SignalMsg}, and retries the *initial*
 * connection with exponential backoff so a briefly-unreachable server (cold start, a
 * flaky network) does not fail the session before it begins.
 *
 * Reconnection is deliberately limited to that first connect while the room is being
 * negotiated. Once the handshake settles and the transfer layer arms {@link SignalChannel.setResume}
 * with the room number and role, a post-establishment drop is no longer terminal: the socket
 * is re-dialed (bounded backoff) and re-attached to the lingering room with a `resume` request
 * (the CLI twin is `wsclient.ReconnectingSignal`), so a later ICE-restart renegotiation's
 * SDP/ICE frames can still flow while a healthy direct path keeps transferring. Until resume is
 * armed, a post-open close stays a terminal event for the caller to handle.
 */

import type { SignalMsg } from '@sendbeam/protocol';

/**
 * A live, bidirectional signaling channel with a swappable inbound handler. The rendezvous layer
 * hands one of these to the transfer layer (via `adoptSignaling`) once the handshake settles,
 * so the SDP/ICE exchange can reuse the still-open socket instead of opening a second one.
 */
export interface SignalChannel {
  send(msg: SignalMsg): void;
  sendBinary(frame: ArrayBuffer): void;
  onMessage(handler: (msg: SignalMsg) => void): void;
  onBinary(handler: (frame: ArrayBuffer) => void): void;
  onClose(handler: (err: Error) => void): void;
  /**
   * Arm post-open reconnect: once the room number and role are known, a dropped socket is
   * re-dialed and resumed onto the lingering room (V12-PR04 signaling recovery) so a later
   * ICE-restart renegotiation's SDP/ICE frames can still flow. Until this is called, a
   * post-open drop stays terminal (the handshake/transfer fails closed).
   */
  setResume(room: number, role: string): void;
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
  onBinary?: (frame: ArrayBuffer) => void;
  /** The socket closed after having opened. `clean` is the WebSocket close cleanliness. */
  onClose?: (clean: boolean, code: number, reason: string) => void;
  /** A transport-level problem (connect exhausted, malformed inbound frame). */
  onError?: (err: Error) => void;
  backoff?: Partial<BackoffOptions>;
  /** Number of re-dial attempts after a post-establishment drop before giving up. */
  resumeRetries?: number;
}

/** Server → client control frames the reconnecting client consumes internally during the room
 * resume flow: they describe signaling-room state, not application frames. Only `resumed` is
 * filtered here; `peer_left`/`peer_rejoined` are forwarded intact to the active handler. */
const SERVER_CONTROL_TYPES: ReadonlySet<string> = new Set(['resumed']);

export class SignalingClient {
  private readonly opts: SignalingClientOptions;
  private readonly backoff: BackoffOptions;
  private readonly resumeRetries: number;
  private ws?: WebSocket;
  private opened = false;
  private closedByUser = false;
  private retryTimer?: ReturnType<typeof setTimeout>;

  // Post-establishment resume state, armed via setResume() once the room is known.
  private resume?: { room: number; role: string };
  private reconnectTimer?: ReturnType<typeof setTimeout>;
  private reconnectAttempt = 0;

  constructor(opts: SignalingClientOptions) {
    this.opts = opts;
    this.backoff = { ...DEFAULT_BACKOFF, ...opts.backoff };
    this.resumeRetries = opts.resumeRetries ?? DEFAULT_BACKOFF.retries;
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
    ws.binaryType = 'arraybuffer';

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
        this.opened = false;
        // A drop after opening: the session is resumable once resume is armed and the drop was
        // a network blip (unclean). A clean close is a deliberate server teardown and stays
        // terminal. Before resume is armed this path is terminal for the caller (handshake).
        if (this.resume && !ev.wasClean) {
          this.scheduleReconnect();
          return;
        }
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

  /**
   * Arm post-open reconnect with the persistent room number and role. Until this is called a
   * post-open drop stays terminal; after it, an unclean drop re-dials and resumes the room.
   */
  setResume(room: number, role: string): void {
    this.resume = { room, role };
  }

  private scheduleReconnect(): void {
    if (this.closedByUser) return;
    if (this.reconnectAttempt >= this.resumeRetries) {
      this.opts.onClose?.(false, 0, 'signaling: reconnect exhausted');
      return;
    }
    const n = this.reconnectAttempt++;
    const raw = Math.min(this.backoff.maxMs, this.backoff.baseMs * this.backoff.factor ** n);
    const delay = raw * (1 + Math.random() * this.backoff.jitter);
    this.reconnectTimer = setTimeout(() => void this.tryReconnect(), delay);
  }

  // Re-dial the socket and resume the lingering room. Control frames (`resumed`) are consumed
  // internally; all application frames keep routing through the same handlers as the original.
  private tryReconnect(): void {
    if (this.closedByUser || !this.resume) return;
    let ws: WebSocket;
    try {
      ws = new WebSocket(this.opts.url);
    } catch {
      this.scheduleReconnect();
      return;
    }
    ws.binaryType = 'arraybuffer';
    ws.onopen = () => {
      this.ws = ws;
      this.opened = true;
      const { room, role } = this.resume!;
      ws.send(JSON.stringify({ type: 'resume', room, role }));
    };
    ws.onmessage = (ev: MessageEvent) => this.dispatch(ev);
    ws.onerror = () => {
      // The error event carries no detail; the following close drives the retry/terminal path.
    };
    ws.onclose = (ev: CloseEvent) => {
      if (this.closedByUser) return;
      this.opened = false;
      if (this.resume && !ev.wasClean && this.reconnectAttempt < this.resumeRetries) {
        this.scheduleReconnect();
        return;
      }
      this.opts.onClose?.(ev.wasClean, ev.code, ev.reason);
    };
    this.ws = ws;
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
    if (ev.data instanceof ArrayBuffer) {
      this.opts.onBinary?.(ev.data);
      return;
    }
    if (typeof ev.data !== 'string') {
      this.opts.onError?.(new Error('signaling: unsupported frame'));
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
    // `resumed` is the room-resume acknowledgement for our own resume request, not an app frame;
    // consume it so it never reaches (and could otherwise confuse) the active handler.
    if (SERVER_CONTROL_TYPES.has(msg.type)) return;
    this.opts.onMessage(msg);
  }

  /** JSON-encode and send a signaling message. Throws if the socket is not open. */
  send(msg: SignalMsg): void {
    if (!this.isOpen) throw new Error('signaling: socket not open');
    this.ws!.send(JSON.stringify(msg));
  }

  /** Send one opaque encrypted transfer frame over the adopted relay socket. */
  sendBinary(frame: ArrayBuffer): void {
    if (!this.isOpen) throw new Error('signaling: socket not open');
    this.ws!.send(frame);
  }

  /** Close the socket and cancel any pending reconnect. Idempotent. */
  close(code = 1000, reason = ''): void {
    this.closedByUser = true;
    if (this.retryTimer) clearTimeout(this.retryTimer);
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.ws?.close(code, reason);
  }
}

function toError(err: unknown): Error {
  return err instanceof Error ? err : new Error(String(err));
}
