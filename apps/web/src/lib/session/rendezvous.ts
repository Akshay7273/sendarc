/**
 * Browser rendezvous orchestrator — the seam between the transport and the pure handshake
 * state machine. It owns a {@link SignalingClient} and a {@link RendezvousSession}, wiring
 * the socket's inbound frames into `session.handle` and the session's outbound sink into
 * `client.send`, then drives the lifecycle: connect (with backoff) → `start` → resolve with
 * the session keys, or fail closed.
 *
 * The two layers below it stay ignorant of each other — the state machine never touches a
 * `WebSocket`, and the client never parses a handshake. This module is the only place that
 * knows both, which keeps each unit-testable and gives the Svelte UI a single object to
 * bind against: a live `phase`, the invite `code` once allocated, and a `done` promise.
 *
 * A socket drop after opening is mapped to a session `abort`, so the UI observes exactly
 * one terminal outcome (`done` rejects) whether the failure came from the peer, the crypto,
 * or the wire.
 */

import {
  RendezvousSession,
  type CapsPayload,
  type RendezvousPhase,
  type RendezvousResult,
  type SignalMsg,
} from '@sendarc/protocol';

import { SignalingClient, type BackoffOptions, type SignalChannel } from '../signaling/client.js';

export interface RendezvousControllerOptions {
  /** Signaling endpoint. Defaults to `/ws` on the current origin (ws/wss to match the page). */
  url?: string;
  /** Overrides for this peer's announced capabilities. */
  localCaps?: Partial<CapsPayload>;
  onPhase?: (phase: RendezvousPhase) => void;
  /** Fires once the full invite code is known (after `created` for an offerer, immediately for a joiner). */
  onCode?: (code: string) => void;
  backoff?: Partial<BackoffOptions>;
}

/** A rendezvous in progress. `done` settles once, mirroring the session's outcome. */
export interface RendezvousController {
  /** The full invite code, once allocated/known. */
  readonly code: string | undefined;
  readonly phase: RendezvousPhase;
  /** Resolves with the session keys on success; rejects with a `RendezvousError` otherwise. */
  readonly done: Promise<RendezvousResult>;
  /** Abort locally: notify the peer with `bye` and tear down the socket. Idempotent. */
  cancel(reason?: string): void;
  /**
   * Take over the still-open signaling socket for the transfer, before it is auto-closed.
   * Valid only after `done` resolves; the caller then owns teardown via the returned channel's
   * `close()`. Swapping in a new `onMessage` handler reroutes inbound frames (SDP/ICE) away from
   * the settled handshake session and into the transfer layer.
   */
  adoptSignaling(): SignalChannel;
}

/** Start as the offerer: allocate a room and display the generated invite code. */
export function offer(
  opts: RendezvousControllerOptions & { words?: string; wordCount?: number } = {},
): RendezvousController {
  return run((sink) => {
    const session = new RendezvousSession({
      role: 'offerer',
      transport: sink,
      ...pick(opts),
      ...(opts.words !== undefined ? { words: opts.words } : {}),
      ...(opts.wordCount !== undefined ? { wordCount: opts.wordCount } : {}),
    });
    return session;
  }, opts);
}

/** Start as the joiner: pair into the room named by an invite code typed or opened from a link. */
export function join(opts: RendezvousControllerOptions & { code: string }): RendezvousController {
  return run(
    (sink) =>
      new RendezvousSession({
        role: 'joiner',
        code: opts.code,
        transport: sink,
        ...pick(opts),
      }),
    opts,
  );
}

/** Common wiring for both roles: connect, bind the socket to the session, own the teardown. */
function run(
  make: (sink: { send(msg: SignalMsg): void }) => RendezvousSession,
  opts: RendezvousControllerOptions,
): RendezvousController {
  const url = opts.url ?? defaultSignalingUrl();

  // Inbound frames go to the handshake session until the transfer layer adopts the socket, at
  // which point `route` is swapped to the transfer's own handler. `adopted` also suppresses the
  // success auto-close, since the transfer layer then owns the socket's lifetime.
  let route: (msg: SignalMsg) => void = (msg) => session.handle(msg);
  let routeBinary: (frame: ArrayBuffer) => void = () => session.abort('unexpected binary frame');
  let routeClose: (err: Error) => void = (err) => session.abort(err.message);
  let adopted = false;

  // The two layers reference each other, so one closure must name the other before it is
  // constructed: the session's sink calls `client.send`, but nothing sends until the socket
  // has opened (connect → start), by which point `client` below is initialized.
  const session = make({ send: (msg) => client.send(msg) });

  const client = new SignalingClient({
    url,
    onMessage: (msg) => route(msg),
    onBinary: (frame) => routeBinary(frame),
    onClose: (clean, code, reason) => {
      // A post-open drop is terminal; translate it into a session failure. If the session
      // already settled (the normal close we trigger on `done`), abort is a no-op.
      routeClose(
        new Error(clean ? `signaling closed (${code})` : `signaling lost (${code} ${reason})`),
      );
    },
    onError: (err) => session.abort(err.message),
    ...(opts.backoff !== undefined ? { backoff: opts.backoff } : {}),
  });

  // Tear the socket down once the handshake settles. Failure closes immediately (stop a doomed
  // retry loop). Success defers to a macrotask so a caller can `adoptSignaling()` synchronously
  // off `await done` and keep the socket for the transfer; if nobody adopts, it still closes
  // to free the room on the server.
  void session.done.then(
    () => setTimeout(() => void (adopted || client.close()), 0),
    () => client.close(),
  );

  client.connect().then(
    () => session.start(),
    (err: unknown) => session.abort(err instanceof Error ? err.message : String(err)),
  );

  return {
    get code() {
      return session.code;
    },
    get phase() {
      return session.phase;
    },
    done: session.done,
    cancel: (reason = 'cancelled') => {
      session.abort(reason);
      client.close();
    },
    adoptSignaling: () => {
      adopted = true;
      return {
        send: (msg) => client.send(msg),
        sendBinary: (frame) => client.sendBinary(frame),
        onMessage: (handler) => (route = handler),
        onBinary: (handler) => (routeBinary = handler),
        onClose: (handler) => (routeClose = handler),
        close: () => client.close(),
      };
    },
  };
}

/** Pull the options shared by both roles into the shape the session constructor expects. */
function pick(opts: RendezvousControllerOptions) {
  return {
    ...(opts.localCaps !== undefined ? { localCaps: opts.localCaps } : {}),
    ...(opts.onPhase !== undefined ? { onPhase: opts.onPhase } : {}),
    ...(opts.onCode !== undefined ? { onCode: opts.onCode } : {}),
  };
}

/** `/ws` on the current origin, with the scheme upgraded to match http→ws / https→wss. */
function defaultSignalingUrl(): string {
  const { protocol, host } = window.location;
  const scheme = protocol === 'https:' ? 'wss:' : 'ws:';
  return `${scheme}//${host}/ws`;
}
