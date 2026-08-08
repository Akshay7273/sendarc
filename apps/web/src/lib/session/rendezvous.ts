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

import { SignalingClient, type BackoffOptions } from '../signaling/client.js';

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

  // The two layers reference each other, so one closure must name the other before it is
  // constructed: the session's sink calls `client.send`, but nothing sends until the socket
  // has opened (connect → start), by which point `client` below is initialized.
  const session = make({ send: (msg) => client.send(msg) });

  const client = new SignalingClient({
    url,
    onMessage: (msg) => session.handle(msg),
    onClose: (clean, code, reason) => {
      // A post-open drop is terminal; translate it into a session failure. If the session
      // already settled (the normal close we trigger on `done`), abort is a no-op.
      session.abort(clean ? `signaling closed (${code})` : `signaling lost (${code} ${reason})`);
    },
    onError: (err) => session.abort(err.message),
    ...(opts.backoff !== undefined ? { backoff: opts.backoff } : {}),
  });

  // Tear the socket down once the handshake settles either way — success frees the room on
  // the server, failure stops a doomed retry loop.
  void session.done.then(
    () => client.close(),
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
