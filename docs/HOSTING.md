# Self-hosting SendBeam

SendBeam ships as a single container that serves the web app, the signaling
endpoint, and the encrypted relay from one process on one port. This guide
covers running it yourself, including TLS, STUN/TURN, and relay limits.

## Quickstart

Requires Docker (or any OCI-compatible runtime) and nothing else:

```sh
docker run -d --name sendbeam -p 8443:8443 ghcr.io/akshay7273/sendbeam
```

Then open <http://localhost:8443> and send your first file. Plain HTTP on
`localhost` is a browser secure context, so WebRTC works; for anything
reachable from another machine, put TLS in front (see [TLS](#tls)).

Health: `GET /healthz` returns `{"status":"ok"}`; the container also
exposes a `HEALTHCHECK` against it.

Metrics: `GET /metrics` serves Prometheus text with active rooms
(`sendbeam_rooms`), relayed ciphertext bytes (`sendbeam_relay_bytes_total`),
and refusal/error codes (`sendbeam_errors_total{code=...}`). Point a scraper
or a dashboard at it; nothing content-bearing is ever exposed.

## What the image contains

- The built web bundle (`apps/web`), served with SPA fallback by `sendbeamd`
- The blind signaling endpoint (`/ws`) and the encrypted relay
- CA certificates for outbound TLS
- Runs as an unprivileged user (`sendbeam`, uid 10001); no shell access

The web app defaults to the signaling endpoint at `/ws` on its own origin,
so web + signaling + relay all share the published port.

## Environment variables

| Variable                                 | Default       | Purpose                                                                                                                                          |
| ---------------------------------------- | ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `SENDBEAM_ADDR`                          | `:8443`       | Listen address.                                                                                                                                  |
| `SENDBEAM_TLS_CERT` / `SENDBEAM_TLS_KEY` | unset         | PEM cert/key paths; when both are set `sendbeamd` terminates TLS itself.                                                                         |
| `SENDBEAM_WEB_DIR`                       | unset         | Directory of the built web bundle to serve; set to `/srv/web` in the image.                                                                      |
| `SENDBEAM_WEB_DEV_PROXY`                 | unset         | Vite dev-server URL to proxy to (development only; overrides `SENDBEAM_WEB_DIR`).                                                                |
| `SENDBEAM_ALLOWED_ORIGINS`               | empty         | Comma-separated WSS origin allowlist. Empty allows only same-origin browser sockets; native CLI clients (no `Origin` header) are always allowed. |
| `SENDBEAM_ICE_SERVERS`                   | unset         | Comma-separated STUN (or TURN) URLs published to the web app via `/config.json`; unset keeps the bundled Google STUN default.                    |
| `SENDBEAM_SIGNAL_IDLE_TIMEOUT`           | `2m`          | Close a socket silent this long; also bounds how long an unpaired room lingers.                                                                  |
| `SENDBEAM_SIGNAL_MAX_MESSAGE_BYTES`      | `65536`       | Cap on a single inbound signaling message.                                                                                                       |
| `SENDBEAM_RELAY_MAX_FRAME_BYTES`         | `131072`      | Cap on a single relay frame.                                                                                                                     |
| `SENDBEAM_RELAY_WINDOW_BYTES`            | `1048576`     | In-flight window per relay connection.                                                                                                           |
| `SENDBEAM_RELAY_QUEUE_BYTES`             | `2097152`     | Bounded per-connection relay queue.                                                                                                              |
| `SENDBEAM_RELAY_BURST_BYTES`             | `8388608`     | Token-bucket burst for relay throughput.                                                                                                         |
| `SENDBEAM_RELAY_BYTES_PER_SEC`           | `33554432`    | Relay throughput ceiling (32 MiB/s by default).                                                                                                  |
| `SENDBEAM_RELAY_MAX_SESSION_BYTES`       | `17179869184` | Lifetime bytes relayed per session (16 GiB).                                                                                                     |

Durations use Go's `time.ParseDuration` syntax (`30s`, `5m`); sizes use
plain integers (bytes). Overrides apply only to the signaling/relay layer;
the web bundle is a fixed artifact.

## TLS

Two supported arrangements:

**1. Terminate at `sendbeamd`** — mount a PEM cert and key:

```sh
docker run -d --name sendbeam \
  -p 8443:8443 \
  -v /etc/letsencrypt/live/example.com/fullchain.pem:/certs/fullchain.pem:ro \
  -v /etc/letsencrypt/live/example.com/privkey.pem:/certs/privkey.pem:ro \
  -e SENDBEAM_TLS_CERT=/certs/fullchain.pem \
  -e SENDBEAM_TLS_KEY=/certs/privkey.pem \
  -e SENDBEAM_ALLOWED_ORIGINS=https://example.com \
  ghcr.io/akshay7273/sendbeam
```

Minimum TLS 1.2 is enforced server-side.

**2. Reverse proxy (recommended)** — let Caddy (or Traefik) handle issuance
and renewal, and proxy plain HTTP to the container:

```caddy
example.com {
    reverse_proxy 127.0.0.1:8443
}
```

```sh
docker run -d --name sendbeam -p 127.0.0.1:8443:8443 \
  -e SENDBEAM_ALLOWED_ORIGINS=https://example.com \
  ghcr.io/akshay7273/sendbeam
```

With a proxy, set `SENDBEAM_ALLOWED_ORIGINS` to your public origin so the
browser's `Origin` header (rewritten to `https://example.com`) passes the
allowlist. Any WebSocket-aware reverse proxy works.

## STUN and TURN

- **STUN** — both clients use Google's STUN (`stun:stun.l.google.com:19302`)
  by default for external candidate discovery. The CLI points at your own
  STUN servers with the repeatable `--ice-server` flag. The web bundle's ICE
  config is configurable at runtime: the server publishes an operator-chosen
  STUN list via `/config.json` (from `SENDBEAM_ICE_SERVERS`), which the web
  app fetches on load, validates, and passes to `RTCPeerConnection`.
- **TURN** — optional. Operators who need better restrictive-network
  reachability publish TURN URLs (alongside STUN) in `SENDBEAM_ICE_SERVERS`;
  clients then gather a TURN relayed candidate and race it against direct
  candidates. TURN credentials are served with `Cache-Control: no-cache` and
  clients never reuse a fetched config past the 15-minute credential TTL, so
  operators may serve short-lived credentials without embedding them in the
  web bundle. **Default self-hosting requires no TURN service**: when no TURN is
  configured, restricted pairs fall back to the app-layer **encrypted relay**
  through this same server, which fills the TURN role without a second service.
  The relay (and a TURN server, when used) never sees plaintext: payloads are
  end-to-end encrypted and framed inside WebSocket messages, and a TURN server
  observes only encrypted WebRTC datagrams. See `docs/adr/0003-path-selection.md`.

For pairings behind symmetric NATs, make sure this server is reachable on
the public port (it is the fallback path), and budget its bandwidth with
the relay limits below.

## Relay limits

The relay is the only place an operator spends bandwidth and memory, so
every layer is bounded. Defaults are in the table above; raise or lower
them per instance:

| What             | Default  | Effect                                                     |
| ---------------- | -------- | ---------------------------------------------------------- |
| Frame size       | 128 KiB  | A single relay frame cannot exceed this.                   |
| Window           | 1 MiB    | Unacked in-flight bytes per connection.                    |
| Queue            | 2 MiB    | Buffered bytes per connection before backpressure.         |
| Throughput       | 32 MiB/s | Token-bucket ceiling shared across connections.            |
| Session lifetime | 16 GiB   | Bytes relayed per session before the session is torn down. |

These keep a busy instance's memory in the low tens of MiB regardless of
how many transfers run.

## Security notes

- Pairing is code-authenticated (SPAKE2-style handshake); the server never
  sees the word code or plaintext payloads.
- Server logs contain room numbers and metadata only — no secrets, no
  file names, no payload digests of content.
- `SENDBEAM_ALLOWED_ORIGINS` blocks cross-site socket abuse; keep it set
  when the instance is public.
- Run behind a reverse proxy that terminates TLS for production; plain
  HTTP is for localhost demos only.

## Updating

```sh
docker pull ghcr.io/akshay7273/sendbeam
docker restart sendbeam
```

The container is stateless; nothing persists inside it, so restarts are
safe at any time.
