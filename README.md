# SendArc

SendArc is a self-hostable, end-to-end-encrypted, peer-to-peer file transfer that runs
entirely in the browser. Open a link on two devices and SendArc establishes an
authenticated rendezvous, negotiates a direct WebRTC connection, and streams the file
encrypted, with bounded memory on both ends and a verified digest at completion.

The server is a blind rendezvous point and fallback relay. It pairs two peers by an
opaque session id and forwards their messages; it never sees the invite secret, the
file bytes, filenames, or the encryption keys.

## Status

Early development. The foundation (M0) is in place — monorepo, web and server
skeletons, local HTTPS, and CI. Active work is the M1 + M2 vertical slice:
authenticated rendezvous through to a verified direct transfer.

## How it works

- **Rendezvous.** The sender mints a routing id `sid` and a 256-bit invite secret `S`.
  Both are packed into the invite link, but `S` lives only in the URL fragment
  (`#…`), which browsers never transmit — so it never reaches the server.
- **Authenticated handshake.** Peers run an ephemeral P-256 ECDH exchange and confirm
  a shared HMAC over the transcript, keyed by `S`. A wrong secret or a tampered SDP
  fingerprint fails closed, which is what stops a malicious server from
  man-in-the-middling the connection.
- **Encrypted transfer.** Files are streamed as AES-256-GCM frames. The same frame
  layer is used on the direct WebRTC path and on the relay fallback, so recovery is
  transport-agnostic. Integrity is checked per block (SHA-256) and for the whole file
  with a streaming digest that matches `sha256sum`.
- **Bounded memory.** The sender streams from disk, in-flight data is capped by a
  fixed window, and the receiver writes verified blocks to its sink and drops them —
  neither side buffers the whole file in RAM.

## Repository layout

```
apps/web            Svelte 5 + Vite single-page app (UI, WebRTC, crypto, transfer)
apps/server         Go signaling + relay server (sendarcd)
packages/protocol   Wire types and constants shared by the web app (mirrored in Go)
infra/certs         Local mkcert TLS material (gitignored)
```

## Quick start (development)

Requires Node ≥ 22, Go ≥ 1.24, [pnpm](https://pnpm.io) (via `corepack enable`),
[mkcert](https://github.com/FiloSottile/mkcert), and
[just](https://github.com/casey/just).

```bash
just install     # install JS and Go dependencies
just dev         # Vite HMR + Go server at https://localhost
```

`just dev` generates a local certificate on first run. If the browser distrusts it,
run `mkcert -install` once to add the local CA to your system trust store.

Other recipes:

```bash
just build       # build the web bundle and the sendarcd binary
just serve       # serve the production build over TLS
just lint        # lint web + server
just typecheck   # TypeScript + Svelte
just test        # unit tests (web + server)
```

## Security

SendArc treats the server and the network as untrusted for confidentiality and
integrity. Encryption is end-to-end on both the direct and relay paths, and peer
authentication is bound to the invite secret.

## License

Not yet chosen. Until a license is added, no rights are granted beyond viewing the
source; do not assume any license. A license will be selected before the first public
release.
