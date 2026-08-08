# SendArc

SendArc is a self-hostable, end-to-end-encrypted, peer-to-peer file transfer. Two peers
share a short invite code; SendArc establishes an authenticated rendezvous, negotiates a
direct WebRTC connection, and streams the file encrypted, with bounded memory on both
ends and a verified digest at completion. It ships as a browser app and a terminal client
that speak the same protocol.

The server is a blind rendezvous point and fallback relay. It pairs two peers by a room
number and forwards their messages untouched; it never sees the invite words, the file
bytes, filenames, or the encryption keys.

## Status

Early development. The foundation (M0) and the authenticated rendezvous (M1) are in
place: the monorepo, the browser and CLI clients, the blind signaling server, local
HTTPS, and CI. Two peers can already reach a mutually authenticated, verified secure
channel. Active work is M2 — the direct WebRTC connection and the encrypted, streamed,
digest-verified file transfer on top of it.

## How it works

- **Invite code.** The sender asks the server for a room and mints a few random words,
  e.g. `4-brave-otter`. The room number routes the two sockets; the words are generated
  and checked entirely on the clients. In the browser the code travels in the URL
  fragment (`#…`), which is never put on the wire, so the words never reach the server.
- **Authenticated handshake.** Both ends run SPAKE2 (RFC 9382, over P-256) with the full
  invite code as the shared password, then exchange RFC 9382 key-confirmation MACs. A
  wrong code fails closed, so a malicious or compromised server cannot man-in-the-middle
  the connection. Both peers also derive the same short fingerprint, which the two humans
  can read to each other as an out-of-band check.
- **Encrypted transfer.** Files are streamed as AES-256-GCM frames keyed by the handshake
  output. The 16-byte frame header is the AEAD's associated data, binding each frame to
  its position. The same frame layer is used on the direct WebRTC path and on the relay
  fallback, so recovery is transport-agnostic. Integrity is checked per block (SHA-256)
  and for the whole file with a streaming digest that matches `sha256sum`.
- **Bounded memory.** The sender streams from disk, in-flight data is capped by a fixed
  window, and the receiver writes verified blocks to its sink and drops them — neither
  side buffers the whole file in RAM.

## Repository layout

```
apps/web            Svelte 5 + Vite single-page app (UI, WebRTC, crypto, transfer)
apps/cli            Go terminal client (sendarc send / receive)
apps/server         Go signaling + relay server (sendarcd)
packages/protocol   Wire types and constants shared by the web app and CLI (TypeScript)
packages/wire       Go mirror of the wire protocol, shared by the server and CLI
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
just lint        # lint the web app and every Go module
just typecheck   # TypeScript + Svelte
just test        # unit tests (web + Go modules)
```

## Security

SendArc treats the server and the network as untrusted for confidentiality and
integrity. Encryption is end-to-end on both the direct and relay paths, and peer
authentication is bound to the invite code.

## License

Not yet chosen. Until a license is added, no rights are granted beyond viewing the
source; do not assume any license. A license will be selected before the first public
release.
