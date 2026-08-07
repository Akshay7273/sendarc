# agy

Secure, end-to-end-encrypted, peer-to-peer file transfer that runs entirely in the
browser. Open a link on two devices → authenticated rendezvous → direct WebRTC
connection → streamed encrypted transfer with bounded memory and verified completion.
The server is a blind rendezvous + relay: it never sees your files or the secret.

## Status

Early development — building the M1+M2 vertical slice.

## Quick start (dev)

Requires Node ≥22, Go ≥1.23, [pnpm](https://pnpm.io) (via `corepack enable`),
[mkcert](https://github.com/FiloSottile/mkcert), and [just](https://github.com/casey/just).

```bash
just install     # install JS + Go dependencies
just dev         # Vite HMR + Go server at https://localhost
```

## Architecture

Svelte 5 PWA (`apps/web`) + Go signaling/relay server (`apps/server`), sharing wire
types via `packages/protocol`. End-to-end encryption uses WebCrypto (P-256 ECDH,
HKDF-SHA256, AES-256-GCM); the rendezvous secret lives only in the URL fragment and
never reaches the server.

## License

Not yet chosen. Do not assume any license until one is added.
