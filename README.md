# SendArc

[![CI](https://github.com/Akshay7273/sendarc/actions/workflows/ci.yml/badge.svg)](https://github.com/Akshay7273/sendarc/actions/workflows/ci.yml)

**Send files securely. Share only a short code. Keep plaintext off the server.**

SendArc is a self-hostable, end-to-end-encrypted file-transfer application for the browser
and terminal. It authenticates two peers with a short invite code, prefers a direct WebRTC
connection, and falls back to a bounded encrypted relay when a direct path is unavailable.
Files stream without being loaded entirely into memory.

> [!NOTE]
> SendArc is pre-release software. File and folder transfers are working over direct and relayed
> connections, but there is no stable release or compatibility guarantee yet.

## Why SendArc

- **End-to-end encrypted.** File contents, names, digests, and session keys are encrypted
  between the two peers. The rendezvous server cannot read them.
- **Authenticated by a human-friendly code.** SPAKE2 binds the cryptographic handshake to
  the invite code and fails closed when the code is wrong.
- **Direct when possible, relayed when necessary.** SendArc prefers an authenticated WebRTC
  DataChannel and automatically falls back to an end-to-end-encrypted WebSocket relay. The relay
  is credit-gated and bounded, and never stores transfer data.
- **Streams large files with bounded memory.** Fixed-size blocks, transport backpressure,
  and a bounded in-flight window keep memory use independent of file size.
- **Files and folders.** Each file is independently verified; browsers can write directly to a
  chosen destination or stream a portable ZIP fallback without buffering the file set in memory.
- **Reliable and controllable.** Verified block acknowledgements drive progress and recovery;
  missing blocks are retried, and either peer can pause, resume, or cancel a transfer.
- **Verifiable completion.** Every block is authenticated and hashed; the final streaming
  SHA-256 digest is compatible with `sha256sum`.
- **Browser and CLI interoperability.** Send or receive with either client using the same
  protocol and invite code.

## How it works

```text
 Sender                      Blind rendezvous                     Receiver
   │  create room ─────────────────▶│                                │
   │◀──────────── room number       │◀────────────── join room ─────│
   │                                │                                │
   │  SPAKE2 + key confirmation ◀───┼───▶ SPAKE2 + key confirmation │
   │  authenticated SDP / ICE   ◀───┼───▶ authenticated SDP / ICE   │
   │                                │                                │
   ├════ encrypted WebRTC DataChannel, direct when available ═══════┤
   └──── or opaque encrypted frames through the bounded relay ──────┘
```

The room number is only a routing token. The random words stay on the clients—in browser
links they live after `#`, which is not sent in HTTP requests. Both peers use the complete
code as the SPAKE2 password, confirm the derived key, and authenticate WebRTC signaling.
Transfer frames remain end-to-end encrypted on both direct and relay paths.

The server can observe connection metadata, WebRTC signaling, and—when relay fallback is
used—encrypted frame sizes and timing. It cannot derive the session key or decrypt file
metadata and content. The security section below summarizes the trust boundary.

## Supported paths

| Sender  | Receiver | Preferred path         | Fallback        |
| ------- | -------- | ---------------------- | --------------- |
| Browser | Browser  | Direct WebRTC          | Encrypted relay |
| Browser | CLI      | Direct WebRTC          | Encrypted relay |
| CLI     | Browser  | Direct WebRTC          | Encrypted relay |
| CLI     | CLI      | Direct WebRTC via Pion | Encrypted relay |

## Run locally

### Requirements

- Node.js 22 or newer
- Go 1.24 or newer
- [pnpm](https://pnpm.io/) through Corepack
- [just](https://github.com/casey/just)
- [mkcert](https://github.com/FiloSottile/mkcert)

### Browser application

```bash
git clone https://github.com/Akshay7273/sendarc.git
cd sendarc
corepack enable
just install
just dev
```

Open `https://localhost:8443` on both peers. The first run creates a local TLS certificate.
Run `mkcert -install` once if your browser does not trust the development certificate.

### Terminal client

With the local server running, build the CLI:

```bash
(cd apps/cli && go build -o ../../bin/sendarc ./cmd/sendarc)
```

Send one or more files or folders:

```bash
bin/sendarc send ./photos ./notes.txt --insecure-skip-verify
```

Receive it from another terminal:

```bash
bin/sendarc receive 4-brave-otter --out ./downloads --insecure-skip-verify
```

`--insecure-skip-verify` is only for the self-signed local development certificate. Do not
use it with a deployed server. Add `--relay-only` to either command to require the encrypted
relay path, which is useful for connectivity checks. Run `bin/sendarc help` for all options.

## Development

```bash
just build       # build the web application and server binary
just lint        # lint TypeScript, Svelte, and every Go module
just typecheck   # run TypeScript and Svelte diagnostics
just test        # run JavaScript and Go test suites
just serve       # serve a production-style local build over TLS
```

The repository is a pnpm and Go workspace:

```text
apps/web            Svelte web application, WebRTC client, and transfer worker
apps/cli            Go terminal client
apps/server         Go HTTPS and blind rendezvous server
packages/protocol   TypeScript protocol, cryptography, and transfer engine
packages/wire       Go implementation of the shared wire protocol
```

## Security

SendArc treats the rendezvous server and network as untrusted for confidentiality and
integrity. Bulk encryption uses AES-256-GCM with monotonic per-direction nonces; the sequence
counter and frame header are authenticated as associated data. SPAKE2 with RFC 9382 key
confirmation protects the short invite code from offline guessing by the server and prevents
an undetected man-in-the-middle handshake.

SendArc has not yet received an independent security audit. Please do not use pre-release
builds for irreplaceable or highly sensitive data.

## License

No license has been granted yet. Until a `LICENSE` file is added, the source is available
for inspection only; do not assume permission to copy, modify, or distribute it.
