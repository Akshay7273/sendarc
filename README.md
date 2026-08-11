# SendBeam

**Encrypted peer-to-peer file transfer for the browser and the terminal. No accounts, no uploads, no server-side storage.**

[![CI](https://github.com/Akshay7273/sendbeam/actions/workflows/ci.yml/badge.svg)](https://github.com/Akshay7273/sendbeam/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/Akshay7273/sendbeam/blob/main/LICENSE)
[![Image](https://img.shields.io/badge/image-ghcr.io%2Fakshay7273%2Fsendarc-blue.svg)](https://github.com/Akshay7273/sendbeam/pkgs/container/sendarc)

[Quick start](#quick-start) · [CLI](#cli) · [Self-hosting](#self-hosting) · [Security](#security) · [Documentation](#documentation) · [Development](#development)

## About

SendBeam is an open-source, end-to-end-encrypted file transfer application for the browser
and the command line. Files stream directly between two peers over WebRTC; a blind
rendezvous server negotiates the connection and never stores, inspects, or decrypts file
data. When a direct path is blocked by a restrictive NAT, an encrypted relay on the server
carries opaque ciphertext while the transfer stays end-to-end-encrypted.

Two clients share one wire protocol: the web application and a Go CLI. Send from a browser
tab and receive in the CLI — or any other combination — with the same invite code, even
across different networks.

The design is documented in the [protocol specification](docs/protocol.md) and the
[threat model](docs/threat-model.md).

## Quick start

The easiest way to try SendBeam is the public container image — no toolchain required:

```bash
docker run -d --name sendbeam -p 8443:8443 ghcr.io/akshay7273/sendbeam
```

Open `http://localhost:8443` in two browser tabs, create a room, and share the link (or
the short code) with the receiver. No account, no install, no configuration. Files stream
with bounded memory — size is not a limit — and the receiver can verify the final SHA-256
against `sha256sum`.

## Browser

The web application works in any evergreen browser:

- **Direct by default.** Peers connect over an authenticated WebRTC DataChannel; the
  encrypted relay takes over automatically when a direct path is unavailable.
- **Large files, small memory.** Files are streamed in fixed-size encrypted blocks; memory
  stays bounded regardless of file size.
- **Files and folders.** Receivers on Chromium can write straight to a chosen file; all
  browsers fall back to an in-browser filesystem or a portable ZIP archive.
- **Verified completion.** Every block is authenticated and hashed; the final digest is
  `sha256sum`-compatible.

## CLI

Send and receive from terminals, servers, and scripts.

Install with the project's task runner, or build from source:

```bash
just install-cli                      # installs sendarc into ~/.local/bin
git clone https://github.com/Akshay7273/sendbeam.git && cd sendarc
go build -o ~/.local/bin/sendarc ./apps/cli/cmd/sendbeam
```

Then send and receive with short, plain commands:

```bash
sendarc send photo.jpg
sendarc receive 4-brave-otter --out ./downloads
```

Both clients produce the same invite code and link, so browser and CLI peers can mix freely.
Run `sendarc help` for all options.

## Self-hosting

Prefer your own infrastructure? The single container runs the web app, the signaling
endpoint, and the encrypted relay from one port — for `linux/amd64` and `linux/arm64`:

```bash
docker pull ghcr.io/akshay7273/sendbeam
docker run -d --name sendbeam -p 8443:8443 ghcr.io/akshay7273/sendbeam
```

The image rebuilds on every push to `main` and on each `v*` tag. Configuration, TLS, STUN,
relay limits, and a `/metrics` endpoint in Prometheus format are covered in
[docs/HOSTING.md](docs/HOSTING.md).

## Security

SendBeam treats the rendezvous server and the network as untrusted for confidentiality and
integrity. Peers authenticate with SPAKE2 (RFC 9382) keyed by the invite code — a wrong code
fails closed, and the server cannot offline-guess it or undetectably intercept the
handshake. Files are encrypted with AES-256-GCM under per-direction monotonic nonces, on
both the direct and the relayed path. The server can observe room numbers and ciphertext
metadata only; it never sees file contents, names, digests, or keys.

Full analysis, accepted limitations, and the trust boundary are in the
[threat model](docs/threat-model.md). Cryptographic test vectors are published in
[docs/test-vectors/](docs/test-vectors/), and dependency audits run in CI.

> [!NOTE]
> SendBeam is pre-release software without a stable release or an independent security
> audit. Do not use it for irreplaceable or highly sensitive data.

## Documentation

- [Self-hosting](docs/HOSTING.md) — deployment, TLS, STUN/TURN, relay limits, metrics
- [Protocol specification](docs/protocol.md) — `sendarc/1` wire protocol
- [Threat model](docs/threat-model.md) — trust boundary, attacks, mitigations
- [Compatibility matrix](docs/compat-matrix.md) — NAT topologies, degraded networks, browsers
- [Benchmarks](docs/BENCHMARKS.md) — throughput, memory, methodology
- [Test vectors](docs/test-vectors/) — cross-language crypto and transfer vectors

## Development

```bash
just install     # install JS + Go dependencies
just dev         # web app with HMR + Go server over https://localhost:8443
just build       # build the web application and server binary
just lint        # lint TypeScript, Svelte, and every Go module
just test        # run JavaScript and Go test suites
```

For a CLI peer against the local development server, add `--insecure-skip-verify`
(the local certificate is self-signed); never use it with a deployed server.

The repository is a pnpm and Go workspace:

```text
apps/web            Svelte web application, WebRTC client, and transfer worker
apps/cli            Go terminal client
apps/server         Go HTTPS and blind rendezvous server
packages/protocol   TypeScript protocol, cryptography, and transfer engine
packages/wire       Go implementation of the shared wire protocol
```

## Contributing

Contributions are welcome — open an [issue](https://github.com/Akshay7273/sendbeam/issues)
for bugs or feature requests, and submit pull requests against `main`. To report a
vulnerability, see the [security policy](docs/threat-model.md).

## License

MIT License, Copyright (c) 2026 Akshay7273. See [LICENSE](LICENSE) for details.

Open source. Built for everyone.
