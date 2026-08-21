<p align="center">
  <img src="apps/web/src/lib/assets/sendbeam-mark.svg" alt="SendBeam" width="110" height="110" />
</p>

<h1 align="center">SendBeam</h1>

<p align="center">
  <strong>Encrypted peer-to-peer file transfer for the web, the terminal, and the desktop. No accounts, no uploads, no server-side storage.</strong>
</p>

<p align="center">
  <a href="https://github.com/Akshay7273/sendbeam/actions/workflows/ci.yml"><img src="https://github.com/Akshay7273/sendbeam/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/Akshay7273/sendbeam/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT" /></a>
  <a href="https://github.com/Akshay7273/sendbeam/pkgs/container/sendbeam"><img src="https://img.shields.io/badge/image-ghcr.io%2Fakshay7273%2Fsendbeam-blue.svg" alt="Container image" /></a>
  <a href="https://omnitrix.space"><img src="https://img.shields.io/badge/live%20demo-omnitrix.space-8b7cf6.svg" alt="Live demo" /></a>
</p>

<p align="center">
  <a href="https://omnitrix.space"><strong>Live demo</strong></a>
  · <a href="#quick-start">Quick start</a>
  · <a href="#browser">Browser</a>
  · <a href="#cli">CLI</a>
  · <a href="#desktop">Desktop</a>
  · <a href="#self-hosting">Self-hosting</a>
  · <a href="#security">Security</a>
  · <a href="#documentation">Documentation</a>
  · <a href="#development">Development</a>
</p>

## About

SendBeam is an open-source, end-to-end-encrypted file transfer application for the browser,
the command line, and the desktop. Files stream directly between two peers over WebRTC; a blind
rendezvous server negotiates the connection and never stores, inspects, or decrypts file
data. When a direct path is blocked by a restrictive NAT, an encrypted relay on the server
carries opaque ciphertext while the transfer stays end-to-end-encrypted.

All clients share one wire protocol: web, Go CLI, and native desktop. Send from a browser
tab and receive in the CLI or desktop — or any other combination — with the same invite code, even
across different networks.

The design is documented in the [protocol specification](docs/protocol.md) and the
[threat model](docs/threat-model.md).

## Quick start

**Try it live.** Open [https://omnitrix.space](https://omnitrix.space) in two browser tabs,
create a room, and share the link (or the short code) with the receiver — no account, no
install, no configuration.

**Run it yourself.** The public container image is the fastest self-hosted path, with no
toolchain required:

```bash
docker run -d --name sendbeam -p 8443:8443 ghcr.io/akshay7273/sendbeam
```

Then open `http://localhost:8443` and follow the same flow. Files stream with bounded
memory — size is not a limit — and the receiver can verify the final SHA-256 against
`sha256sum`.

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
just install-cli                      # installs sendbeam into ~/.local/bin
git clone https://github.com/Akshay7273/sendbeam.git && cd sendbeam
go build -o ~/.local/bin/sendbeam ./apps/cli/cmd/sendbeam
```

Then send and receive with short, plain commands:

```bash
sendbeam send photo.jpg
sendbeam receive 4-brave-otter --out ./downloads
```

Both clients produce the same invite code and link, so browser and CLI peers can mix freely.
Run `sendbeam help` for all options.

CLI receives are crash-resilient: verified progress is journaled under `<out>/.sendbeam`
and resumes automatically when you rejoin the same room, and
`sendbeam transfers list|inspect|resume|discard` manages that state (see
[docs/durable-receive.md](docs/durable-receive.md)).

## Desktop

SendBeam Desktop provides a native desktop interface for Windows, macOS, and Linux built
on Wails v3, running the shared Go engine.

- **Native system UX.** OS drag-and-drop file transfers, system native file pickers, and system tray integration.
- **Unified protocol.** Interoperates seamlessly with browser and CLI peers.
- **Cross-platform packaging.** Windows portable ZIP & NSIS installer, macOS Universal application (.app & .dmg), and Linux AppImage & Debian package (.deb).

> [!NOTE]
> Public signed installers and automated update channels will be published in a future release. Current packages can be built from source or downloaded from CI artifacts.

```bash
# Build desktop native binary (requires platform WebView dependencies)
cd apps/desktop
go build -o sendbeam-desktop .
```

See [apps/desktop/README.md](apps/desktop/README.md) and [docs/distribution.md](docs/distribution.md) for platform-specific packaging instructions.

## Trusted Device Mesh & Automation

SendBeam v1.5 introduces cryptographic device identity, mutual pairing, and instant transfer automation across your personal device fleet — with zero cloud accounts or centralized directories:

- **Pair Once, Connect Forever:** Pair two devices over an authenticated SPAKE2 ceremony (`sendbeam pair` in CLI, or via Web/Desktop UI). Once paired, devices establish mutual forward-secret sessions (`sendbeam/2`) without typing room codes.
- **Targeted Sending:** Send files directly to any paired device by name or ID:
  ```bash
  sendbeam send report.pdf @macbook
  ```
- **Automated Receiver Listener:** Run `sendbeam listen` on home servers or workstations to automatically receive files from authorized devices under strict path-contained policies (`--dest`, `--max-size`, `--auto-accept`).
- **Privacy-Preserving Presence:** Devices announce availability using 15-minute epoch-rotated blinded handles across the Internet and blinded UDP multicast beacons on LANs. The rendezvous server never learns device identities, IP associations, or pairwise relationships.
- **Unified Across All Platforms:** Supported in the CLI, Desktop application, and evergreen web browsers via origin-scoped IndexedDB storage.

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
> SendBeam is stable open-source software. It has not had an independent
> security audit; review the [threat model](docs/threat-model.md) before using it
> for irreplaceable or highly sensitive data.

## Documentation

- [Installation & Quickstart](docs/install.md) — installation instructions for Linux, macOS, and Windows
- [Compatibility matrix](docs/compat-matrix.md) — Browser ↔ CLI ↔ Desktop cross-client matrix, NAT topologies, networks
- [Self-hosting server](docs/HOSTING.md) — deployment, TLS, STUN/TURN, relay limits, Prometheus metrics
- [Self-hosting clients](docs/self-hosting-clients.md) — configuring CLI & Desktop with custom servers and OS secret stores
- [Troubleshooting & Diagnostics](docs/troubleshooting.md) — network diagnostics, restrictive firewalls, lock resolution
- [State Storage Locations](docs/state-storage.md) — persistent config, journals, sender records, and keychains
- [Supply Chain Integrity](docs/supply-chain.md) — build provenance attestations, SPDX 2.3 SBOMs, checksum manifests
- [Updater Architecture](docs/updater.md) — self-update channels, cryptographic verification, and rollback safety
- [Distribution](docs/distribution.md) — multi-platform packaging, artifacts, and build metadata
- [Release Gate v1.5](docs/RELEASE-v1.5.md) — v1.5 milestone criteria, verification evidence, and release checklist
- [Release Gate v1.4](docs/RELEASE-v1.4.md) — v1.4 milestone criteria, verification evidence, and release checklist
- [Protocol specification](docs/protocol.md) — `sendbeam/1` & `sendbeam/2` wire protocols
- [Threat model](docs/threat-model.md) — trust boundary, attacks, mitigations
- [Trust & Device Identity Model](docs/trust-model.md) — device identity, trust database, pairing boundaries, and policy confinement
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
