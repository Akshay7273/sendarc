# ADR 0007 — Desktop framework: Wails v3

Status: accepted
Scope: v1.4 (native product & distribution) — V14-PR02
Applies to: the desktop shell in `apps/desktop` and all later native product work

## Context

v1.4's mission is "one reusable Go engine and a first-class desktop client". V14-PR01
extracted the engine into `packages/engine`; the desktop host must now be chosen. Hard
constraints from the plan and prior ADRs:

- WebRTC, crypto, file I/O, durability, and trust logic stay in Go and are shared with the
  CLI (`packages/engine` is consumed through its public API only — ADR 0006).
- The desktop client must feel native: native pickers, drag/drop, notifications, tray,
  background behavior, signing, and installer packaging on Windows, macOS, and Linux.
- CI must be able to build and test the app headlessly (no display server, minimal deps).
- The product UI (invite + QR, transfer progress, history, pause/resume) already exists as a
  web UI in `apps/web`; reusing that surface reduces product surface area and divergence.

The decision was re-evaluated at milestone kickoff (2026-08) against primary sources:
Wails v3.0.0-beta.0 shipped 2026-08-02 with a stable desktop API (beta announcement,
v3.wails.io); Fyne 2.8.0 shipped 2026-07-13 (fyne.io blog); Tauri v2 has been stable since
2024-10 (v2.9.x current). A thin-shell prototype was built against `packages/engine` before
committing (see Prototype below).

## Decision

Use **Wails v3** (`github.com/wailsapp/wails/v3`, currently `v3.0.0-beta.8`) for the desktop
host, with the Go engine driving everything through Wails services and a system-WebView
frontend.

Key properties that decided it:

1. **One language, one engine.** Services are plain Go methods that call `packages/engine`
   in-process. There is no second backend language, no sidecar process, and no IPC boundary
   for transfer logic — the CLI and desktop consume literally the same implementation.
2. **Headless CI and tests.** `go build -tags server` runs the same application as an HTTP
   server with no native window and **no cgo requirement**, so service/engine integration
   tests run on any runner with no display and no WebKit. Verified in the prototype: the
   shell builds with `CGO_ENABLED=0` and serves `/health` plus the embedded frontend.
   (Caveat: `go test -race` forces cgo, and Wails' internal Linux cgo packages are not yet
   `!server`-tagged, so race runs need the GTK4/WebKitGTK6 dev packages installed — the
   desktop CI job installs them once.)
3. **Web-view footprint.** Wails uses the platform WebView (WebKitGTK on Linux, WKWebView on
   macOS, WebView2 on Windows) — no bundled Chromium; binaries stay tens of MB.
4. **Native integration.** Dialogs, drag/drop, notifications, system tray, application
   menus, and multi-window are first-class platform APIs in v3 (examples: `dialogs`,
   `drag-n-drop`, `notifications`, `menu`).
5. **Packaging and signing.** Official guides exist for NSIS (Windows), DMG (macOS), Linux
   installers, and macOS/Windows code signing on CI; beta release artifacts ship with
   checksums and provenance.
6. **UI reuse.** The frontend is ordinary web tech (the web app is Svelte 5); the product UI
   patterns port directly, and the shell can even reuse the runtime bridge.
7. **Project health.** v3 has a stable desktop API, teams report production use, v2 remains
   a stable fallback, and the project has an explicit beta → RC → GA milestone process
   (35k+ stars; beta released 2026-08-02).

## Rejected alternatives

| Option                 | Status    | Why rejected                                                                                                                                                                                                                                                                                           |
| ---------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Fyne 2.8**           | Runner-up | Pure Go, race-clean, tiny footprint, easy cross-compile — credible if Wails stalls. But widgets are custom-rendered rather than native, the existing web UI cannot be reused (the rich transfer UI would be re-implemented from scratch in Go widgets), and installer/signing tooling is less turnkey. |
| **Tauri v2**           | Rejected  | Architecturally sound and stable, but its core is Rust: hosting the Go engine requires a sidecar process, splitting the single-engine mission (ADR 0006) and adding a second language + toolchain to the supply chain.                                                                                 |
| **Gio**                | Rejected  | Immediate-mode, low-level; dialogs/notifications/tray are DIY or partial; highest UI effort for a product.                                                                                                                                                                                             |
| **Gluon / go-flutter** | Rejected  | Go↔Flutter bindings are niche with uncertain maintenance; adds Dart.                                                                                                                                                                                                                                   |
| **Electron**           | Rejected  | Bundled Chromium footprint and a Node backend; the anti-pattern Wails exists to avoid.                                                                                                                                                                                                                 |

## Prototype

Before committing, a thin shell was built in a scratch module linking `packages/engine`
through a Wails v3 service:

- `application.New` with an `EngineService` (engine build info, capability set) and the
  embedded frontend asset server; `ServerOptions` for headless mode.
- `go build -tags server` with `CGO_ENABLED=0` produced a ~16–23 MB binary; running it
  served `/health` (`{"status":"ok"}`) and the embedded frontend plus `/wails/runtime.js`
  (the runtime bridge) over HTTP.
- The same service pattern drives a full in-process engine transfer (SPAKE2 rendezvous,
  encrypted relay, durable receive, whole-file verification) headlessly — the engine
  self-check that ships in the shell.

## Shell architecture (this PR)

```
apps/desktop/
  go.mod                     # github.com/sendbeam/desktop; requires engine + wails v3
  main.go                    # application.New + window + services; embed frontend/dist
  internal/engine/           # EngineService (Info, Caps, SelfCheck) + loopback relay
  frontend/dist/index.html   # thin shell UI calling services via /wails/runtime.js
```

- Desktop build: `go build .` (native window; needs platform WebView deps).
- Server build: `go build -tags server .` (headless HTTP; no GUI deps) — used by CI.
- All WebRTC, crypto, file I/O, durability, and trust logic lives in `packages/engine`;
  the shell adds no protocol or security logic of its own.

## Consequences

- CI gains a dedicated `desktop` job: server-tagged vet/test/race/build (headless) plus a
  full window build after installing GTK4/WebKitGTK6 dev packages.
- Local `just lint`/`just test`/`just fmt` cover the desktop module through the server tag,
  so no developer needs a GUI toolchain to contribute to the shell.
- The engine's public API becomes the contract for PR03 (core transfer product); shell
  services stay thin and move presentation concerns to the frontend.
- Risk accepted: v3 is beta. Mitigations: stable desktop API, production reports, v2
  fallback, and our engine/tests are framework-independent (they run headless either way).
