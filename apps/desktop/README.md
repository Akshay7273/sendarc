# SendBeam Desktop

The desktop host for the shared Go engine (`packages/engine`), built on Wails v3 (see
`docs/adr/0007-desktop-framework.md`). All WebRTC, crypto, file I/O, durability, and trust
logic lives in the engine; the desktop is a thin presentation seam over the same public API
the CLI consumes, so a desktop peer interoperates with CLI and browser peers of the same
deployment out of the box.

## Core transfer product

- **Send** — pick multiple files and folders with the native dialog, or drag and drop them
  onto the window. A sender gets an invite: a code, a copyable join link, and a scannable
  QR of that link (generated in Go, no JS build step).
- **Receive** — paste a code or a full invite link, choose a destination folder (native
  picker), and receive verified, byte-identical files.
- **Live state** — phase (allocating → waiting → handshaking → established), transport
  (direct WebRTC / encrypted relay), SAS fingerprint once the key is confirmed, pause /
  resume / cancel controls, and a progress card with percent, five-second rolling speed,
  ETA, current file, and aggregate (N of M files).
- **Interop** — the service dials the signaling server with the same `wsclient` the CLI
  uses; a service test drives a full transfer over a real WebSocket signaling hub to prove
  the desktop speaks the browser/CLI protocol from the first implementation.

## Layout

- `main.go` — Wails application: window (with file drop enabled), services, embedded
  frontend. Forwards dropped files to the service.
- `build/` — packaging configuration and assets:
  - `appicon.png`, `icons/` — multi-resolution icon assets
  - `windows/` — Windows manifest, version info, icon, and NSIS installer scripts
  - `darwin/` — macOS `Info.plist`, `icons.icns`, and DMG assets
  - `linux/` — Linux `.desktop` entry, icons, AppImage AppRun, and Debian packaging metadata
- `internal/engine/` —
  - `service.go` — `EngineService` (`Info`, `Caps`, `SelfCheck`).
  - `transfer_service.go` — `TransferService` (`Send`, `Receive`, `Pause`, `Resume`,
    `Cancel`, `PickFiles`, `PickDestination`) streaming `sendbeam:transfer` snapshots.
  - `pickers.go` — native dialogs (graceful server-mode fallback).
  - `loopback.go` — in-process signaling relay used by tests and the self-check.
  - `transfer_service_test.go` — loopback transfers (single/multi-file, pause/resume/
    cancel, QR, invite links) and a real-WebSocket interop transfer.
- `frontend/dist/` — the product UI (plain HTML/JS over the Wails runtime bridge).

## Build and Packaging

### Source Builds

```bash
# Native window (needs platform WebView deps, e.g. libgtk-4-dev + libwebkitgtk-6.0-dev on Linux)
go build -o sendbeam-desktop .

# Headless server (no GUI deps; used by CI and tests)
go build -tags server -o sendbeam-desktop-server .
```

### Native Packaging

#### Windows (AMD64)

- **Portable ZIP**: `SendBeam-windows-amd64-portable.zip` containing `sendbeam-desktop.exe`, `LICENSE`, and `README.md`.
- **NSIS Installer**: `SendBeam-windows-amd64-installer.exe` compiled via NSIS (`makensis build/windows/nsis/project.nsi`).

#### macOS (Universal: ARM64 + AMD64)

- **Universal Application**: Compile `darwin/arm64` and `darwin/amd64` slices with `CGO_ENABLED=1`, merge with `lipo -create`, and construct `SendBeam.app`.
- **DMG**: Package `SendBeam-macos-universal.dmg` with `hdiutil create`.

#### Linux (AMD64)

- **AppImage**: Standalone executable bundle `SendBeam-linux-amd64.AppImage`.
- **Debian package**: Native `.deb` package `sendbeam-desktop_1.4.0_amd64.deb` containing desktop launcher, icons, and binaries.

> [!NOTE]
> Public signed installers and automated update channels will be published in a future milestone. Current packaging targets are unsigned validation builds.

## Test

```bash
go test -tags server ./...          # headless (no GUI deps)
go test -race -tags server ./...    # needs the GTK dev packages for wails internals
```

## Server mode

`go build -tags server` runs the same app as HTTP on `localhost:18123` (see `main.go`);
native dialogs and drag/drop degrade to a clear error so the headless build stays usable
for CI and smoke tests.

## Why Wails v3

The engine (WebRTC, crypto, file I/O, durability, trust) stays in Go and is consumed by the
CLI and desktop identically; the frontend is ordinary web tech over a system WebView. The
server build makes CI and tests fully headless. See ADR 0007 for the evaluation and rejected
alternatives (Fyne, Tauri, Gio, Electron).
