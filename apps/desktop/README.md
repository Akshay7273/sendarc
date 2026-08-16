# SendBeam Desktop

The desktop host for the shared Go engine (`packages/engine`), built on Wails v3 (see
`docs/adr/0007-desktop-framework.md`). This is the thin shell from V14-PR02: an app window,
a service seam over the engine, and a self-check that proves the engine works end to end.
The core transfer product UI lands in V14-PR03.

## Layout

- `main.go` — Wails application: window, services, embedded frontend.
- `internal/engine/` — `EngineService` exposing the engine to the frontend (`Info`, `Caps`,
  `SelfCheck`) and the in-process loopback relay used by the self-check.
- `frontend/dist/` — the shell UI (plain HTML/JS over the Wails runtime bridge).

## Build

```bash
# Native window (needs platform WebView deps, e.g. libgtk-4-dev + libwebkitgtk-6.0-dev on Linux)
go build -o sendbeam-desktop .

# Headless server (no GUI deps; used by CI and tests)
go build -tags server -o sendbeam-desktop-server .
```

## Test

```bash
go test -tags server ./...
```

## Why Wails v3

The engine (WebRTC, crypto, file I/O, durability, trust) stays in Go and is consumed by the
CLI and desktop identically; the frontend is ordinary web tech over a system WebView. The
server build makes CI and tests fully headless. See ADR 0007 for the evaluation and rejected
alternatives (Fyne, Tauri, Gio, Electron).
