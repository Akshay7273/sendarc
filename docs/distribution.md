# Distribution and Native Packaging

This document outlines SendBeam's distribution architecture, multi-platform artifact packaging, build metadata injection, and verification standards.

## Supported Distribution Artifacts

SendBeam produces deterministic standalone artifacts for the CLI and Desktop clients across Linux, macOS, and Windows.

### 1. CLI Distributions

The `sendbeam` terminal client is compiled as a static or minimal-dependency binary for each target OS and architecture:

| Target  | Architecture | Archive Name                       | Binary Name    |
| :------ | :----------- | :--------------------------------- | :------------- |
| Linux   | `amd64`      | `sendbeam-cli-linux-amd64.tar.gz`  | `sendbeam`     |
| Linux   | `arm64`      | `sendbeam-cli-linux-arm64.tar.gz`  | `sendbeam`     |
| macOS   | `amd64`      | `sendbeam-cli-darwin-amd64.tar.gz` | `sendbeam`     |
| macOS   | `arm64`      | `sendbeam-cli-darwin-arm64.tar.gz` | `sendbeam`     |
| Windows | `amd64`      | `sendbeam-cli-windows-amd64.zip`   | `sendbeam.exe` |
| Windows | `arm64`      | `sendbeam-cli-windows-arm64.zip`   | `sendbeam.exe` |

Each CLI archive contains:

- `sendbeam` (or `sendbeam.exe`) executable
- `LICENSE`
- `README.md`

### 2. Desktop Distributions

The SendBeam Desktop application (built with Wails v3) packages the Go transfer engine with native platform presentation:

| Platform              | Format         | Artifact Name                          | Description                                                   |
| :-------------------- | :------------- | :------------------------------------- | :------------------------------------------------------------ |
| **Windows** (amd64)   | Portable ZIP   | `SendBeam-windows-amd64-portable.zip`  | Self-contained executable archive with license and metadata   |
| **Windows** (amd64)   | NSIS Installer | `SendBeam-windows-amd64-installer.exe` | Windows installer with Start Menu shortcuts and uninstaller   |
| **macOS** (Universal) | App Archive    | `SendBeam-macos-universal.zip`         | Mach-O Universal bundle (`arm64` + `amd64`) in `SendBeam.app` |
| **macOS** (Universal) | DMG Image      | `SendBeam-macos-universal.dmg`         | Disk image with drag-and-drop Applications shortcut           |
| **Linux** (amd64)     | Debian Package | `sendbeam-desktop_1.4.0_amd64.deb`     | Debian/Ubuntu `.deb` with `.desktop` menu entry and icons     |
| **Linux** (amd64)     | AppImage       | `SendBeam-linux-amd64.AppImage`        | Portable Linux executable with embedded runtime               |

> [!NOTE]
> CI distribution artifacts are unsigned validation packages. Official code signing (Authenticode, Apple Developer ID, Notarization) and trusted release channels will be enabled in subsequent milestones.

---

## Build Metadata and Versioning

Build metadata is decoupled from the immutable wire protocol version (`sendbeam/1`).

### Product Version Metadata

Binaries embed the following metadata injected via `-ldflags`:

- **Product Version**: Release tag (e.g. `1.4.0`) or `dev` fallback.
- **Git Commit**: Exact git commit SHA (e.g. `1e937f5e07ea...`) or short SHA.
- **Go Version**: Active Go toolchain version (from `runtime.Version()`).
- **Platform**: Target OS and Architecture (from `runtime.GOOS/runtime.GOARCH`).

### CLI Version Commands

```bash
sendbeam version
# Output: sendbeam dev (1e937f5e07ea)
# Tagged: sendbeam 1.4.0 (1e937f5e07ea)

sendbeam --version
# Output: sendbeam dev (1e937f5e07ea)
```

---

## Packaging Workflow and Verification

Packaging is automated in `.github/workflows/distribution.yml` across native GitHub-hosted runners:

- `ubuntu-24.04` (Linux packaging + GTK/WebKit)
- `macos-latest` (Universal Mach-O + DMG creation)
- `windows-latest` (Windows PE + NSIS compilation)

### Checksum Manifest

All produced distribution archives and installers are hashed with SHA-256 and collected into a canonical manifest:

```text
SHA256SUMS.txt
```
