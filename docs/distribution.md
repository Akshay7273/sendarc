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

The SendBeam Desktop application packages the Go transfer engine with native platform presentation:

| Platform              | Format         | Development Artifact Name                             | Tagged Release Artifact Name           | Description                                                   |
| :-------------------- | :------------- | :---------------------------------------------------- | :------------------------------------- | :------------------------------------------------------------ |
| **Windows** (amd64)   | Portable ZIP   | `SendBeam-windows-amd64-portable.zip`                 | `SendBeam-windows-amd64-portable.zip`  | Self-contained executable archive with license and metadata   |
| **Windows** (amd64)   | NSIS Installer | `SendBeam-windows-amd64-installer.exe`                | `SendBeam-windows-amd64-installer.exe` | Windows installer with Start Menu shortcuts and uninstaller   |
| **macOS** (Universal) | App Archive    | `SendBeam-macos-universal.zip`                        | `SendBeam-macos-universal.zip`         | Mach-O Universal bundle (`arm64` + `amd64`) in `SendBeam.app` |
| **macOS** (Universal) | DMG Image      | `SendBeam-macos-universal.dmg`                        | `SendBeam-macos-universal.dmg`         | Disk image with drag-and-drop Applications shortcut           |
| **Linux** (amd64)     | Debian Package | `sendbeam-desktop_0.0.0~dev+git.<shortsha>_amd64.deb` | `sendbeam-desktop_<ver>_amd64.deb`     | Debian/Ubuntu `.deb` with `.desktop` menu entry and icons     |
| **Linux** (amd64)     | AppImage       | `SendBeam-linux-amd64.AppImage`                       | `SendBeam-linux-amd64.AppImage`        | Portable Linux executable with embedded runtime               |

> [!NOTE]
> CI distribution artifacts are unsigned validation packages stored as GitHub Actions workflow artifacts (retained for 14 days). Formal GitHub Releases, production code signing (Authenticode, Apple Developer ID, Notarization), and auto-updater channels belong to future milestones.

---

## Authoritative Version Resolution Policy

Build and packaging metadata is resolved deterministically through [scripts/version-metadata.sh](scripts/version-metadata.sh) across all CLI and desktop platforms:

| Version Field                | Untagged / Development / PR Builds | Tagged Release Builds (`vX.Y.Z`) | Description                                                          |
| :--------------------------- | :--------------------------------- | :------------------------------- | :------------------------------------------------------------------- |
| **Internal Product Version** | `dev`                              | `X.Y.Z`                          | Go `-ldflags` embedded product build version (`ProductVersion`)      |
| **Display Version**          | `dev`                              | `X.Y.Z`                          | Human-facing CLI version UX and installer display string             |
| **macOS Short Version**      | `0.0.0`                            | `X.Y.Z`                          | `CFBundleShortVersionString` (strictly `[0-9]+(\.[0-9]+)*`)          |
| **macOS Bundle Version**     | `0.0.0`                            | `X.Y.Z`                          | `CFBundleVersion` (strictly numeric dotted version)                  |
| **Windows Fixed Version**    | `0.0.0.0`                          | `X.Y.Z.0`                        | 4-part numeric PE `FixedFileInfo` (`FileVersion` / `ProductVersion`) |
| **Debian Package Version**   | `0.0.0~dev+git.<shortsha>`         | `X.Y.Z`                          | Debian-compliant package version string                              |
| **Git Commit**               | Exact 40-character commit SHA      | Exact 40-character commit SHA    | Full git commit SHA embedded via `-ldflags`                          |

Wire protocol versioning remains immutable (`sendbeam/1`) and is decoupled from product release versions.

### CLI Version UX

```bash
# Development build:
sendbeam version
# Output: sendbeam dev (1e937f5e07ea)

# Tagged release build:
sendbeam version
# Output: sendbeam 1.4.0 (1e937f5e07ea)
```

---

## Packaging Workflow and Verification

Packaging is automated in `.github/workflows/distribution.yml` across native GitHub-hosted runners:

- `ubuntu-24.04` (Linux packaging + GTK/WebKit)
- `macos-latest` (Universal Mach-O + DMG creation)
- `windows-latest` (Windows PE resource embedding + NSIS compilation)

### Checksum Manifest & Supply Chain Integrity

All produced distribution archives, installers, and SPDX 2.3 SBOM manifests are hashed with SHA-256 and collected into a canonical manifest:

```text
SHA256SUMS.txt
```

- Cryptographic build provenance: attested in CI via `actions/attest-build-provenance@v2`.
- Software Bill of Materials: generated via `scripts/generate-sbom.sh` (`sendbeam-cli.spdx.json`, `sendbeam-desktop.spdx.json`).
- Detailed supply chain security model: [docs/supply-chain.md](supply-chain.md).
- Standalone self-updater architecture & rollback: [docs/updater.md](updater.md).
