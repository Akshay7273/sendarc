# SendBeam Installation & Quickstart Guide

This guide details how to install and run the official SendBeam CLI and Desktop clients across Linux, macOS, and Windows.

---

## 1. Linux Installation

SendBeam offers multiple packaging formats for Linux: Debian packages (`.deb`), portable AppImages, and standalone CLI archives.

### A. Desktop Application

#### Option 1: Debian / Ubuntu Package (`.deb`)

```bash
# Download and install the Debian package
sudo dpkg -i sendbeam-desktop_<version>_amd64.deb

# If any dependencies are missing:
sudo apt-get install -f
```

This installs `sendbeam-desktop` to `/usr/bin/sendbeam-desktop`, registers desktop menu entries with icons, and configures file associations.

#### Option 2: Portable AppImage

The AppImage runs on any modern Linux distribution without installation:

```bash
# Make the AppImage executable
chmod +x SendBeam-linux-amd64.AppImage

# Launch SendBeam Desktop
./SendBeam-linux-amd64.AppImage
```

---

### B. CLI Terminal Client

```bash
# Extract the archive
tar -xzf sendbeam-cli-linux-amd64.tar.gz

# Install to /usr/local/bin
sudo install -m 755 sendbeam /usr/local/bin/sendbeam

# Verify installation
sendbeam version
```

---

## 2. macOS Installation

SendBeam is distributed as a Universal Mach-O binary bundle (`arm64` Apple Silicon + `x86_64` Intel) in both DMG and ZIP formats.

### A. Desktop Application

1. Download `SendBeam-macos-universal.dmg`.
2. Double-click to mount the disk image.
3. Drag **SendBeam.app** into your **Applications** folder.
4. Launch SendBeam from Applications or Spotlight.

---

### B. CLI Terminal Client

```bash
# Extract the appropriate architecture archive (arm64 for Apple Silicon, amd64 for Intel)
tar -xzf sendbeam-cli-darwin-arm64.tar.gz

# Install to /usr/local/bin
sudo install -m 755 sendbeam /usr/local/bin/sendbeam

# Verify installation
sendbeam version
```

---

## 3. Windows Installation

SendBeam provides an NSIS executable installer, a standalone portable ZIP, and a CLI executable for Windows.

### A. Desktop Application

#### Option 1: Executable Installer (Recommended)

1. Download and run `SendBeam-windows-amd64-installer.exe`.
2. Follow the setup wizard. The installer creates Start Menu shortcuts and registers SendBeam with the Windows Uninstaller.

#### Option 2: Portable ZIP

1. Download and extract `SendBeam-windows-amd64-portable.zip`.
2. Run `sendbeam-desktop.exe` directly from the extracted folder.

---

### B. CLI Terminal Client

1. Download and extract `sendbeam-cli-windows-amd64.zip`.
2. Copy `sendbeam.exe` to a folder included in your system `PATH` (e.g. `C:\Program Files\SendBeam` or `%USERPROFILE%\bin`).
3. Open PowerShell or Command Prompt and verify:

```powershell
sendbeam version
```

---

## 4. Checksum & Provenance Verification

All release packages and archives are hashed with SHA-256 and collected in the canonical manifest:

```bash
# Download SHA256SUMS.txt along with your release package, then verify:
sha256sum -c SHA256SUMS.txt
```

For cryptographic in-toto build provenance and SBOM verification, refer to [docs/supply-chain.md](supply-chain.md).

---

## 5. Quickstart: Your First Transfer

### Web App
Navigate to [omnitrix.space](https://omnitrix.space), drop your files to generate an invite code, or enter an invite code to receive.

### CLI

```bash
# Send a file or folder:
sendbeam send ./photo.jpg

# Receive using an invite code:
sendbeam receive 7-guitarist-melody
```

### Desktop
Open **SendBeam Desktop**, click **Send Files** (or drag and drop into the window), and share the generated code or QR code with the receiver.
