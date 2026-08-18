# Operational Troubleshooting & Network Diagnostics

This guide provides troubleshooting procedures for SendBeam network connectivity, transport fallback, single-instance process locks, and OS credential stores.

---

## 1. Network Diagnostics & Diagnostics Command

SendBeam includes built-in diagnostic tools that inspect network interfaces, STUN responsiveness, and signaling latency without exposing private information.

### CLI Diagnostics

Run `sendbeam diagnose` to run a comprehensive system and network self-check:

```bash
sendbeam diagnose
```

Example sanitized output:

```text
SendBeam Diagnostics:
  Product Version: 1.4.0 (42105680bc7a)
  OS/Arch:         linux/amd64
  Signaling:       wss://omnitrix.space/ws [reachable: 48ms]
  STUN Check:      stun.l.google.com:19302 [srflx candidate gathered: 203.0.113.45:49210]
  Local Interfaces: eth0 (192.168.1.100/24), wlan0 (10.0.0.15/24)
  Relay Readiness: Ready (WebSocket upgrade OK)
```

To export machine-readable diagnostics for bug reports:

```bash
sendbeam diagnose --json > diagnostics.json
```

> [!NOTE]
> Diagnostic outputs are automatically sanitized: filenames, directory paths, file contents, invite words, passwords, and full IP addresses (beyond the first two octets) are excluded.

---

## 2. Network Topologies & Transport Fallback

SendBeam uses an adaptive path selection engine that races direct WebRTC against the encrypted WebSocket relay:

| Network Condition                         | Behavior                                                                     | Expected Resolution                                               |
| :---------------------------------------- | :--------------------------------------------------------------------------- | :---------------------------------------------------------------- |
| **Open Internet / UPnP / Full-Cone NAT**  | Direct WebRTC engaged within ~1.2s.                                          | High-speed direct peer-to-peer.                                   |
| **UDP Blocked (Corporate Firewalls)**     | No STUN response gathered; relay warms and engages in ~5.2s.                 | Automatic encrypted WebSocket relay fallback over HTTPS port 443. |
| **Symmetric NAT to Symmetric NAT**        | Direct hole-punching impossible; ICE fails after negotiation timeout (~11s). | Automatic encrypted WebSocket relay fallback.                     |
| **Relay Only Requested (`--relay-only`)** | Skips WebRTC ICE gathering entirely.                                         | Instant encrypted relay connection.                               |

### Firewall Ports

If configuring corporate or router firewalls to optimize direct WebRTC transfers:

- **Egress UDP:** Ports 1024–65535 (for STUN/WebRTC media).
- **Egress TCP / HTTPS:** Port 443 (for signaling and encrypted WebSocket relay).

---

## 3. Resolving Single-Instance Lock Issues

SendBeam Desktop enforces single-instance execution to prevent multiple processes from corrupting persistent journals or clobbering network sockets.

### Symptoms

- Launching Desktop displays: `SendBeam is already running`.
- A background instance is active in the system tray.

### Resolution

1. **Check the System Tray:**
   - Look for the SendBeam icon in your taskbar / system tray (macOS menu bar, Windows system tray, or Linux notification area).
   - Click the icon and select **Show SendBeam** or **Quit SendBeam**.

2. **Terminating Stale Background Processes:**
   - **Linux / macOS:**
     ```bash
     killall sendbeam-desktop
     ```
   - **Windows (PowerShell):**
     ```powershell
     Stop-Process -Name sendbeam-desktop -Force
     ```

3. **Clearing Stale Lock Files:**
   If a hard crash prevented lock cleanup:
   - Linux: Delete `~/.config/sendbeam/sendbeam.lock`
   - macOS: Delete `~/Library/Application Support/SendBeam/sendbeam.lock`
   - Windows: Delete `%APPDATA%\SendBeam\sendbeam.lock`

---

## 4. Secret Store Troubleshooting

SendBeam Desktop integrates with native credential managers to protect TURN credentials.

### Linux: `SecretStoreUnavailable`

On minimal or headless Linux installations without a running D-Bus Secret Service:

- Install `gnome-keyring` or `libsecret-tools`:
  ```bash
  sudo apt-get install gnome-keyring libsecret-tools
  ```
- Or run in headless/CLI mode where sensitive TURN credentials can be passed via command-line arguments.

### macOS: Keychain Prompts

- If prompted by macOS Keychain to grant access to SendBeam, select **Always Allow** to allow background credential access for scheduled updates and self-host credentials.
