# Configuring Clients for Self-Hosted Servers

SendBeam native clients (CLI and Desktop) can easily be pointed to any private or enterprise self-hosted signaling and relay server (`sendbeamd`).

For instructions on deploying the server, refer to [docs/HOSTING.md](HOSTING.md).

---

## 1. CLI Client Configuration

### Custom Signaling / Relay Server

By default, the CLI connects to the public rendezvous server. To target your private server:

```bash
# Send via custom server:
sendbeam send ./archive.tar.gz --server "wss://relay.example.com/ws"

# Receive via custom server:
sendbeam receive 7-guitarist-melody --server "wss://relay.example.com/ws"
```

### Development / Self-Signed TLS

If your self-hosted server is running in a local environment or testing lab with a self-signed TLS certificate:

```bash
sendbeam send ./file.txt --server "wss://localhost:8443/ws" --insecure-skip-verify
sendbeam receive 7-code --server "wss://localhost:8443/ws" --insecure-skip-verify
```

> [!WARNING]
> `--insecure-skip-verify` disables TLS certificate validation and should only be used for local development and test labs. End-to-end payload encryption remains active via SPAKE2 / AES-GCM.

### Custom STUN & TURN Servers

Add custom STUN / TURN servers for direct-path ICE candidate gathering:

```bash
# Specify custom STUN server (repeatable flag):
sendbeam send ./file.txt --ice-server "stun:stun.example.com:3478"

# Force the encrypted WebSocket relay transport (bypassing WebRTC):
sendbeam send ./file.txt --relay-only
```

---

## 2. Desktop Client Configuration

The Desktop application stores configuration in a structured JSON file and persists sensitive credentials in native OS secret storage.

### Setting the Server URL in UI

1. Open **SendBeam Desktop**.
2. Open **Settings** (gear icon or menu).
3. In **Server URL**, enter your signaling server endpoint (e.g. `wss://relay.example.com/ws`).
4. Click **Save**. The client immediately uses this server for new invite generation and room connections.

---

## 3. OS Secret Storage Integration

SendBeam Desktop enforces strict security invariants for credentials:

- **Plaintext Forbidden:** Passwords and secrets are **never** stored in plaintext within the configuration file (`config.json`).
- **Hardware & User-Bound Storage:** Credentials are saved exclusively using the operating system's credential manager:
  - **macOS:** Apple Keychain via Security Services framework (`/usr/bin/security`).
  - **Windows:** Data Protection API (DPAPI per-user encryption) with secure streaming.
  - **Linux:** Secret Service API (via `secret-tool` / libsecret / GNOME Keyring / KWallet).
- **Fail-Closed Policy:** If the OS secret store is unavailable, SendBeam fails closed (`ErrSecretStoreUnavailable`) rather than silently falling back to insecure plaintext files.

### Configuration Schema (`config.json`)

```json
{
  "server_url": "wss://relay.example.com/ws",
  "close_to_tray": true,
  "start_minimized": false,
  "notifications_enabled": true,
  "ice_servers": [
    {
      "urls": ["stun:stun.example.com:3478"]
    },
    {
      "urls": ["turn:turn.example.com:3478"],
      "username": "sendbeam-user",
      "credential_ref": "turn-password-ref"
    }
  ]
}
```

Notice that `credential_ref` references a key in the OS secret store, preserving zero plaintext exposure on disk.
