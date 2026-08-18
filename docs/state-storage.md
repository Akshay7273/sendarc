# State Storage & Filesystem Locations

This document provides a comprehensive mapping of where SendBeam stores persistent state, configuration, transfer journals, sender records, and temporary files across Linux, macOS, Windows, and Web browsers.

---

## 1. Directory Overview by Operating System

| Platform    | Configuration Root (`ConfigDir`)                                          | Durable Data Root (`DataDir`)                                             |
| :---------- | :------------------------------------------------------------------------ | :------------------------------------------------------------------------ |
| **Linux**   | `$XDG_CONFIG_HOME/sendbeam`<br>(Default: `~/.config/sendbeam`)            | `$XDG_DATA_HOME/sendbeam`<br>(Default: `~/.local/share/sendbeam`)         |
| **macOS**   | `~/Library/Application Support/SendBeam`                                  | `~/Library/Application Support/SendBeam`                                  |
| **Windows** | `%APPDATA%\SendBeam`<br>(e.g. `C:\Users\<User>\AppData\Roaming\SendBeam`) | `%APPDATA%\SendBeam`<br>(e.g. `C:\Users\<User>\AppData\Roaming\SendBeam`) |
| **Web App** | IndexedDB (`sendbeam-state`)                                              | Origin Private File System (`OPFS`)                                       |

---

## 2. File & Directory Breakdown

### A. Desktop Configuration

- **File:** `config.json`
- **Location:** `<ConfigDir>/config.json`
- **Contents:** User settings (signaling server URL, close-to-tray preference, notifications toggle, STUN/TURN server URLs, and non-secret credential references).

### B. Single-Instance Lock

- **File:** `sendbeam.lock`
- **Location:** `<ConfigDir>/sendbeam.lock`
- **Purpose:** Acquired at application startup via OS file locking (`flock` on Unix, `LockFileEx` on Windows) to guarantee single-instance execution. Automatically released upon process termination.

### C. Durable Receive Journals (v1.3 Durable Resume)

- **Directory:** `.sendbeam/journals` (inside destination output directory)
- **Purpose:** Records block-granular verified progress, transfer ID, expected manifest fingerprint, and resume credentials for interrupted file downloads.
- **Cleanup:** Automatically purged upon verified file completion or explicitly via `sendbeam transfers discard <id>`.

### D. Sender Restart Records

- **Directory:** `<DataDir>/senders` (or `~/.sendbeam/senders`)
- **Purpose:** Stores local path key mappings to transfer IDs and resume secret envelopes so that re-sending the same files can resume an interrupted session without retransmitting already-committed blocks.

### E. Native Credentials & Keychains

- **macOS:** Stored in login keychain with service name `com.sendbeam.desktop`.
- **Windows:** Encrypted with current user SID using Windows DPAPI.
- **Linux:** Stored in default Secret Service keyring (`org.freedesktop.Secret.Generic`).

---

## 3. Web Client Storage Architecture

| Web Storage Primitive                 | Purpose                                                                                   | Lifetime                                                                                      |
| :------------------------------------ | :---------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------- |
| **IndexedDB** (`sendbeam_journals`)   | Tracks transfer progress checkpoints, transfer lease IDs, and resume credentials.         | Persistent across page reloads and browser restarts until transfer completes or is discarded. |
| **Origin Private File System (OPFS)** | Streams and stores incoming partial file chunks (`*.part`) with block-granular integrity. | Retained during interrupted transfers; finalized atomically to user download when complete.   |
| **SessionStorage / LocalStorage**     | Ephemeral UI states and theme preferences.                                                | Standard browser storage lifetime.                                                            |

---

## 4. Managing and Clearing State

### CLI Transfers Command

```bash
# List all active or interrupted durable transfer journals:
sendbeam transfers list

# Inspect details of an interrupted transfer:
sendbeam transfers inspect <transfer-id>

# Resume an interrupted transfer:
sendbeam transfers resume <transfer-id> --code 7-guitarist-melody

# Discard an interrupted transfer and delete partial chunks:
sendbeam transfers discard <transfer-id>

# Discard all interrupted journals:
sendbeam transfers discard-all
```

### Complete Reset

To remove all local configuration and cached state:

- **Linux:** `rm -rf ~/.config/sendbeam ~/.local/share/sendbeam`
- **macOS:** `rm -rf ~/Library/Application\ Support/SendBeam`
- **Windows (PowerShell):** `Remove-Item -Recurse -Force "$env:APPDATA\SendBeam"`
- **Web App:** Clear site storage for `omnitrix.space` in browser developer tools.
