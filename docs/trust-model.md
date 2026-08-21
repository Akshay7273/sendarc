# Trust & Device Identity Model

Scope: SendBeam v1.5 introduces persistent device identity and trusted device mesh capabilities, allowing paired devices to authenticate each other and automate transfers without centralized accounts, global directories, or server-side file persistence.

---

## 1. Cryptographic Device Identity

Every SendBeam client generates and manages an independent, long-term cryptographic identity.

### 1.1 Key Material

- **Algorithm:** Ed25519 (`crypto/ed25519` in Go, `@noble/curves/ed25519` in TypeScript).
- **Public Key:** 32 bytes raw.
- **Private Key:** 32-byte private seed (never transmitted across any network boundary or exported into logs).

### 1.2 Canonical Device Identifier (`DeviceID`)

The `DeviceID` is an immutable, collision-resistant string derived deterministically from the public key:

```
DeviceID = "sb-dev-" || LowercaseHex(SHA-256(RawPublicKey[32]))
```

- **Length:** 71 characters (`sb-dev-` prefix + 64 hex characters).
- **Properties:** Universally unique, content-addressed to the public key, independent of human names or network addresses.

### 1.3 Human-Verifiable Fingerprint

For visual comparison and out-of-band out-of-screen verification:

```
Fingerprint = "SB1-" || FormatBase32_4x4(SHA-256(RawPublicKey[32])[0..10])
```

- **Example:** `SB1-MW3A-M46W-5WEE-X4A4`
- **Properties:** 80 bits of cryptographic pre-image resistance, grouped into 4 uppercase alphanumeric chunks for effortless visual inspection.

---

## 2. Key Storage & Protection

The private seed is protected locally according to the platform's security capabilities:

| Platform        | Storage Mechanism                        | Fallback / Degradation                                                    |
| :-------------- | :--------------------------------------- | :------------------------------------------------------------------------ |
| **macOS**       | Keychain Services / Protected File       | User-confined directory (`~/.config/sendbeam/identity.key`, `0600` perms) |
| **Windows**     | DPAPI / Protected File                   | User app data directory (`%APPDATA%\SendBeam\identity.key`, `0600` ACL)   |
| **Linux / BSD** | Secret Service API / Protected File      | User config directory (`~/.config/sendbeam/identity.key`, `0600` perms)   |
| **Browser**     | IndexedDB / WebCrypto non-exportable key | LocalStorage is strictly refused for raw private keys                     |

Silent downgrade to insecure plaintext persistence is forbidden.

---

## 3. Local Trust Database (`trust.json`)

Paired devices are recorded in a local versioned database containing identity bindings and policy parameters.

### 3.1 Record Schema

```json
{
  "device_id": "sb-dev-65b60673d6ed884bf01c2c222d82ada0740f29ac3355d6a925c81f17f47a27b8",
  "public_key": "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664",
  "local_label": "Work Laptop (M3 Max)",
  "pair_credential_ref": "cred-78f9a20...",
  "capabilities": ["transfer.v1", "transfer.v2", "lan_direct", "auto_accept"],
  "first_seen_at": "2026-08-21T06:00:00Z",
  "last_seen_at": "2026-08-21T06:45:00Z",
  "revoked": false,
  "revoked_at": null,
  "policy": {
    "auto_accept": true,
    "auto_accept_dest_dir": "/home/user/Downloads/SendBeam",
    "max_file_size_bytes": 10737418240,
    "allowed_mime_types": []
  }
}
```

### 3.2 Atomicity & Concurrency Safety

- Writes use **atomic temporary files and renames** (`trust-*.tmp` → `trust.json`) with restricted permissions (`0600`).
- Process-level mutexes and cooperative file locks prevent concurrent read/write corruptions.

---

## 4. Trust Boundaries & Revocation Semantics

### 4.1 Local Revocation vs. Global Accounts

SendBeam operates strictly without centralized accounts or global directory servers.

- **Local Unpair / Revoke:** Revoking a device removes or marks the local trust record as revoked. Future connection attempts from that device will be rejected immediately during the authenticated handshake.
- **Honest Limitations:** There is no centralized server revocation list (CRL) or account-wide revocation. If Device A revokes Device B, Device A will reject Device B. If Device B still has Device A in its local DB, Device B's attempts to connect to Device A will fail authentication.

### 4.2 Display Names vs. Cryptographic Identity

- **Display labels are strictly local user metadata.** Display names transmitted over the wire are never used as a trust anchor.
- Authentication binds to the `DeviceID` (public key digest) and cryptographic signatures.

---

## 5. Auto-Accept Policy & Confinement

Automated transfers (e.g. CLI daemon or background desktop receiver) require strict safety bounds:

1. **Explicit Opt-in:** `auto_accept` defaults to `false`. It must be explicitly configured per-device.
2. **Absolute Destination Directory:** `auto_accept_dest_dir` must be an absolute path. Setting it to filesystem root (`/` or `C:\`) is strictly rejected.
3. **Path Sanitization:** File names are subject to strict relative path validation (`safe_path.go` / `safe-path.ts`) to prevent directory traversal or symlink escapes outside the designated destination root.
4. **Quota & Size Caps:** Incoming files exceeding `max_file_size_bytes` or available disk headroom abort before writing to disk.

---

## 6. One-Time Pairing Ceremony

The pairing ceremony bootstraps long-term pairwise trust through the existing SPAKE2 authenticated channel without requiring central servers.

```mermaid
sequenceDiagram
    autonumber
    participant A as Initiator (Alice)
    participant B as Responder (Bob)
    Note over A,B: 1. Complete SPAKE2 Handshake -> Shared Master Key
    A->>B: PairingRequest (DeviceID, PubKey, Name, Caps, Nonce_A, Sig_A)
    Note over B: 2. Verify Sig_A against PubKey & MasterKey<br/>Check DeviceID == sha256(PubKey)
    B->>A: PairingResponse (DeviceID, PubKey, Name, Caps, Nonce_B, Sig_B)
    Note over A: 3. Verify Sig_B against PubKey & MasterKey<br/>Derive k_pair & credRef
    Note over B: 4. Derive k_pair & credRef (Identical Symmetrical State)
    A->>B: PairingConfirm (Status: accepted, AuthTag: HMAC(k_pair, ID_B))
    B->>A: PairingConfirm (Status: accepted, AuthTag: HMAC(k_pair, ID_A))
    Note over A,B: 5. Store Peer TrustRecord in trust.json
```

### 6.1 Cryptographic Transcript Binding

- **Request Challenge:** `"sendbeam/1 pairing-request:" || SHA-256(MasterKey) || Nonce_A || DeviceID_A`
- **Response Challenge:** `"sendbeam/1 pairing-response:" || SHA-256(MasterKey) || Nonce_A || Nonce_B || DeviceID_B`
- Both signatures are signed with the device's private Ed25519 key.

### 6.2 Pair Credential Derivation (`k_pair`)

```
k_pair = HKDF-SHA256(
    IKM = MasterKey,
    Salt = Nonce_A || Nonce_B,
    Info = "sendbeam/1 pair-credential" || LexicographicalSort(PubKey_A, PubKey_B),
    Length = 32 bytes
)
PairCredentialRef = "cred-" || LowercaseHex(SHA-256(k_pair))
```

### 6.3 Re-Pairing & Conflict Mitigation

- **Legitimate Re-Pairing:** When a known device reconnects with the same cryptographic key, its local label, capabilities, and `LastSeenAt` timestamp are safely updated.
- **Key & Label Conflicts:**
  - If a pairing peer claims an active name already assigned to a different public key, the ceremony aborts with `ErrLabelConflict`.
  - Silent key overwrites are strictly forbidden to prevent impersonation attacks.

---

## 7. Trusted-Session Authentication (`sendbeam/2`)

Repeat connections between paired devices authenticate without human codes or passwords using mutual challenge-response verification over ephemeral key material.

```mermaid
sequenceDiagram
    autonumber
    participant A as Initiator
    participant B as Responder
    Note over A: 1. Generate Ephem_A, Nonce_A<br/>Sign Challenge_A with Ed25519<br/>Compute MAC_A using k_pair
    A->>B: TrustedAuthInit (InitID, RespID, CredRef, Ephem_A, Nonce_A, Caps_A, TS, Sig_A, MAC_A)
    Note over B: 2. Check TrustStore & Revocation<br/>Verify Timestamp (±5 min)<br/>Verify Sig_A & MAC_A
    Note over B: 3. Generate Ephem_B, Nonce_B<br/>Sign Challenge_B with Ed25519<br/>Compute MAC_B using k_pair
    B->>A: TrustedAuthResponse (Status, RespID, Ephem_B, Nonce_B, Caps_B, Sig_B, MAC_B)
    Note over A: 4. Verify Sig_B & MAC_B
    Note over A,B: 5. Derive Forward-Secret Session Keys (k_i2r, k_r2i)
    A->>B: TrustedAuthConfirm (Status: ready, AuthTag: HMAC(Master, InitID))
    B->>A: TrustedAuthConfirm (Status: ready, AuthTag: HMAC(Master, RespID))
    Note over A,B: 6. Secure Transfer Epoch Established
```

### 7.1 Forward-Secret Key Schedule

```
IKM = HMAC-SHA256(k_pair, Ephem_A || Ephem_B || Nonce_A || Nonce_B)
Salt = Nonce_A || Nonce_B
Transcript = "sendbeam/2 trusted-resp:" || SHA-256(k_pair) || Ephem_A || Ephem_B || Nonce_A || Nonce_B || InitID || RespID || SHA-256(NegotiatedCaps)

SessionMaster = HKDF-SHA256(IKM, Salt, "sendbeam/2 session-master:" || Transcript, 32)
k_i2r = HKDF-SHA256(SessionMaster, nil, "sendbeam/2 initiator-to-responder key", 32)
k_r2i = HKDF-SHA256(SessionMaster, nil, "sendbeam/2 responder-to-initiator key", 32)
```

### 7.2 Replay & Revocation Enforcement

- **Timestamp Skew Bounding:** Timestamps outside ±5 minutes are rejected immediately (`ErrTrustedTimestampSkew`).
- **Cryptographic Binding:** The signature and MAC tag strictly bind `k_pair`, `EphemeralPub`, `Nonce`, `DeviceID`, and `NegotiatedCapabilities`.
- **Local Revocation:** If a peer has been marked `revoked: true` in the local trust database, all connection attempts are rejected with `ErrTrustedPeerRevoked`.
- **Protocol Boundary:** One-time pairing and transfers remain compatible via `sendbeam/1`, while trusted-device mesh operations use `sendbeam/2`.

---

## 8. Privacy-Preserving Remote Presence & LAN Discovery

SendBeam allows paired devices to discover each other across the internet and local networks without leaking device identities, filenames, user accounts, or global directories.

### 8.1 Opaque Epoch-Rotated Rendezvous Handles

To discover peers over the signaling server without creating a global directory or publishing device IDs:

- **Pairwise Time-Windowed Handle Derivation:**
  ```
  epochIndex = floor(unixTimestampSeconds / 900)  // 15-minute epoch window
  handle = HMAC-SHA256(k_pair, "sendbeam/2 rendezvous-handle:" || epochIndex)
  ```
- **Clock Drift Tolerance:** Clients compute candidate handles for `[epochIndex-1, epochIndex, epochIndex+1]` to tolerate clock skew.
- **Server Privacy:** The signaling server matches connections solely on exact handle equality. The server cannot determine which devices share a handle or link different epoch handles together.

### 8.2 Blinded LAN Discovery Beacons

For local network (Wi-Fi/LAN) direct transfer without internet roundtrips:

- **Beacon Frame Format:**
  - Header (32 bytes): Magic `"SB2B"`, Version `1`, TCP Listening Port (2 bytes), Timestamp (8 bytes), Nonce (16 bytes), Tag Count (1 byte).
  - Tags: Up to 32 truncated 16-byte blinded tags.
- **Blinded Tag Formula:**
  ```
  tag = HMAC-SHA256(k_pair, "sendbeam/2 lan-beacon:" || Nonce || epochIndex)[0:16]
  ```
- **Local Matching:** Listening nodes compute candidate tags using `k_pair` secrets from their local trust stores. Unpaired third parties on the LAN only see pseudorandom bytes.
- **Direct LAN Connection:** When a peer is matched on LAN, nodes connect directly via TCP/TLS, bypassing internet signaling and relay.

---

## 9. CLI Automation & Mesh Operations

The `sendbeam` CLI provides scriptable trusted-device operations:

- `sendbeam devices [--json]`: Lists all paired devices with fingerprint, authorization policy, and last authenticated contact.
- `sendbeam pair [code] [--name <label>] [--auto-accept --dest <dir>]`: Runs the mutual pairing ceremony over one-time SPAKE2 room codes.
- `sendbeam unpair <device> [--yes] [--purge]`: Revokes or purges trust credentials for a specified device ID, label, or fingerprint.
- `sendbeam send <paths...> @<device>`: Directly transfers files to a trusted device without human room codes or interactive prompts.
- `sendbeam listen [--dest <dir>] [--auto-accept] [--once]`: Background daemon listening for incoming LAN discovery beacons and opaque rendezvous presence.
