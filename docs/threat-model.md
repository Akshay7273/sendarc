# Threat model

Scope: SendBeam transfers a file directly between two peers (browser or terminal). This
document states what we defend against, what we deliberately do not, and why. The wire
protocol it refers to is specified in [`protocol.md`](./protocol.md).

## Security goals

- **Confidentiality** of file contents, filenames, and metadata against the server and any
  network observer, on both the direct and relay paths.
- **Integrity**: the receiver reconstructs exactly the bytes the sender sent, or the
  transfer fails closed. No silent corruption.
- **Peer authentication**: both ends prove knowledge of the invite code, so a malicious or
  compromised server cannot MITM the connection.

## Trust boundaries

- The **signaling/relay server is untrusted** for confidentiality and integrity. It is
  trusted only for availability and correct routing, and even routing is bound to the
  invite code — the server never learns the words, so it cannot silently redirect a peer
  into a handshake it can complete.
- The **network is untrusted** (passive and active attackers).
- Each **peer trusts the other peer** by construction: anyone holding the full invite code
  can authenticate. Authentication proves "you have the code," not a human identity.
- The **local machine and browser are trusted** (out of scope: malware, a hostile browser
  extension, a compromised OS).
- The **durable journal is local, user-editable state** (`docs/adr/0004-durable-journal.md`).
  Its checksum and manifest-fingerprint checks detect corruption, torn writes, and casual
  tampering; they are **not** a trust anchor — anything that can rewrite the file can
  recompute them. Resume-time validation binds journal claims (transfer ID, manifest
  fingerprint, per-file digests, identity envelopes) against authenticated transfer state,
  and the journal never persists raw session key material (no master keys, directional
  keys, live AEAD counters, or credentials; only the opaque versioned `resumeSecret`
  envelope defined by the future resume protocol). Corrupt, torn, unknown, or unsupported
  journal state fails closed and is never partially applied.
- The **local trust database and device identity keys are local, user-protected state**
  ([`docs/trust-model.md`](./trust-model.md)). Device identity is backed by an Ed25519 keypair
  whose private seed is stored in OS-protected credential facilities or restricted filesystem
  permissions (`0600`). Device IDs (`sb-dev-...`) and fingerprints (`SB1-...`) are deterministic
  hashes of the public key; human display labels never authenticate identity. Automated
  acceptance is strictly opt-in per device and bounded to an absolute destination directory
  with full path sanitization. Unpairing or revocation is enforced locally without relying on
  centralized servers.

## Adversaries and mitigations

### Malicious server / active network MITM

The invite-code-authenticated handshake — SPAKE2 (RFC 9382, P-256) with RFC 9382 key
confirmation — runs before WebRTC. Because the server never sees the words, it cannot
derive the SPAKE2 password; a MITM attempt yields a confirmation-MAC mismatch and aborts
closed. SDP and ICE messages are authenticated so a malicious server cannot substitute its
own SDP to MITM the DataChannel:

```
mac = HMAC-SHA256(k_auth, utf8(type) || ":" || u32be(room) || ":" || u32be(seq) || ":" || body)
```

where `k_auth` is retained SPAKE2 key-confirmation material: each peer signs with its own
confirmation key and verifies with the peer's. This binds the DTLS fingerprint, the room,
and message order, so SDP/ICE cannot be swapped or replayed. Confidentiality never relies
on DTLS: the AES-GCM frame layer keyed by the handshake output is the end-to-end guarantee
on both paths. As defense in depth, both peers derive an identical short fingerprint from
the master key that the two humans can compare out of band.

### Passive server on the relay path

Sees ciphertext, message sizes, and timing only. No plaintext, no filenames, no keys. This
is documented, not hidden — see accepted limitations below.

### TURN server

TURN is **optional** (`docs/adr/0003-path-selection.md`). When an operator configures a TURN
server, it acts as a third-party relay for WebRTC datagrams: it sees only encrypted
AEAD/DTLS datagrams, never plaintext file contents, filenames, or keys (the application-layer
AES-GCM frame is the end-to-end confidentiality guarantee on every candidate). Like the relay,
the TURN server observes connectivity metadata (source/destination addresses and ports,
timing) that a passive network observer would see anyway. Because the authenticated SDP/ICE
exchange binds the DTLS fingerprint and negotiating a second MITM SDP is impossible, a TURN
server that dropped or tampered with datagrams would only cause a connectivity failure, not a
confidentiality or integrity break. Operators may use short-lived TURN credentials, which
clients honour via the 15-minute runtime-ICE-config TTL (`HOSTING.md`).

### Replay / reordering / tampering

AES-256-GCM with a per-direction monotonic nonce counter; the frame header is the GCM AAD,
binding each frame to its position (file, block, offset, length). A reused counter is
refused rather than risk nonce reuse. Any tampering fails the GCM auth tag; a bad per-block
SHA-256 escalates to abort (no blind retry). Resume state is a claim, not a trust anchor: a
receiver only applies a locally restored seed after binding it to the authenticated
manifest's canonical fingerprint (exact file set and block geometry) and failing closed on
any violation, never clamping an out-of-range claim; the sender likewise rejects any
`resume_state` that does not match its own manifest (unknown, duplicate, or missing file
entries, out-of-range `haveBlocks`, a fingerprint mismatch, or a conflicting duplicate), so a
malicious or stale peer cannot steer a resumed transfer into writing the wrong bytes or
skipping unverified data.

### Code leakage

Anyone who obtains the full invite code can join until the first peer pairs or the room is
reaped. Mitigations: strictly 1:1 pairing (a second `join` on a live room is refused with
`room_full`), rooms reaped after the signaling idle timeout (default 10 minutes), and — in
the browser — a fragment-only code kept out of `Referer` and server logs via
`Referrer-Policy: no-referrer` and fragment semantics. Because the code is a low-entropy
human string, its security rests on the online, single-attempt nature of SPAKE2 (the server
cannot brute-force it offline) combined with 1:1 pairing and the short room lifetime, not
on the code's length.

### Denial of service

Per-session relay queue, bandwidth, frame-size, and lifetime-bytes caps
(`SENDBEAM_RELAY_*`, see `HOSTING.md`); message-size and per-connection message-rate caps;
per-IP connection-rate limits; and a room reaper on the idle timeout. A WSS origin
allowlist on the signaling upgrade (`SENDBEAM_ALLOWED_ORIGINS`) blocks cross-site socket
abuse. All limits are operator-tunable and the defaults keep memory in the low tens of MiB.

### Malicious sender (receiver-side safety)

Filenames are sanitized on receipt to prevent directory traversal; a per-transfer
file-count cap, quota checks, and the in-flight block bound (`DEFAULT_INFLIGHT_BLOCKS = 8`)
prevent resource exhaustion; the receiver confirms before writing outside OPFS; per-block
and whole-file digests are verified before completion is reported.

### Web-facing hardening

The HTTP surface sets a strict CSP (`default-src 'self'`, `connect-src 'self' wss: https:`,
`script-src 'self' 'wasm-unsafe-eval'`, `object-src 'none'`, `base-uri 'none'`,
`frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and
`Referrer-Policy: no-referrer`. The server logs room numbers and metadata only — never the
invite words, filenames, plaintext, or keys.

## What the server can and cannot see

- **Cannot see:** the invite words, file bytes, filenames, digests, session keys.
- **Can see:** the room number, socket metadata, SDP/ICE needed to route, and — on the
  relay path only — ciphertext byte counts and timing.

## Accepted limitations (v1)

- **File sizes and timing are observable.** There is no traffic padding in v1.
- **Whoever holds the code can impersonate a peer** until first-pair or room reaping. The
  human fingerprint check does not close this — a code holder can complete the handshake
  and produce the matching fingerprint — so the real mitigations are careful code
  distribution, single-use pairing, and the short room lifetime.
- **Endpoint compromise is out of scope.** A compromised browser, extension, or OS can read
  plaintext before or after transfer; no wire protocol can prevent that.
- **The relay has no metadata defense.** A server observing the relay path can correlate
  the two sockets in a room (both directions cross the same server). It still cannot read
  anything.

## Verification

Negative crypto tests are part of the suite: a wrong invite code fails closed; a tampered
`pake` element aborts; a tampered or replayed SDP MAC is rejected; a reused GCM nonce is
rejected; a bad block hash aborts without retry; two sessions sharing the same code derive
different master keys (ephemeral SPAKE2 freshness); a forged `resume_state` is rejected (bad
transfer id, mismatched or malformed manifest fingerprint, unknown/duplicate/missing file
entries, or out-of-range `haveBlocks` all fail closed on both the sender and receiver).
Cross-language vector tests keep the TypeScript and Go implementations byte-identical, and
the test-vector suite (KATs + a full transfer vector) is published under
`docs/test-vectors/` for independent reimplementation. Before public release the crypto
and server are security-reviewed and the JS/Go dependencies audited.

## Remote Presence & Blinded Discovery Metadata Boundaries (v1.5)

- **Opaque Rendezvous Handles:** Pairwise handles are derived via `HMAC-SHA256(k_pair, "sendbeam/2 rendezvous-handle:" || epoch)` rotating every 15 minutes. The signaling server sees connection attempts for a random-looking 32-byte hex string, but cannot link distinct handles across epochs, determine the underlying device identities, or associate them with account records.
- **Blinded LAN Beacons:** UDP broadcast/multicast beacons contain only ephemeral random nonces, port numbers, and truncated 16-byte HMAC tags (`HMAC(k_pair, nonce || epoch)`). Passive network observers on the local Wi-Fi see pseudorandom beacons without plaintext device names, fingerprints, or transfer metadata.
