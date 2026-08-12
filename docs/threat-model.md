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

### Replay / reordering / tampering

AES-256-GCM with a per-direction monotonic nonce counter; the frame header is the GCM AAD,
binding each frame to its position (file, block, offset, length). A reused counter is
refused rather than risk nonce reuse. Any tampering fails the GCM auth tag; a bad per-block
SHA-256 escalates to abort (no blind retry). Resume state is integrity-checked: a
`resume_state` that does not match the authenticated manifest is rejected.

### Code leakage

Anyone who obtains the full invite code can join until the first peer pairs or the room is
reaped. Mitigations: strictly 1:1 pairing (a second `join` on a live room is refused with
`room_full`), rooms reaped after the signaling idle timeout (default 2 minutes), and — in
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
different master keys (ephemeral SPAKE2 freshness); a forged `resume_state` is rejected.
Cross-language vector tests keep the TypeScript and Go implementations byte-identical, and
the test-vector suite (KATs + a full transfer vector) is published under
`docs/test-vectors/` for independent reimplementation. Before public release the crypto
and server are security-reviewed and the JS/Go dependencies audited.
