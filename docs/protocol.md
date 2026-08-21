# Wire protocol

**Protocol version: `sendbeam/1`.**

This is the normative reference for what goes over the wire between two SendBeam peers and
between a peer and the server. It is the source both client implementations follow: the
browser via `packages/protocol` (TypeScript) and the CLI via `packages/wire` (Go). The two
are kept in sync by a cross-language vector test; where a value appears below it is defined
once in `packages/protocol/src/constants.ts` and mirrored in Go.

Any change to a wire value or layout is a protocol change: bump the version and negotiate it
in `caps`. Per-version compatibility is what lets one peer run `sendbeam/1` and another a
future version; the caps round-trip settles the common subset.

## Roles

The peer that allocates the room is the **offerer**; the peer that joins is the **joiner**.
Roles are fixed for the lifetime of a session and select the directional keys and the SPAKE2
message elements.

## Signaling

Signaling is JSON messages over a single WebSocket to the server. The server is a blind
pairer and forwarder: it allocates a room number, links the two sockets that share it, and
forwards the peer messages below between them **without inspecting their bodies** — it
parses only `type`, `room`, and `role` from inbound messages, and never decodes handshake or
transfer payloads. It never receives the invite words or any derived key.

| Message          | Direction        | Fields               | Purpose                                          |
| ---------------- | ---------------- | -------------------- | ------------------------------------------------ |
| `create`         | offerer → server | —                    | Ask for a room.                                  |
| `created`        | server → offerer | `room`               | Room allocated (smallest free number).           |
| `join`           | joiner → server  | `room`               | Pair with an existing room.                      |
| `peer-joined`    | server → both    | `role`               | The two sockets are paired; carries your role.   |
| `pake`           | peer → peer      | `msg`                | A SPAKE2 message element (base64url SEC1).       |
| `confirm`        | peer → peer      | `mac`                | RFC 9382 key-confirmation MAC (base64url).       |
| `caps`           | peer → peer      | `frame`              | First AES-GCM frame: the sealed capabilities.    |
| `sdp`            | peer → peer      | `sdp`, `seq`, `mac`  | SDP offer/answer, session-authenticated.         |
| `ice`            | peer → peer      | `cand`, `seq`, `mac` | ICE candidate, authenticated like `sdp`.         |
| `relay_open`     | peer → server    | `role`               | Request the encrypted relay for this session.    |
| `relay_required` | server → peer    | —                    | Direct path impossible; relay is mandatory.      |
| `relay_ready`    | server → peer    | —                    | Relay slot assigned; frames are now relayed.     |
| `relay_credit`   | peer → peer      | `bytes`              | Credit grant, letting the peer send more frames. |
| `credit`         | peer → peer      | `bytes`              | Peer-to-peer credit for the direct channel.      |
| `resume`         | peer → server    | `room`, `role`       | Re-attach to a live room on reconnect.           |
| `resumed`        | server → peer    | `role`               | Re-attached; session continues.                  |
| `peer_left`      | server → peer    | —                    | The paired socket disconnected.                  |
| `peer_rejoined`  | server → peer    | —                    | The paired peer re-attached.                     |
| `bye`            | any → any        | `reason`             | Graceful teardown.                               |
| `error`          | server → peer    | `code`, `msg`        | Protocol or limit error.                         |

`pake`, `confirm`, `caps`, `sdp`, and `ice` are the only forwardable peer payloads; the rest
of the relay/credit traffic is server-mediated or opaque.

Error codes are a closed set:

`bad_message`, `unknown_room`, `room_full`, `not_paired`, `rate_limited`, `protocol`,
`relay_not_ready`, `relay_credit`, `relay_limit`.

Pairing is strictly 1:1: a second `join` on a live room is refused (`room_full`). Rooms are
reaped after the signaling idle timeout (default 10 minutes; `SENDBEAM_SIGNAL_IDLE_TIMEOUT`)
with no traffic. If a socket drops and reconnects within that window, `resume` re-attaches
it to the same slot (routing only — it still must pass the SPAKE2 handshake), so a stray
reconnect cannot hijack a session; the paired peer sees `peer_left`/`peer_rejoined`.

### Connection recovery

Once the data channel is open (transfer already running), both CLI and browser treat a
WebRTC ICE `disconnected` as a **transient** condition first, with a bounded observation
window (default 6 s) rather than failing the path outright:

1. Entering `disconnected` on an established direct path reports a distinct `recovering`
   transport state and, on the offerer, issues an **ICE restart** (`CreateOffer` with
   `ICERestart: true` / `pc.restartIce()`), renegotiating the SDP over signaling. The
   existing data channel and its committed transfer progress are untouched.
2. If the path returns to `connected`/`completed` before the window elapses, recovery clears
   and the direct path keeps transferring.
3. If the window elapses or the restart fails, the direct path is declared unrecoverable and
   the transfer falls back to the encrypted relay (`resume` re-attaches the signaling socket
   if it dropped, so the relay handshake and later SDP/ICE frames can still flow). Transfer
   progress and AEAD counters are preserved across the cutover.

The signaling socket itself is independently resumable: a post-establishment drop on an open
room is re-dialed and re-attached with `resume` (bounded retries), so ICE-restart
renegotiation can still exchange SDP/ICE even if signaling dropped earlier.

### Direct path and optional TURN

The "direct" path is an authenticated WebRTC DataChannel. When the operator publishes TURN
servers (see `HOSTING.md`), the ICE agent may also gather a **TURN relayed candidate**; such a
candidate is still a _direct-path_ candidate, raced against host/srflx/prflx candidates and
handled by the supervisor as the same path — never as the encrypted-relay fallback. When no
TURN is configured, behavior is unchanged from direct-only. Application-layer AES-GCM frames
are identical on every candidate, so TURN never weakens the protocol (see
`docs/adr/0003-path-selection.md`).

### Diagnostics

Both clients can emit a **sanitized** snapshot of path/ICE/timing/failure state for
troubleshooting (`sendbeam diagnose`; the web failure screen's "Copy diagnostics"). The
snapshot intentionally excludes invite codes, full IP addresses, filenames, SDP, credentials,
and payload metadata — it reports only candidate _types_ ("host"/"srflx"/"prflx"/"relay"),
transport, timing, and error classes (see `docs/adr/0002-error-taxonomy.md`).

### Flow

```
offerer                         server                          joiner
   │  create                 ─────▶│                               │
   │◀── created{room}              │                               │
   │                               │◀───────────────  join{room}  ─│
   │◀── peer-joined{offerer} ──────┼──── peer-joined{joiner} ─────▶│
   │  pake                    ◀────┼────▶  pake                     │   SPAKE2 (RFC 9382)
   │  confirm                 ◀────┼────▶  confirm                  │   key confirmation
   │  caps                    ◀────┼────▶  caps                     │   sealed capabilities
   │  sdp / ice (session-MAC'd) ◀──┼──▶ sdp / ice                   │   negotiate WebRTC
   │═══════ WebRTC DataChannel (direct), or encrypted WS relay ════│   transfer frames
```

## Invite code

The invite code is the room number and a client-generated word list joined by `-`, e.g.
`4-brave-otter`. The room number is server-visible (it routes the sockets); the words are
generated and verified only on the clients. Defaults: `DEFAULT_WORD_COUNT = 2` words drawn
from a `WORDLIST_SIZE = 256` list (one byte of entropy each), separated by `CODE_SEPARATOR`
(`-`). The sender can raise the word count.

The **full normalized code string is the SPAKE2 password**. Because the words never leave
the client, the server cannot run the handshake or a dictionary attack against it. In the
browser the code lives in the URL fragment so it is never transmitted; the CLI takes it as an
argument.

## Authenticated handshake

1. **SPAKE2 (RFC 9382, group P-256).** The invite code is mapped to the scalar `w` by
   `w = HKDF(code, salt=nil, info="sendbeam/1 spake2 w", L=48) mod n` — 48 bytes of HKDF
   output reduced into the 256-bit scalar field, leaving negligible modular bias
   (`SPAKE2_W_HKDF_BYTES = 48`). The offerer sends `T = X + w·M`, the joiner sends
   `S = Y + w·N`, each as a base64url raw SEC1 point in a `pake` message.
2. **Key confirmation.** Both sides derive the RFC 9382 transcript and confirmation keys
   `KcA || KcB = HKDF(Ka, nil, "ConfirmationKeys", 32)` — this label is fixed by the RFC
   and must not change — then exchange confirmation MACs in `confirm` (offerer `cA`, joiner
   `cB`). A mismatch aborts the handshake **closed**; there is no fallback.
3. **Master key.** The RFC's shared secret `Ke` is expanded into the SendBeam master key,
   bound to the handshake transcript: `master = HKDF(Ke, "sendbeam/1 master" || TT)`, where
   `TT` is the RFC 9382 transcript. Every downstream key is therefore transcript-bound.

### Short authentication string

Both peers derive the same human-comparable fingerprint from the master key:

```
fp = SHA-256("sendbeam/sas\0" || master)[0:4]      shown as two hex groups, e.g. "7948 2d83"
```

The domain-separated hash means no raw key bytes are exposed. The two humans read it to each
other as an out-of-band check layered on top of SPAKE2. Canonical vector:
`master = 0x00 0x01 … 0x1f` → `7948 2d83`.

### Key schedule

All keys derive from the master key by HKDF-SHA256 with these `info` labels:

| Label                      | Output                                  |
| -------------------------- | --------------------------------------- |
| `sendbeam/1 master` (+ TT) | Master key, from the RFC 9382 `Ke`.     |
| `sendbeam/1 o2j`           | Directional AEAD key, offerer → joiner. |
| `sendbeam/1 j2o`           | Directional AEAD key, joiner → offerer. |

Each directional key carries its own 4-byte nonce salt; the AEAD nonce is
`salt[4] || counter_be[8]` (see below), so the two directions can never collide on a
nonce even though both start counters at zero.

## Frames

After the handshake, all peer-to-peer payloads are AES-256-GCM frames. The first frame in
each direction is the sealed `caps`; from then on the same frame layer carries the transfer.

### Header

A fixed 16-byte, big-endian header prefixes every frame and is used **verbatim as the
AES-GCM associated data (AAD)**, so it is authenticated but not encrypted, and encode/decode
must be byte-exact (`FRAME_HEADER_BYTES = 16`, `FRAME_VERSION = 1`).

| Offset | Size | Field      | Notes                                           |
| ------ | ---- | ---------- | ----------------------------------------------- |
| 0      | u8   | `version`  | Header layout version (`1`).                    |
| 1      | u8   | `type`     | Frame type (see below).                         |
| 2      | u8   | `flags`    | Reserved for per-frame flags.                   |
| 3      | u8   | reserved   | Zero.                                           |
| 4      | u16  | `fileIdx`  | File index within the transfer.                 |
| 6      | u32  | `blockIdx` | Block index within the file.                    |
| 10     | u16  | `frameOff` | Byte offset of this frame **within the block**. |
| 12     | u16  | `len`      | Ciphertext payload length.                      |
| 14     | u16  | reserved   | Zero; keeps the header a fixed 16 bytes.        |

The field widths imply the structural caps: up to `0xffff + 1` files per transfer and
`0xffffffff + 1` blocks per file (`MAX_FILES_PER_TRANSFER`, `MAX_BLOCKS_PER_FILE`).

### Frame types

`Caps=1`, `Manifest=2`, `BlockData=3`, `BlockHash=4`, `BlockRecv=5`, `Ack=6`, `Nack=7`,
`Control=8`, `Complete=9`, `Done=10`, `Fail=11`, `ResumeState=12`. The transfer control
types (`Manifest` … `ResumeState`) travel as JSON inside the plaintext payload (codec in
`packages/protocol/src/transfer-messages.ts`, mirrored by `packages/wire/transfer_*.go`);
`BlockData` payloads are raw file bytes.

### AEAD

AES-256-GCM with a 32-byte key, 12-byte nonce, and 16-byte tag (`AEAD_KEY_BYTES = 32`,
`AEAD_NONCE_BYTES = 12`, `AEAD_TAG_BYTES = 16`). The nonce is a 4-byte per-direction salt
followed by a big-endian u64 counter (`AEAD_SALT_BYTES = 4`):

```
nonce = salt[4] || counter_be[8]
```

The counter is monotonic per direction. A reused counter is refused rather than risk nonce
reuse, and any tampering — of the ciphertext or of the header used as AAD — fails the GCM
tag and aborts.

## Capabilities

The `caps` frame is the first thing sent after key confirmation and negotiates the transfer
parameters (`CapsPayload`):

```
version    protocol version string ("sendbeam/1")
maxFrame   maximum frame payload the sender will use (default 16 KiB, max 64 KiB)
blockSize  logical block size — the unit of ack/retry/resume (default 1 MiB)
features   negotiated features: folders | resume | relay | archive
sinkHints  receiver sink availability: direct-file | opfs | archive
```

A successful `caps` exchange completes the handshake: two peers are mutually authenticated
over a fresh AEAD channel, and each side takes its peer's `maxFrame`/`blockSize` from the
remote caps. (The caps exchange consumed counter 0 in each direction.)

## Transfer

After caps, the sender drives the transfer as a sequence of frames over whichever channel
the session settled on — the WebRTC DataChannel when the ICE path succeeded, otherwise the
server-mediated encrypted relay (the `relay_open`/`relay_ready`/`relay_credit` exchange
above; relayed payloads are the same AEAD frames, never re-encrypted or inspected).

1. **Manifest.** The sender sends a `Manifest` (optionally carrying a `transferId` that opts
   the transfer into resumption). Each `FileEntry` carries `idx`, `name`, `size`, `mime`,
   `lastModified`, `blockSize`, `blocks`, and the SHA-256 `fileDigest`. The receiver selects
   its sink only after seeing the authenticated manifest.
2. **Blocks.** The sender chunks each file into `blockSize` blocks, then into `maxFrame`
   frames. Every block is confirmed before the window moves on: the receiver sends `BlockRecv`
   for a complete block, or `Nack` to request retransmission; the sender's in-flight bound is
   `DEFAULT_INFLIGHT_BLOCKS = 8`, which caps receiver RAM regardless of sink speed. Per-block
   and whole-file SHA-256 digests are exchanged (`BlockHash`, manifest `fileDigest`) and
   verified on receipt.
3. **Control.** `Control` carries transport-level operations (e.g. pause/resume); `Complete`
   is sent after the last block, `Done` is the receiving side's digest-verified confirmation,
   and `Fail` aborts with a typed error code.
4. **Resume.** In resume mode the receiver sends a `ResumeState` first — one per-file entry
   of the committed high-water mark — and the sender restarts each file from that offset,
   ignoring any `resume_state` that does not match the manifest. A transfer with no prior
   state reports all-zero marks.

   The `ResumeState` message is **additive** (key order pinned: `type`, `transferId`,
   `manifestFingerprint`, `files`). The optional `manifestFingerprint` field carries the
   canonical fingerprint of the exact manifest the checkpoints belong to (identical algorithm
   to the durable journal's `manifestFingerprint`; see ADR 0004). It is **not** required for
   wire compatibility: a peer that predates the binding answers without the field, and the
   sender accepts that under the structural rules `sendbeam/1` always applied. When the field
   is present it must be 64 lowercase hex and equal the sender's canonical manifest fingerprint,
   otherwise the sender fails the transfer closed.

   Resume state is a **claim, not a trust anchor**. A receiver only applies a locally restored
   seed after it validates the seed against the _authenticated_ manifest: the fingerprint must
   match (binding the exact file set and block geometry), the file coverage must be exact and
   complete, and every `haveBlocks` must lie within `[0, blocks]`. Any violation fails the
   receive closed (`sink_error`) before any of the seed is advertised — a claim is never
   clamped into range. A seed whose `transferId` does not match the manifest belongs to a
   different transfer and is ignored, starting a fresh receive.

   Settlement is idempotent and cutover-safe: an identical duplicate `resume_state` (a path
   cutover can deliver the receiver's answer twice) is a no-op, while a conflicting duplicate
   fails; and when a cutover retransmits the manifest, the receiver re-answers with the exact
   same fingerprint-bound `ResumeState` so the negotiation converges instead of stalling.

Durable resumption across process/session boundaries additionally relies on a **local
durable-transfer journal** — a versioned on-device persistence contract (schema, checksum,
fingerprint, fail-closed loading) defined in `docs/adr/0004-durable-journal.md` and
implemented by the Go `packages/wire/journal.go` and TypeScript
`packages/protocol/src/journal.ts` twins. The journal is **not** wire state: it is never
transmitted between peers, is not part of `sendbeam/1`, and carries no wire-version
implication. The wire `resume_state` message gains only the additive, optional
`manifestFingerprint` field described above; old peers ignore it and new peers validate it.

### Resume authentication (capability `resume-auth-v1`)

Cross-session resume (V13-PR07) — resuming after the original process/session is gone — is
an **additive, capability-gated extension of `sendbeam/1`**, never a `sendbeam/2`. The full
design, derivation formulas, state machine, and security analysis live in
`docs/adr/0005-cross-session-resume.md`; this section summarizes the wire-visible shape.

The capability is named **`resume-auth-v1`** (Go `wire.ResumeAuthCapability`, TS
`RESUME_AUTH_CAPABILITY`). It is a `features` entry announced in caps like any other feature.
PR08 integrates it into the CLI and browser flows: a host advertises it only when its local
integration can really load a valid resume credential, run resume-auth, derive fresh
transfer keys, and enforce the no-downgrade behavior. Ordinary transfers are byte-for-byte
unchanged, and legacy peers that never advertise the capability never receive resume-auth
messages.

The host integration ordering for a cross-session durable resume is: local interrupted
state selected → source/destination revalidated (cheap source pre-check — canonical
identity — before dialing; the exact manifest fingerprint is recomputed and compared with
the record strictly before the manifest frame is transmitted) → fresh signaling/rendezvous
created → peer capability checked → ResumeAuthSession completes mutually → fresh traffic
keys available → transfer sender/receiver constructed under the NEW key epoch →
authenticated Manifest → fingerprint-bound resume_state → sender validates the durable
claim → missing blocks only → whole-file verification. No Manifest/ResumeState/BlockData/
Complete from a resumed transfer is sent or trusted before resume-auth completes, and the
normal transfer protocol never runs under provisional resume-auth keys.

When both peers agree on `resume-auth-v1` and both hold the transfer's local resume
credential, the peers run the resume-auth handshake over the (abstract) transport. Message
shapes (JSON, canonical field order, base64url-no-padding binary fields):

| Step | Direction        | Type               | Fields                                                         |
| ---- | ---------------- | ------------------ | -------------------------------------------------------------- |
| 1    | offerer → joiner | `resume_init`      | `version: 1`, `role: "offerer"`, `nonce` (32 B)                |
| 2    | joiner → offerer | `resume_challenge` | `version: 1`, `role: "joiner"`, `nonce` (32 B), `proof` (32 B) |
| 3    | offerer → joiner | `resume_confirm`   | `version: 1`, `role: "offerer"`, `proof` (32 B)                |
| 4    | joiner → offerer | `resume_ready`     | `version: 1`, `role: "joiner"`, `proof` (32 B)                 |

`transferId` and the manifest fingerprint are never transmitted; both peers hold them
locally and bind them into the authenticated transcript. Proofs are HMAC-SHA256 under
role-separated subkeys derived from the transfer-scoped resume secret, over the canonical
binary transcript (domain string + `u32be` version + transferId bytes + fingerprint bytes +
both 32-byte nonces) plus a per-message tag byte. On mutual success both sides derive a
fresh resume session master (HKDF under `sendbeam/1 resume master` || transcript) and feed
it into the standard directional key derivation, producing completely fresh O2J/J2O keys
and salts whose counters start at the fresh-session initial value. See
`docs/adr/0005-cross-session-resume.md` for the exact formulas and the pinned vectors in
`docs/test-vectors/resume-auth.json`.

Security posture: fresh 256-bit nonces per attempt; replay, reflection, and
capability-stripping cannot downgrade to an unauthenticated resume (absence of the
capability or of a matching credential simply makes cross-session resume unavailable);
old traffic keys/counters are never restored or reused; and the server cannot forge a
resume authentication. Same-session resume (`resume_state` above) is unchanged.

Decoder bounds: one resume-auth message is limited to **1024 bytes** (checked before any
JSON parsing), every nonce/proof must be exactly the canonical 43-char unpadded base64url
of 32 bytes (length checked before any base64 decoding), characters outside the base64url
alphabet and padded or non-canonical spellings are rejected, and there is no implicit
version — `version` must be exactly 1. The capability is included in the resume decision.
PR08 owns the discovery path that obtains authenticated capability state for a
cross-session attempt, and the protocol guarantees the fail-closed side: capability
absent, stripped, or untrusted ⇒ cross-session resume unavailable, never an unauthenticated
resume. Same-session path recovery (direct↔relay cutover) never re-runs resume-auth — the
fresh resumed key epoch is per resumed process/session, and a path change within the same
epoch follows the existing same-session counter/path semantics.

## Trusted Device Mesh & `sendbeam/2` Protocol (v1.5)

SendBeam v1.5 introduces `sendbeam/2` for persistent trusted devices. For complete cryptographic formulas, pairing sequence diagrams, presence handle derivations, and security threat vectors, see [`docs/trust-model.md`](trust-model.md).

### Summary of `sendbeam/2` Wire Messages

1. **Pairing Handshake (`sendbeam/pairing/1`)**:
   - `pairing_request`: initiator sends Ed25519 identity key, device label, and SPAKE2-bound signature.
   - `pairing_response`: responder verifies signature, computes `k_pair`, and responds with its signed public key and confirmation tag.
   - `pairing_confirm`: initiator verifies responder signature and tag, persists pair credential, and returns final confirmation tag.

2. **Trusted Session Authentication (`sendbeam/2`)**:
   - `trusted_auth_init`: Initiator sends `initiator_device_id`, timestamp, 32-byte nonce, ephemeral X25519 public key, and HMAC tag over the domain challenge.
   - `trusted_auth_response`: Responder validates device trust, timestamp freshness (±5 min), verifies tag, generates responder ephemeral key, and returns HMAC response tag.
   - `trusted_auth_confirm`: Initiator verifies responder tag, derives forward-secret `SessionMaster`, `k_i2r`, `k_r2i`, and returns mutual confirmation tag.

3. **Privacy-Preserving Presence & LAN Discovery**:
   - **Remote Presence**: 15-minute epoch-rotated blind handles (`HMAC(k_pair, "sendbeam/2 rendezvous-handle:" || epoch)`).
   - **Blinded LAN Discovery**: UDP Multicast `224.0.0.251:5354` carrying 16-byte blinded beacon tags derived from current epoch subkeys.
