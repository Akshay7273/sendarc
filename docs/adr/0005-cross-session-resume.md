# ADR 0005 — Cross-session authenticated resume protocol

Status: accepted (design), implementation gated
Scope: v1.3 (durable transfers) — V13-PR07
Applies to: `packages/wire/resumeauth.go` (Go), `packages/protocol/src/resume-auth.ts`
(TypeScript), the durable journal (`journal.go`/`journal.ts`), the CLI sender/receiver
seams (`apps/cli`), and the browser sender/receiver seams (`apps/web`)

## Context

V13-PR01–PR06 make a transfer durable **within a session**: the receiver journals verified
blocks and a reloaded peer re-attaches through a fresh rendezvous whose SPAKE2 proof is
still backed by a live invite code. When the **original process/session is gone**, the
invite code, the SPAKE2 ephemeral state, the session master, the directional transfer keys,
and the AEAD salts/counters are all lost or must not be reused. A cross-session resume must
let the **same original sender and receiver** authenticate a resumed transfer without any
of that material, and must never silently downgrade into an unauthenticated resume.

This ADR defines the cryptographic protocol that fills the `resumeSecret` envelope PR01
reserved in the journal schema (ADR 0004 §5) and the sender-record secret field this PR
introduces. PR08 owns the product integration (peer discovery, Interrupted Transfers UX,
restart crash campaign); this ADR defines the exact protocol PR08 will drive, and the
byte-identical Go + TypeScript semantics both implementations must share.

## 1. Threat model and requirements

Same trust boundary as ADR 0004 §3 plus the cross-session case:

- The rendezvous server and any network observer may record, drop, replay, duplicate,
  reorder, or modify every resume-auth message, and may start its own fake peer. The server
  never learns the original session master, the resume root, or the resume secret.
- Possession of the **resume secret** proves the holder is the original peer for **that
  transfer only** (transfer-scoped credential). A holder can authenticate a resume of that
  transfer; it cannot recover the master, forge other transfers, or authenticate a changed
  source.
- The threat model does **not** include local OS/browser compromise of the persisted
  credential (v1.4 owns platform security integration).

Required properties (V13-PR07):

1. Resume secret derived from the **original authenticated session master**.
2. Secret cryptographically bound to `transferId` + canonical manifest fingerprint.
3. Only the minimum transfer-scoped credential is persisted; never the master, directional
   keys, salts, counters, invite code, SPAKE2 ephemera, or confirmation keys.
4. Fresh challenge nonces on every attempt; mutual proof of possession; replay and
   reflection resistance; the server/network cannot forge authentication.
5. Every resumed session gets completely fresh directional traffic keys; old AEAD
   keys/salts/counters are never restored or reused.
6. Safe behavior with old peers and with either side having lost its secret; no silent
   downgrade into unauthenticated cross-session resume.
7. Go + TypeScript semantics and test vectors are byte-identical.

## 2. Capability decision: `sendbeam/1` + `resume-auth-v1`

**Decision: `sendbeam/1` with an additive, capability-gated extension — NOT `sendbeam/2`.**

Proof that `sendbeam/1` stays safe:

- Ordinary transfers are byte-for-byte unchanged. The resume-auth messages are new message
  shapes; a legacy peer that never advertises `resume-auth-v1` never receives them.
- The resume-auth protocol runs **only after** both peers agree on the capability in a
  session whose own key confirmation already authenticates the caps exchange. Stripping the
  capability therefore cannot cause a downgrade: absence of the capability means
  cross-session resume is **unavailable** (fresh transfer or explicit restart), never an
  unauthenticated resume.
- The resume secret lives in **local** state (journal / sender record), which carries no
  wire-version implication (ADR 0004 §3).

Capability name: **`resume-auth-v1`** (Go `ResumeAuthCapability`, TS
`RESUME_AUTH_CAPABILITY`). It is defined, documented, and negotiation-tested in this PR but
**not advertised in production defaults**: `DefaultCaps()` does not include it, and the web
sender/receiver never enable automatic cross-session resume. PR08 / lead approval turns the
product flow on.

## 3. Secret derivation

All derivations are HKDF-SHA256 (RFC 5869) with the domain strings below; all multi-byte
integers are big-endian; transferId is decoded from validated 32 lowercase hex chars to 16
bytes; the manifest fingerprint from validated 64 lowercase hex chars to 32 bytes. Inputs
that fail validation are rejected before any derivation (no partial bytes).

Domain strings (ASCII, no trailing NUL):

| Constant                    | Value                             |
| --------------------------- | --------------------------------- |
| `INFO_RESUME_ROOT`          | `sendbeam/1 resume root`          |
| `INFO_RESUME_SECRET`        | `sendbeam/1 resume secret`        |
| `INFO_RESUME_PROOF_OFFERER` | `sendbeam/1 resume offerer proof` |
| `INFO_RESUME_PROOF_JOINER`  | `sendbeam/1 resume joiner proof`  |
| `INFO_RESUME_MASTER`        | `sendbeam/1 resume master`        |

```
resumeRoot   = HKDF-SHA256(ikm = originalMaster, salt = nil,
                           info = "sendbeam/1 resume root", outLen = 32)

secretInfo   = "sendbeam/1 resume secret" || u32be(1) || transferId(16) || manifestFingerprint(32)
resumeSecret = HKDF-SHA256(ikm = resumeRoot, salt = nil, info = secretInfo, outLen = 32)
```

- `resumeRoot` is a **transient, narrowly-scoped** intermediate: derived in the main thread
  (browser) or driver (CLI) from the master, passed to the worker only when the manifest
  fingerprint is needed to finish the derivation. It is never persisted, never logged,
  never returned to the UI. The master cannot be recovered from it (HKDF one-wayness).
- `resumeSecret` is the persisted 256-bit transfer-scoped credential. Its derivation binds
  the resume protocol version (`u32be(1)`), the transfer id, and the manifest fingerprint
  with explicit fixed-width binary fields — no string concatenation, no ambiguous
  delimiters.
- There is deliberately **no reuse** of the directional traffic keys, no ad-hoc
  `SHA256(master || strings)`, no invite-code persistence, and no SPAKE2 ephemeral state.

## 4. Persisted material

Persist **only** the opaque versioned 256-bit credential:

```json
{ "version": 1, "value": "<64 lowercase hex chars>" }
```

Encoding: lowercase hex of the 32-byte secret (`version 1`). The journal and sender-record
decoders require the **exact** 64-hex length for version 1; anything else (other length,
wrong version, non-hex, empty, oversized) fails closed. An old opaque value is never
reinterpreted as a valid key.

Never persist: original SPAKE2 password/invite words, full invite code, original master,
SPAKE2 ephemeral scalar, confirmation keys, original directional AES keys, original nonce
salts, original send/receive AEAD counters, handshake transcripts, fresh-resume traffic
keys, resume challenge nonces, or resume proofs.

Lifecycle: the credential exists only while the transfer can legitimately be resumed. It
disappears when the sender record is removed after verified success, when the receiver
journal is removed after verified success, when the user explicitly discards the transfer,
or when journal/sender-state expiry/GC deletes the record. Failed/incomplete resume attempts
do **not** consume the long-lived secret; a later attempt uses fresh nonces and derives
fresh traffic keys. There is no server-side copy.

## 5. When the secret becomes persistable

The secret cannot be derived until the canonical manifest fingerprint is known.

- **Sender:** `OnManifest` (PR04 seam) runs with the validated manifest strictly before its
  frame is transmitted. Ordering: build + validate manifest → canonical fingerprint →
  derive transfer-scoped `resumeSecret` from the resume root → durably persist the sender
  record containing it → **only then** transmit the manifest.
- **Receiver:** after decrypting + validating the authenticated manifest: canonical
  fingerprint → derive the matching secret → persist into the durable receive journal →
  only then may that secret authorize a future cross-session resume. Persistence happens at
  manifest time, not as a best-effort afterthought several blocks in.

**Never re-derive on a resumed session:** a restarted transfer performs a fresh rendezvous
with a fresh master. The secret must stay bound to the **original** session, so a restart
keeps the already-persisted secret and never overwrites it with one derived from the new
master.

## 6. Resume-auth handshake (mutual authentication)

A small transport-agnostic state machine. PR08 owns peer discovery/reconnection; the engine
operates over an **abstract message transport** (`Send(msg)` / `Handle(msg)`) plus local
resume context, and does not trust the server. Both sides already know locally:
`transferId`, `manifestFingerprint`, their stable role (offerer = sender, joiner =
receiver), and the `resumeSecret`. The transferId and fingerprint are **not** transmitted;
they enter only through the transcript (no plaintext discovery leak — matching is PR08).

### 6.1 Messages

JSON, canonical field order, `base64url` (no padding) for binary fields. All decoders are
strict and bounded: exact version, exact role per message type, nonce exactly 32 bytes,
proof exactly 32 bytes, no unknown fields, no trailing data, no attacker-controlled
allocations.

| Step | Direction        | Type               | Fields                                                         |
| ---- | ---------------- | ------------------ | -------------------------------------------------------------- |
| 1    | offerer → joiner | `resume_init`      | `version: 1`, `role: "offerer"`, `nonce` (32 B)                |
| 2    | joiner → offerer | `resume_challenge` | `version: 1`, `role: "joiner"`, `nonce` (32 B), `proof` (32 B) |
| 3    | offerer → joiner | `resume_confirm`   | `version: 1`, `role: "offerer"`, `proof` (32 B)                |
| 4    | joiner → offerer | `resume_ready`     | `version: 1`, `role: "joiner"`, `proof` (32 B)                 |

The fourth message exists because the offerer is the data producer: it must not begin
streaming resumed data until it knows the joiner processed and authenticated the
confirmation. A 3-message protocol would leave a half-established state where the sender
could start under new traffic keys while the receiver has not authenticated the peer.

### 6.2 Fresh nonces

Both peers contribute fresh 256-bit (`crypto/rand` in Go, `crypto.getRandomValues` in TS)
nonces on **every** attempt; a crashed mid-handshake attempt abandons its nonces and a new
attempt generates new ones. Nonces are never persisted, never timestamps, never old
counters, never the transferId. Tests inject a deterministic `NonceSource`.

### 6.3 Canonical transcript

```
transcript = "sendbeam/1 resume-auth" || u32be(1) || transferId(16) || manifestFingerprint(32)
             || offererNonce(32) || joinerNonce(32)
```

Fixed-width binary fields; the same bytes on both sides and in both languages. Role binding
comes from (a) the fixed offerer/joiner nonce positions, (b) role-separated proof subkeys
(§6.4), and (c) per-message proof tags.

### 6.4 Proof construction

Subkeys derived from the resume secret with explicit domain separation:

```
K_offererProof = HKDF-SHA256(resumeSecret, nil, "sendbeam/1 resume offerer proof", 32)
K_joinerProof  = HKDF-SHA256(resumeSecret, nil, "sendbeam/1 resume joiner proof", 32)
```

Proofs (HMAC-SHA256 over the complete transcript plus a fixed per-message tag byte):

```
joinerProof  = HMAC-SHA256(K_joinerProof,  transcript || 0x01)   // resume_challenge
offererProof = HMAC-SHA256(K_offererProof, transcript || 0x02)   // resume_confirm
readyProof   = HMAC-SHA256(K_joinerProof,  transcript || 0x03)   // resume_ready
```

Both peers compute the offerer and joiner proofs over the **same** transcript. The joiner
proves possession by step 2; the offerer proves possession by step 3; step 4 confirms to
the offerer that the joiner processed the confirmation. Verification uses constant-time
comparison (`hmac.Equal` in Go; the reviewed constant-time helper in TS).

### 6.5 State machine

```
offerer:  idle ──Start──► awaitChallenge ──valid challenge──► awaitReady ──valid ready──► done
                             │ (verify joiner proof)             │ (verify ready proof)
                             │ emit resume_confirm               │ result: fresh keys
joiner:   idle ──valid init──► awaitConfirm ──valid confirm──► done
             │ (verify version/role)  │ (verify offerer proof)
             │ emit resume_challenge  │ emit resume_ready; result: fresh keys
```

- Any message out of state, conflicting duplicate, version/role/nonce/proof mismatch fails
  closed (typed error; see §8).
- **Idempotency:** an exact duplicate of the message that advanced the current state is
  re-answered with the **same** previously-generated snapshot (nonce/proof) — e.g. a
  retransmitted `resume_init` is re-answered with the identical `resume_challenge`, a
  retransmitted `resume_challenge` with the identical `resume_confirm`, a retransmitted
  `resume_confirm` with the identical `resume_ready`. No fresh nonce is generated for a
  retry. A different message in the same position is a conflicting duplicate and fails
  closed. No challenge replacement after a proof, no nonce/proof/role/version mutation.

## 7. Fresh resumed traffic keys

After **mutual** authentication succeeds, both sides derive:

```
resumeMaster = HKDF-SHA256(resumeSecret, nil, "sendbeam/1 resume master" || transcript, 32)
resumedKeys  = DeriveTransferKeys(resumeMaster)   // existing "sendbeam/1 o2j" / "sendbeam/1 j2o"
```

The resulting offerer→joiner key + salt and joiner→offerer key + salt differ from the
original session keys, from every prior resume attempt (fresh nonces → fresh transcript),
and from each other. Counters for the new key set start at the fresh-session initial value
(`0`) **only because the keys and nonce salts are themselves new** — the protocol continues
to forbid combining an old key with a counter reset and forbids restoring old counters from
disk.

**Key exposure timing:** resumed traffic keys are not exposed to caller code until mutual
authentication completes. Before that, there is no resumed manifest, no resume_state, no
block data, and no user plaintext under the prospective keys. The handshake result is
all-or-nothing; failure abandons the candidate key material for that attempt.

## 8. Failure classes and error hygiene

High-level classes (stable machine-readable codes; ADR 0002):

| Class                      | Code       | Meaning                              |
| -------------------------- | ---------- | ------------------------------------ |
| unsupported resume auth    | `COMPAT`   | version/capability mismatch          |
| missing local credential   | `STORAGE`  | local secret absent                  |
| authentication failed      | `AUTH`     | proof/transcript/role/nonce mismatch |
| malformed protocol message | `PROTOCOL` | strict decode violation              |
| storage failure            | `STORAGE`  | persist/load failure                 |

Errors never expose the expected/actual proof, the secret, key material, or the original
master. Tests log secrets only inside fixed published KAT vectors.

## 9. Lost secret / old peer / downgrade behavior

- Peer lacks `resume-auth-v1`, either side lost its secret, proof fails, versions differ,
  or transcript differs ⇒ cross-session resume is **unavailable**. Safe fallback is a fresh
  transfer or an explicit restart — never reusing a stable transferId to trust old
  `resume_state` progress. Same-session PR06 behavior inside a still-authenticated session
  is unchanged.
- Capability negotiation is authenticated by the session's own key confirmation and the
  capability is included in the decision; a malicious server stripping `resume-auth-v1`
  yields "no capability" ⇒ unavailable, never an unauthenticated resume.
- No secret is fabricated from public values (transferId, fingerprint, file digests, sender
  paths, journal checksums).
- Old sender records (pre-PR07) and old journals (no secret) remain structurally valid and
  usable for their existing capabilities; they simply cannot authenticate a cross-session
  resume. Existing partials are never silently deleted.

## 10. Revalidation still applies

Resume authentication proves **who** is resuming. It does not replace:

- **PR04 source reattachment:** on sender restart, reopen/reselect the source, recompute the
  canonical identity, and compare with the stored fingerprint before authenticating; a valid
  secret never authorizes a changed source.
- **PR06 journal/resume-state validation:** after authentication, the journal must still
  match transferId + fingerprint, coverage must be exact, committed blocks durably backed,
  and whole-file verification mandatory.
- **PR05 digest checkpoints** remain a performance optimization only; the secret never
  encrypts them, never authorizes a lying checkpoint, and never bypasses validation.

## 11. Local storage security

The resume secret is a transfer-scoped credential: possession permits impersonating the
original peer for that transfer's resume authentication until the record
expires/completes/discards.

- **CLI:** sender records remain mode 0600; journals carry the secret at mode 0600; state
  directories stay 0700.
- **Browser:** IndexedDB/OPFS are origin-scoped local state — no hardware/keychain claim.
  The secret is never placed in localStorage, never in URL/query/hash, never exposed to the
  DOM/UI, never sent to diagnostics.
- The secret is never printed in the transfers list, logs, errors, or diagnostics; tests
  print only fixed public KAT vectors.
- No desktop/keychain work in this PR (v1.4 owns platform security integration).

## 12. Exact boundary with PR08

PR07 (this PR) delivers: the design, the crypto + state machine in Go and TS, the shared
vectors, the persisted-credential seams (sender records + receiver journals), the
capability constant + negotiation tests, and the fail-closed compatibility behavior.
Automatic product use is **not enabled**.

PR08 owns: peer discovery/reconnection, Interrupted Transfers UX, the final CLI resume
command workflow, full browser resume orchestration, the 100+ GiB restart/crash campaign,
production notification flow, and account/device pairing. PR07 adds only the minimum host
seams needed to derive/persist the credential during the original session and to exercise
the protocol in isolated/integration tests.

## Consequences

- New resume-auth code must reproduce the exact derivation formulas, transcript bytes, and
  proofs of this ADR; the committed vectors in `docs/test-vectors/resume-auth.json` pin
  them byte-for-byte across Go and TS.
- Journal/sender-record decoders accept only the exact version-1 64-hex credential; older
  records without one stay valid but cannot authenticate cross-session resume.
- No old traffic key may ever be paired with a counter reset; resumed sessions always use
  fresh keys derived from mutually authenticated resume secrets.
- `resume-auth-v1` is a defined capability, not an advertised default; enabling the product
  flow is PR08 / lead approval.
