# Durable receive (v1.3 PR02/PR03)

Receivers keep verified progress so a crash, cancellation, or reload does not force a
large transfer to restart from zero. This page documents the storage layout, the
durability ordering, finalization, the management surfaces, and the limits that are
deliberately deferred to later v1.3 PRs. The durability contract itself is defined in
[ADR 0004](adr/0004-durable-journal.md); this page describes the CLI (PR02) and browser
(PR03) implementations of it.

## Browser (v1.3 PR03)

The web receiver is durable by default: the sender mints a `transferId` in the manifest
(the wire protocol already supports it), and the browser receive destination journals
verified progress against that id. Storage is split across the two origin-scoped
backends:

```
OPFS:  sendbeam/durable/<transferId>/<rel>.part   # verified partial data
IDB:   sendbeam-durable → journals, leases         # journal + lock/lease metadata
```

- **OPFS partials** mirror manifest paths under a per-transfer directory and always
  carry the `.part` suffix, so partial data can never be mistaken for a finished file.
  The final deliverable appears only after whole-transfer verification: a single-file
  transfer serves the verified partial itself; multi-file transfers assemble a
  store-only ZIP from the partials (the same ZIP writer as the archive fallback).
- **The journal** lives in IndexedDB (`sendbeam-durable`), never localStorage and never
  an OPFS JSON sidecar pretending to be transactional. Every checkpoint advance is one
  atomic readwrite transaction over the journal plus lease stores, using the same
  schema-v1 `DurableJournal` contract (checksum, fingerprint, block granularity) as the
  CLI — decode fails closed on any deviation.
- **Writer**: where sync access handles are supported (dedicated workers on
  Chromium/Firefox) the transfer worker writes each verified block with a
  `FileSystemSyncAccessHandle`, looping on the returned byte counts until the whole block
  is persisted (short writes are completed, zero-progress or impossible results fail
  closed), then flushes it, then advances the journal checkpoint in the same ordering as
  the CLI (`write → flush → commit → ack`). Browsers without sync
  access handles (Safari) fall back to async `createWritable` streams with an honest
  granularity: the stream can only be flushed at close, so a file's checkpoint advances
  only when its whole stream is closed — never block-by-block.
- **Lock/lease**: an atomic IDB test-and-set lease (`transferId → ownerId, expiresAt`)
  serializes concurrent tabs and survives reloads and worker death. A second tab that
  joins the same transfer fails closed with guidance; a lease that outlives its TTL is
  taken over deterministically (bounded stale recovery). The lease is renewed by every
  checkpoint commit plus a bounded timer, released best-effort on pagehide, released on
  abort and on a failed finalization so a retry acquires immediately (never forcing the
  120s stale TTL), and removed by a successful finalize. A lost/foreign lease makes the
  next checkpoint commit abort — two receivers can never both advance one journal.
- **Keep/Discard**: an interrupted receive deliberately keeps the journal and partials at
  their last durable checkpoint (they are the only resumable copy; never silently
  deleted). The failure screen shows a small "partial data kept" block with an explicit
  **Discard partial data** button; discard is idempotent, removes that transfer's OPFS
  partials first and its journal + lease only after the data is provably gone, and is
  refused while another receiver's live lease owns the transfer (a stale failure page can
  never destroy a live receive).
- **Fail-closed loading**: on reload the receiver revalidates every journal claim against
  the authenticated manifest (checksum, manifest fingerprint, destination identity,
  checkpoint bounds) and cross-checks each partial against its checkpoint — corrupt,
  torn, tampered, foreign, mismatched, missing, or truncated state fails the receive
  closed with guidance and deletes nothing. Quota is preflighted via
  `navigator.storage.estimate()` and write-time exhaustion maps to the `quota` failure.
- **Destinations**: `auto` downloads are reload-durable. The direct-file and
  direct-directory picker modes are capability-gated and are **not** reload-durable:
  their persistence/reopen semantics (a user-selected handle) do not satisfy the
  contract, and the UI never claims otherwise.
- **Resume**: same-session recovery. The sender stays in the room; the receiver re-joins
  with the same code, restores each file's whole-file digest from the journaled
  checkpoint state when this runtime produced it (otherwise it re-hashes the persisted
  prefix — correctness-first; the final whole-file digest still verifies), reports
  per-file high-water marks, and streams only the missing blocks. Handshakes always
  derive fresh traffic keys.
- **Secrets**: the journal never persists invite codes, the session master key,
  directional traffic keys, or live AEAD counters.

## CLI (v1.3 PR02)

The CLI receiver keeps verified progress on disk so a crash, cancellation, or process
restart does not force a large transfer to restart from zero. Everything lives under a
hidden `.sendbeam` directory inside the receive out directory (the `--out` argument,
default `.`):

## Storage layout

Everything lives under a hidden `.sendbeam` directory inside the receive out directory
(the `--out` argument, default `.`):

```
<out>/.sendbeam/
  <transferId>.json                 # the durable journal (mode 0600, atomic replace)
  partials/<transferId>/<rel>.part  # verified partial data, mirroring manifest paths
  partials/tmp-<random>/<rel>.part  # non-resumable partials (legacy manifest, no id)
```

- **Journals** are schema-v1 `DurableJournal` files written through the atomic
  temp+fsync+rename primitive (`wire.WriteJournalAtomic`). A crash leaves the old or the
  new journal, never a torn mix. They are never transmitted and carry no wire-version
  implication.
- **Partial data** always carries the `.part` suffix and lives only under
  `partials/`, so it can never be mistaken for a successfully received final file.
  Final files appear in the out directory only after whole-transfer verification.
- **Secrets**: the journal never persists the raw SPAKE2/session master key, directional
  traffic keys, live AEAD counters, or the invite code. The only secret-adjacent field is
  the opaque `resumeSecret` envelope, which PR02 never fills (that is PR07's cross-session
  resume derivation).

## Durability ordering (the contract)

A block is acknowledged only after the full ordering below; a crash at any earlier point
leaves the previous checkpoint authoritative:

```
receive/authenticate block
        ↓
verify block                     (wire layer)
        ↓
write block data                 (.part file)
        ↓
required durability barrier      (fsync of the .part file)
        ↓
atomically advance the journal   (CommitBlocks → atomic journal write)
        ↓
ONLY NOW is the block advertised (the wire ack)
```

- Crash before the durability barrier: the checkpoint claims only the last durable
  block; the un-fsynced tail is re-transferred on resume.
- Crash after durable data but before the journal commit: the data is durable but
  unclaimed; resume truncates the partial to the authoritative checkpoint and re-transfers
  the tail. This is safe re-transfer, never corruption.
- Journal commit failure: the transfer fails closed (`sink_error`/`quota`), the previous
  checkpoint stays authoritative, and nothing is deleted.

## Finalization

Final files appear only after the whole-transfer digest is verified. Finalization then:

1. Promotes every `.part` file to its final name with an **atomic no-overwrite**
   primitive: hard-link (atomic no-clobber on POSIX and NTFS) then unlink the `.part`;
   filesystems without hard links fall back to a checked rename. An existing destination
   fails closed — nothing is overwritten.
2. Removes the journal only after every final rename is in place.
3. Best-effort fsync of the out directory and cleanup of empty partial/final dirs.

A crash between a final rename and the journal removal leaves a fully-committed journal
plus finals; `sendbeam transfers inspect` surfaces it and `discard` cleans it up.

Abort (cancel, peer failure, storage error) deliberately **keeps** the journal and
partials at their last durable checkpoint: they are the only resumable copy of the user's
data and are never silently deleted. Only the explicit `discard` command removes them,
idempotently. Non-resumable transfers (legacy senders whose manifest carried no transfer
id) get no journal, and their temp partials are removed on both finalize and abort.

## Resume

The CLI sender now mints a stable random `transferId` in the manifest (the wire protocol
already supports it), so CLI↔CLI transfers are resumable. When a receiver joins a room
and the authenticated manifest matches an existing journal, the receiver:

1. Revalidates every user-editable journal claim against the authenticated manifest:
   the manifest fingerprint, the destination-location identity, and the checkpoint bounds.
   Corrupt, torn, tampered, foreign, or mismatched journals fail closed — never guessed,
   never deleted automatically.
2. Checks that each `.part` file backs its checkpoint (present and at least as long as
   `committedBytes`); missing or truncated partials fail the transfer closed with guidance.
3. Rebuilds the wire resume seed: per-file high-water marks plus whole-file digests. Each
   digest is restored from the journal's `digestCheckpoint` state when the format matches
   this runtime and the state decodes; otherwise the persisted prefix is re-hashed
   (correctness-first). A restored or re-hashed seed never bypasses the final whole-file
   verification. The seed carries the journal's `manifestFingerprint`, and the receiver
   re-binds the whole seed against the authenticated manifest before advertising any of it
   (PR06): an impossible or mismatched claim fails closed rather than being clamped.
4. Streams only the missing blocks from the sender.

Resume is **same-session** recovery: the sender must still be connected in the room the
user re-joins with the same invite code, and the new handshake always derives fresh
traffic keys — no old key or counter is ever reused.

## Cross-session resume (v1.3 PR08)

A _process/page/session death_ is different from a _same-session path switch_. PR08 makes
that distinction explicit and turns the PR07 resume credential into a real, safe product
flow:

- **reconnect** — same live transfer engine/session; a direct↔relay or temporary outage;
  the existing traffic-key epoch stays valid under current semantics (PR06 path
  recovery). No resume-auth runs.
- **durable resume** — the process/session died; persisted transfer state exists on BOTH
  peers; both possess the matching PR07 resume credential; mutual resume-auth-v1
  succeeds; then a brand-new traffic-key epoch is derived and the verified durable
  checkpoint is reused.
- **restart** — no compatible credential (lost secret, legacy pre-PR07 state, changed
  source, corrupt state, or the user elects to start from zero). Old partials are never
  silently trusted and never deleted without explicit discard.

### The invariant

> Durable progress from a PREVIOUS authenticated session may be reused ONLY after
> successful resume-auth-v1 continuity authentication. A fresh invite/rendezvous code
> authenticates the NEW session; it does NOT by itself prove continuity with the
> original transfer peer.

Both the CLI and the browser enforce this at the storage layer: a journal's verified
progress is never advertised unless the local peer explicitly armed an authenticated
resume attempt (`ExpectResume`/`expectResumeFor`) AND resume-auth succeeded in this
session (`SetResumeAuthorized`/`authorizeResume`) before the manifest was processed. A
fresh session that presents the same `transferId` + manifest fingerprint without the
preamble fails closed — nothing is received, nothing is deleted, the journal stays
intact. Regression tests prove a fresh session cannot skip old blocks merely because
the ids match.

### The flow

1. The user selects the interrupted transfer locally (sender record / receive journal).
2. The sender revalidates its source: reopen the persisted path or handle, recompute the
   canonical identity + exact manifest fingerprint, compare with the record. A changed
   source is a hard resume refusal — a valid `resumeSecret` is not authorization to
   change the source.
3. A fresh temporary rendezvous is created and a fresh invite code shown (the code is
   never persisted and never derived from the resume secret).
4. Both peers join; peer capabilities are checked (`resume-auth-v1`).
5. PR07 resume-auth runs mutually over the session channel, with fresh nonces.
6. ONLY after success: fresh directional keys + salts are derived and counters start at
   0 under them; the transfer engine is constructed with the new key epoch.
7. Authenticated Manifest → fingerprint-bound resume_state → sender validates the
   durable claim → missing blocks only → whole-file verification → Complete/Done.

Nothing — Manifest, ResumeState, BlockData, Complete — travels from a resumed transfer
before resume-auth completes, and the normal transfer protocol never runs under
provisional resume-auth keys.

### Failure semantics

- Resume auth failure: sender record and receiver journal + partials are preserved;
  candidate attempt keys/nonces are destroyed; a later attempt uses fresh nonces.
- Lost credential / peer capability absent / stripped capability: durable data is
  preserved, authenticated resume is reported unavailable, and an explicit fresh
  restart/discard is offered. A replacement credential is NEVER derived from the new
  session.
- Source mismatch: old state is preserved until explicit discard; no data is sent under
  the old transfer identity.
- Corrupt journal: fail closed, keep for inspect/discard; never clamped or repaired
  silently.

## Management commands

```
sendbeam transfers list     [--out DIR]
sendbeam transfers inspect  <id> [--out DIR]
sendbeam transfers resume   <id> [--out DIR]
sendbeam transfers discard  <id>... [--out DIR] [--all] [--yes]
```

- `list` shows every journal (valid or unreadable) and orphaned partial tree, with a
  status per entry: interrupted transfer not found, ready to resume, legacy (restart
  required), partial data missing/truncated, or credential unavailable. A bad journal
  never hides the others and is never deleted. No secret material is printed.
- `inspect` cross-checks one journal against its partial data, reporting exactly which
  file's partial is missing or truncated. It never deletes.
- `resume <id> --code <fresh-code>` performs the cross-session authenticated resume:
  the receiver selects the matching interrupted journal, joins the sender's fresh
  rendezvous with the fresh code, both peers run resume-auth-v1, and only after mutual
  authentication is the verified checkpoint reused under a fresh key epoch. It fails
  closed with distinct errors when the transfer is not found, the source changed, the
  receiver state is missing/corrupt, the credential is unavailable, the peer does not
  support authenticated resume, or resume authentication fails.
- `discard` explicitly deletes one journal and its partial tree (or `--all` with `--yes`),
  bounded to that transfer, idempotent, and safe to repeat. Nothing is ever discarded
  implicitly.

## Bounds

- Partial data never exceeds the manifest's own geometry (each `.part` is capped at the
  file size and truncated to the checkpoint on resume).
- `SENDBEAM_PARTIAL_BUDGET` (bytes) optionally bounds total partial data + journal; a
  breach fails the transfer with `quota` and keeps the resumable state. Unset means
  unlimited.
- Cleanup only ever touches the `.sendbeam` directory of the selected out directory.

## Deferred limits (later v1.3 PRs)

- Persistent server-side presence, inboxes, accounts, cloud backup/history, and
  trusted-device pairing remain explicitly OUT of scope — PR08 stays account-free with
  no server-side file storage, no permanent trusted-device identity, no global transfer
  directory, and no background cloud mailbox. Durable receive state is purely local.
