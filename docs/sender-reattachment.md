# Sender source reattachment (v1.3 PR04)

Senders keep a per-transfer record — the stable `transferId` plus the canonical source
identity — durably persisted **before** the manifest frame is transmitted. If a send is
interrupted (cancel, crash, reload), the sender can be reopened against the exact source
and resumed under the same `transferId`: the receiver keeps its journal and partials
(PR02/PR03), and the sender proves the source is unchanged before the id is re-advertised.
A changed source is never resumed under an old id: the send fails closed before a single
byte goes out.

This page documents the record schema, the durability ordering, the identity definition,
the reopen behavior of both implementations, and the limits deferred to later PRs.

## The record

Both implementations persist one record per transfer, schema-v1, carrying the same core:

```
schemaVersion       1
transferId          32 lowercase hex   (the id advertised in the manifest)
manifestFingerprint 64 lowercase hex   (canonical SHA-256 of the validated manifest)
protocolVersion     'sendbeam/1'
createdAt           unix ms
updatedAt           unix ms
files[]             name, size, mime, lastModified — canonical order
checksum            SHA-256 (hex) over the canonical JSON of every field above
```

### Canonical source identity

`manifestFingerprint` is the exact bytes the receiver's durable journal binds its
checkpoints to (the same `wire.ManifestFingerprint` / `journal.manifestFingerprint`
used by PR02/PR03): the canonical JSON of the validated manifest, covering the
`transferId`, the block geometry, and every file's name, size, mime, timestamp, and
content digest. Any difference means a different source — that is the whole point.

### Platform-specific identity claims

The record's file set is platform-identical; only _how a restart locates the source_
differs, and that is local state, never on the wire:

- **CLI** (`apps/cli/internal/transfer/sender_state.go`): the record adds
  `paths` — the canonical sorted absolute source paths. The store keys records on
  disk as `<transferId>.json` and finds them by `PathKey`, the SHA-256 of the
  NUL-joined canonical sorted paths (domain prefix `sendbeam/sender-paths\x00`).
  A re-run of the same command needs no extra information: it derives the key from
  the arguments and finds the record.
- **Browser** (`apps/web/src/lib/transfer/sender-record.ts`): the record adds a
  `reattachment` claim — `{ kind: 'reselection' }` (a plain picker selection must be
  re-picked) or `{ kind: 'handle'; handleKind; handle }` (a persisted File System
  Access handle that reopens the source directly). Records are keyed by
  `transferId` in IndexedDB (`sendbeam-sender` → `records`).

## Durability ordering

The seam is the wire `onManifest` hook, identical on both twins: it fires with the
validated manifest (after every whole-file digest is computed) **strictly before** the
manifest frame is transmitted, and a rejection aborts the send with nothing sent.

1. **Fresh send**: a transfer id is minted, the record is created from the manifest and
   persisted. A persist failure aborts before the manifest — the id is never advertised
   unless a durable record backs it.
2. **Restart**: the prior record must exist and be valid, and its `manifestFingerprint`
   must equal the fingerprint of the manifest about to be advertised. Any mismatch — or
   a corrupt or missing record — fails closed before the manifest frame. On success the
   record's `updatedAt` is refreshed (and the browser's `reattachment` claim updated to
   the freshest one).
3. **Verified success**: the record is discarded. A failure keeps it, so the send stays
   resumable.

Storage and integrity:

- CLI: `os.UserConfigDir()/sendbeam/sender/<transferId>.json` (env override
  `SENDBEAM_SENDER_STATE`), mode 0600, atomic replace (temp + fsync + rename + directory
  sync). Decode is strict fail-closed: exact schema version, unknown fields rejected, no
  trailing data, checksum verified, and the `manifestFingerprint` recomputed from the
  stored `transferId` + files. A corrupt record is surfaced (list/discard) but never
  treated as absent.
- Browser: records are structured-clone objects in IndexedDB because the handle cannot
  be JSON-encoded. Integrity comes from strict shape validation (exact key sets at every
  level) plus the checksum over the canonical JSON core; the opaque handle is excluded
  from the checksum and fails at reopen time (permission revoked, handle dead), falling
  back to reselection. Browsers without IndexedDB degrade: sends proceed without
  restart/reopen support.

## Reopen behavior

**CLI** — `sendbeam send` re-runs with the same arguments:

1. The store `Lookup`s the record by the canonical path key. No record → fresh send with
   a minted id. Corrupt → fail closed with discard guidance.
2. Cheap pre-check: the freshly statted source (count, and per-file name/size/mime/mtime
   in canonical order) must match the record, or the send refuses before dialing.
3. `PrepareSender` returns the stored `transferId` and a verify hook; the hook re-checks
   the fingerprint against the manifest before it is sent.
4. `sendbeam transfers list` shows "Interrupted sends" (id, files, bytes, updated,
   paths); `sendbeam transfers discard <id>` / `--all` removes sender records too.

**Browser** — the offerer's pick screen lists "Interrupted sends" (records are loaded
from IndexedDB; corrupt ones are surfaced with a Forget action):

1. **Handle records** ("Send again"): the persisted handle is reopened (read permission
   queried/requested; revocation or a dead handle falls back to reselection), the files
   are re-materialized with their canonical relative names, and the send restarts under
   the record's `transferId` with the reattachment re-verified in the worker.
2. **Reselection records** ("Send again"): the user re-picks the original source; a
   cheap pre-check (count, names, sizes, timestamps) gives a friendly refusal on an
   obvious mismatch, and the worker's fingerprint check is authoritative.
3. **Reopenable folders**: a feature-detected "Send folder (reopenable)" button uses
   `showDirectoryPicker` (File System Access) so fresh sends persist a handle and can be
   reopened later instead of re-picked. The existing plain pickers are unchanged.
4. **Forget** removes the record (nothing on the wire or at the receiver depends on it).

In the browser the picked file order is canonicalized (stable sort by relative name)
before sending, the analog of the CLI's sorted canonical paths: re-picking the same
folder in any order produces the same manifest, so fingerprints stay comparable.

## Changed-source rejection

A same-size, same-mtime edit is the hard case: the cheap pre-check passes, the
fingerprint check does not — the manifest about to be advertised is refused at the hook,
before its frame, so the receiver never sees an inconsistent id. Nothing was sent.

## Cross-session authenticated resume (v1.3 PR08)

PR08 builds on the record: on a sender restart the user _reopens_ the interrupted send
(the record's persisted path/handle or an explicit reselection — PR04 stays mandatory),
the source is revalidated (canonical identity + exact fingerprint against the record),
and only then is the transfer resumed with the peer.

The record's PR07 `resumeSecret` is the difference between a **durable resume** and a
**restart**:

- **Durable resume** — both peers possess the matching transfer-scoped credential. The
  sender starts a FRESH temporary rendezvous (fresh invite code, never persisted, never
  derived from the secret), the receiver selects the matching interrupted journal, both
  run resume-auth-v1, and only after mutual success is the verified checkpoint reused
  under a brand-new key epoch.
- **Restart / legacy** — a pre-PR07 record has no credential; nothing is fabricated for
  it. Durable data may remain locally, authenticated cross-session resume is
  unavailable, and an explicit fresh restart/discard is the only path. Old partials are
  never deleted without explicit discard.

A valid `resumeSecret` is NOT authorization to change the source: the source
revalidation ordering (reopen → recompute identity + fingerprint → compare with the
record) runs before any resume-auth, and a mismatch is a hard refusal.

Errors are distinct: interrupted transfer not found, source changed, receiver state
missing/corrupt, resume credential unavailable, peer does not support authenticated
resume, resume authentication failed, or fresh restart required/available. No secret
material is ever printed.

## Limits (deferred)

- Browser restarts depend on the same browser + origin (the handle and record are
  origin-scoped); there is no cross-device resume.
- The record keeps the last successful manifest; it does not archive earlier versions,
  and there is no quota management beyond the per-record removal.
- Persistent server-side presence, inboxes, accounts, cloud backup/history, and
  trusted-device pairing remain OUT of scope — resume is account-free and purely local.

## CLI storage contract

```
os.UserConfigDir()/sendbeam/sender/
  <transferId>.json          # schema-v1 record, mode 0600
```

Every load is fail-closed: corrupt or unsupported records are reported with discard
guidance and never treated as absent.
