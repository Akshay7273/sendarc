# CLI durable receive (v1.3 PR02)

The CLI receiver keeps verified progress on disk so a crash, cancellation, or process
restart does not force a large transfer to restart from zero. This page documents the
storage layout, the durability ordering, finalization, the management commands, and the
limits that are deliberately deferred to later v1.3 PRs. The durability contract itself
is defined in [ADR 0004](adr/0004-durable-journal.md); this page describes the CLI
implementation of it.

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
3. Rebuilds the wire resume seed: per-file high-water marks plus whole-file digests
   re-hashed from the persisted prefix (the correctness-first restore; digest-state
   checkpointing is V13-PR05).
4. Streams only the missing blocks from the sender.

Resume is **same-session** recovery: the sender must still be connected in the room the
user re-joins with the same invite code, and the new handshake always derives fresh
traffic keys — no old key or counter is ever reused.

## Management commands

```
sendbeam transfers list     [--out DIR]
sendbeam transfers inspect  <id> [--out DIR]
sendbeam transfers resume   <id> [--out DIR]
sendbeam transfers discard  <id>... [--out DIR] [--all] [--yes]
```

- `list` shows every journal (valid or unreadable) and orphaned partial tree. A bad
  journal never hides the others and is never deleted.
- `inspect` cross-checks one journal against its partial data, reporting exactly which
  file's partial is missing or truncated. It never deletes.
- `resume` verifies a journal is resumable and explains how: re-run
  `sendbeam receive <code>` in the room where the sender is still connected. The invite
  code is never stored, so a standalone resume without the sender is not possible.
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

- Cross-session authenticated resume with fresh traffic keys without a live sender is
  PR07 (the `resumeSecret` envelope exists in the schema but is unused by PR02).
- Resume validation against authenticated peer identity (beyond the manifest fingerprint
  and destination location) is PR06/PR07.
- Digest-state checkpointing (avoid re-hashing the persisted prefix on resume) is PR05.
- Browser (OPFS) durable receive is PR03.
