# ADR 0004 — Durable transfer journal: durability contract and schema

Status: accepted
Scope: v1.3 (durable transfers)
Applies to: `packages/wire/journal.go` (Go), `packages/protocol/src/journal.ts` (TS), and
the future durability implementations in `apps/cli` (PR02) and `apps/web` (PR03)

## Context

A browser reload, app/process restart, crash, or temporary outage must not force a large
verified transfer to restart from zero. Durability must never create silent corruption:
only data that is **verified, durably persisted, and durably checkpointed** may be
advertised as resumable progress, and the journal must never advance ahead of durable
data.

This ADR defines the durability contract, the versioned journal schema, the fail-closed
loading rules, and the crash/torn-write/GC/expiry semantics that later CLI and browser
durability work must honor. It establishes the foundation (PR01); it does not implement
the full durable receive (PR02/PR03) or cross-session resume (PR06/PR07).

## 1. Durability ordering (the contract)

A checkpoint may be advertised as resumable only after the full ordering below:

```
receive/authenticate block
        ↓
verify block
        ↓
write block data
        ↓
required durability operation (flush/fsync of the data)
        ↓
atomically advance the journal checkpoint
        ↓
ONLY NOW may that checkpoint be advertised as resumable
```

- A crash **anywhere before** journal advancement leaves the previous checkpoint
  authoritative. The journal is not updated, so nothing is claimed that is not durable.
- A crash **after** checkpoint advancement must never leave the journal claiming bytes
  that are not durable: advancement happens only after the durability barrier, and the
  journal update itself is atomic (see §6).
- There is no "probably written" journal state. Journal updates that fail are failed
  closed: the previous checkpoint remains authoritative.

The schema cannot observe whether block data reached stable storage; enforcing the
durability barrier is the storage layer's job (PR02 CLI, PR03 browser). What the schema
and its API enforce instead is that progress can only be _recorded_ through the single
checkpoint-advance API (`CommitBlocks` / `commitBlocks`), which refuses out-of-bounds and
regressing values, and that any journal failing structural validation, fingerprint
self-consistency, version dispatch, or checksum verification is rejected closed.

## 2. Checkpoint granularity

- Progress is recorded **per file** as `committedBlocks`: the count of leading blocks that
  are verified, durably persisted, AND checkpointed. Resume restarts each file at its
  committed high-water mark.
- Checkpoints are **whole committed blocks**. There is no byte-offset field and no
  byte-granular checkpoint; a fractional or otherwise non-integral block count is rejected.
  `committedBytes(fileIdx)` is a derived value (`committedBlocks × blockSize`, final block
  capped at file size), never stored.
- Invariant: `0 ≤ committedBlocks ≤ blocks` for every file, where `blocks` comes from the
  canonical manifest the journal is bound to.
- Advancement is **monotonic**: the checkpoint API refuses regression.

## 3. Journal trust boundary

The journal is local, user-editable on-disk state. It is **claims, not proof**:

- Nothing is trusted merely because it was loaded from a journal. Every field is bound
  against authenticated transfer state at resume time (PR06/PR07): the transfer ID, the
  manifest fingerprint, the per-file digests, and the identity envelopes.
- The journal's checksum and fingerprint checks detect **accidental corruption, torn
  writes, and casual tampering**. They are not a trust anchor: an attacker who can rewrite
  the file can recompute them. The authoritative binding is the authenticated resume
  protocol, not the journal itself.
- A journal that fails any check is rejected **closed** — never partially applied, never
  "probably read". A journal whose claims are internally consistent but wrong about the
  world (e.g. a checkpoint that exceeds what is actually durable, or stale partial data)
  is handled by the storage layer per §8 and by resume validation per PR06, not by
  guessing.

## 4. Schema

The versioned schema lives in two twin modules that must serialize, validate, fingerprint,
and checksum byte-identically, pinned by `docs/test-vectors/durable-journal.json`:

- `packages/wire/journal.go` (Go, consumed by the CLI)
- `packages/protocol/src/journal.ts` (TypeScript, consumed by the browser)

The journal is a **local persistence format, not a wire format**: it is never transmitted
between peers, carries no `sendbeam/1` wire-version implication, and requires no wire
change or protocol-version bump.

Schema version 1 fields:

| Field                                    | Semantics                                                                                                                                                                                                                                      |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `schemaVersion`                          | On-disk schema identifier (currently `1`).                                                                                                                                                                                                     |
| `transferId`                             | Stable 128-bit hex id carried by the authenticated manifest; must match the manifest's `transferId`.                                                                                                                                           |
| `manifestFingerprint`                    | Canonical SHA-256 over the validated manifest's canonical wire JSON (see §5).                                                                                                                                                                  |
| `protocolVersion`                        | Wire-protocol version the transfer ran under (`sendbeam/1`); recorded, never implied.                                                                                                                                                          |
| `resumeVersion`                          | Durability resume protocol version (currently `1`); independent of schema and wire versions.                                                                                                                                                   |
| `blockSize`                              | Transfer's negotiated logical block size; every file entry must match it.                                                                                                                                                                      |
| `createdAt` / `updatedAt`                | Unix milliseconds; `updatedAt ≥ createdAt`.                                                                                                                                                                                                    |
| `sourceIdentity` / `destinationIdentity` | Opaque versioned identity envelopes (see §5).                                                                                                                                                                                                  |
| `files[]`                                | Per-file entries: the wire `FileEntry` geometry (`idx, name, size, mime, lastModified, blockSize, blocks, fileDigest`) plus `committedBlocks`. Stored so the journal alone can re-validate the resumed transfer and reproduce the fingerprint. |
| `resumeSecret` (optional)                | Opaque versioned resume-secret envelope (see §5).                                                                                                                                                                                              |
| `checksum`                               | SHA-256 over the canonical JSON of every other field; a write-time derivation, verified on load.                                                                                                                                               |

## 5. Secret handling and identity

The journal **never** persists:

- the raw PAKE/session master secret,
- existing directional traffic keys,
- live AEAD counters as a shortcut for starting a new process/session,
- unrelated credentials.

The only secret-adjacent field is `resumeSecret`, an **opaque, versioned envelope** whose
content is deliberately undefined by PR01: the cross-session authenticated resumption
derivation is PR07. Its lifecycle contract: created only by the resume protocol, bound to
the transfer ID and manifest fingerprint, invalidated when the transfer completes or the
journal is deleted. Fresh processes/sessions must always use fresh traffic cryptographic
state; nothing in the journal may make unsafe key/counter reuse necessary.

`sourceIdentity` and `destinationIdentity` are opaque versioned envelopes whose values are
defined by the durability implementation that writes them (destination-location identity
in PR02/PR03, peer identity binding in PR07). Validation checks only the envelope shape
(version, bounded hex/base64url value); the content is a claim bound at resume time.

## 6. Versioning, migration, and atomicity

- **Current schema version:** `1`. `DecodeJournal` accepts exactly it.
- **Supported decode behavior:** schema v1 journals decode and validate; unknown fields,
  malformed JSON, trailing data, and any structural inconsistency fail closed.
- **Upgrade/migration entry point:** `decodeJournalVersion` is the dispatch point. When a
  new schema lands it gains a case plus its migration path. There is deliberately no
  fabricated earlier public format: v1 is the first, and tests prove supported transforms
  and rejection behavior rather than pretending migration history exists.
- **Unknown/future version:** rejected as unsupported (COMPAT); the message states the
  journal is newer than the build supports. **Corrupted version** (missing, zero,
  negative, fractional): rejected as corrupt (STORAGE).
- **Downgrade expectations:** a journal written by a newer build is not readable by an
  older build; it fails closed with the unsupported-version error. This is intentional.
- **Atomicity:** native journal writes use the atomic-replacement primitive
  (`WriteJournalAtomic`): write canonical bytes to a temp file in the same directory,
  fsync, close, then rename over the target (POSIX-atomic; Windows `os.Rename` replaces).
  A crash leaves either the old journal or the complete new one, never a torn mix. The
  parent directory is fsynced on POSIX (best effort) so the rename itself is durable.
  Browser storage atomicity is PR03 (transactional origin storage).

## 7. Crash / torn-write contract

The authoritative recovery point is always safe. Modeled cases:

| Crash point                                 | Recovery behavior                                                                                                                                                              |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Before data write                           | Previous checkpoint authoritative; journal untouched.                                                                                                                          |
| During data write                           | Partial/absent block data; journal claims nothing new.                                                                                                                         |
| After data write, before durability barrier | Data may be lost on reboot; journal must not have advanced (the storage layer performs the barrier before `CommitBlocks`).                                                     |
| After durable data, before journal update   | Data durable but unclaimed; resume re-verifies and continues from the previous checkpoint (bytes may be re-requested).                                                         |
| During journal update                       | Atomic replace leaves old or new journal; never torn; torn files fail closed on load.                                                                                          |
| After journal commit                        | Checkpoint authoritative; must not claim bytes that were not made durable first.                                                                                               |
| Truncated journal                           | JSON parse or checksum failure → reject closed.                                                                                                                                |
| Malformed/corrupt journal                   | Validation or checksum failure → reject closed.                                                                                                                                |
| Valid old supported version                 | v1 decodes.                                                                                                                                                                    |
| Unsupported future version                  | Rejected closed (COMPAT).                                                                                                                                                      |
| Missing partial data                        | Journal may exist with no partial data → see §8.                                                                                                                               |
| Checkpoint beyond available durable data    | Impossible to _write_ (bounds + API), and detected on load as inconsistent state → reject; storage layer never deletes potentially resumable data automatically on error (§8). |

## 8. GC / expiry / disk policy (contract)

PR01 defines the policy contract; the CLI/browser implementations (PR02/PR03) build the
management UX and enforce limits.

- **Staleness:** a journal is stale after the implementation-defined expiry (storage
  layers choose a TTL and surface it; nothing in the schema expires implicitly).
- **Expiry:** incomplete transfer state may expire per policy, and **only after**: the
  journal's `resumeSecret` (if any) is invalidated, the user has been given the
  Keep/Discard choice where applicable, and deletion is confirmed — never as a side effect
  of startup error handling.
- **Before deletion:** no journal or partial data is deleted while it is the only copy of
  potentially resumable user data, and never silently on startup error.
- **Disk-budget accounting:** partial data size ≈ the sum of each file's committed bytes
  (`committedBytes`); implementations account for partial data + journal together and
  enforce their budget at write/commit time (quota → fail the transfer closed, existing
  `FailQuota` semantics).
- **Partial data + journal cleanup:** the relationship is journal ⇒ partial data (the
  journal names the files); cleanup removes both or neither, idempotently (a journal is
  removed only after whole-transfer verification / atomic final rename, per PR02).
- **Journal exists, partial data missing:** resume cannot validate → fail closed;
  journal may be discarded only by explicit policy (see above).
- **Partial data exists, journal unusable:** orphaned partial data is never deleted
  automatically; it is surfaced and managed by the future management UX.
- **Cleanup idempotency:** removal of journals/partials must be safe to repeat and must
  never error-loop on already-missing files.

## 9. What PR01 establishes vs later PRs

PR01 establishes: the durability ordering contract, the versioned schema + validation +
fail-closed loading, fingerprint/checksum definitions, version dispatch and migration
policy, the atomic-write primitive (Go), the checkpoint-advance API, the secret-handling
rules, and this ADR.

Later work builds on it without rewriting it:

- **PR02 (CLI durable receive):** `.sendbeam` storage layout, `.part` files, receiver
  integration (durability barrier before `CommitBlocks`), atomic final rename after
  whole-transfer verification, list/inspect/resume/discard UX, disk-budget enforcement.
- **PR03 (browser durable receive):** OPFS data + transactional origin-storage journal,
  dedicated-worker sync access handles, `flush()` before advancement, quota/eviction
  handling, lock/lease semantics.
- **PR06/PR07:** resume validation binding journal claims against authenticated transfer
  state; the cross-session authenticated resume protocol that fills the `resumeSecret`
  envelope and derives fresh traffic keys.

## Consequences

- New durability code must observe the §1 ordering; checkpoint advancement goes through
  the single API and never precedes the durability barrier.
- Journal code is fail-closed: corrupt, torn, unknown, or unsupported state is rejected,
  never guessed.
- No raw session key material may ever be written to a journal; `resumeSecret` is the only
  secret-adjacent field and stays opaque until PR07.
- The journal is local state with no wire-version implication; no `sendbeam/2` and no wire
  change is introduced by durable journaling.
