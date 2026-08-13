/**
 * Durable transfer journal — the versioned local persistence contract for resumable
 * transfers (docs/adr/0004-durable-journal.md).
 *
 * The journal is LOCAL on-device state, NOT part of the sendbeam/1 wire protocol: it is
 * never transmitted between peers and carries no wire-version implication. It lives in
 * this package because the browser and the Go CLI must consume the same contract; it is
 * the TypeScript twin of packages/wire/journal.go, and the two must serialize, validate,
 * fingerprint, and checksum byte-identically (pinned by docs/test-vectors/durable-journal.json).
 *
 * Durability ordering (the contract). A checkpoint may be advertised as resumable only
 * after the full ordering below; a crash at any earlier step leaves the previous
 * checkpoint authoritative:
 *
 *   receive/authenticate block
 *           ↓
 *   verify block
 *           ↓
 *   write block data
 *           ↓
 *   required durability operation (flush of the data)
 *           ↓
 *   atomically advance the journal checkpoint   ← commitBlocks is the only advancement API
 *           ↓
 *   ONLY NOW may that checkpoint be advertised as resumable
 *
 * The schema cannot observe the data-durability barrier (browser storage backends own it,
 * PR03); what it CAN do — and what this module proves with tests — is fail closed on any
 * journal that is structurally invalid, fingerprint-inconsistent, unknown-versioned, or
 * checksum-stale, and refuse checkpoints that are not whole committed blocks.
 */

import type { FileEntry, Manifest } from './transfer.js';
import { FrameType } from './transfer.js';
import { bytesToHex, utf8 } from './bytes.js';
import { sha256 } from './webcrypto.js';
import {
  MAX_MANIFEST_BLOCK_BYTES,
  MAX_TRANSFER_FILES,
  normalizeTransferPath,
  validateManifest,
} from './safe-path.js';
import { PROTOCOL_VERSION } from './constants.js';

/** Current durable-journal schema version. Decode accepts exactly this value. */
export const JOURNAL_SCHEMA_VERSION = 1;

/**
 * Version of the durability resume protocol whose checkpoint semantics the journal was
 * written for. Independent of the schema version and of the wire PROTOCOL_VERSION.
 */
export const JOURNAL_RESUME_VERSION = 1;

/**
 * Digest checkpoint format identifiers (V13-PR05). The identifier tags the serialized
 * digest state so only a compatible runtime restores it: the bytes are opaque,
 * implementation-specific state, never decoded by another implementation. A journal whose
 * checkpoint format this runtime cannot restore falls back to re-hashing the persisted
 * prefix — the checkpoint is an optimization, never a source of truth.
 */
export const DIGEST_CHECKPOINT_FORMAT_HASH_WASM = 'sha256-wasm-v1';
export const DIGEST_CHECKPOINT_FORMAT_GO_STDLIB = 'sha256-go-v1';

/** Bounds the format identifier shape: lowercase alphanumeric start, then `[a-z0-9._-]`. */
const DIGEST_CHECKPOINT_FORMAT_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/;

/**
 * Bounds the serialized digest state (lowercase hex) a journal may carry. hash-wasm's
 * sha256 state is 116 bytes (232 hex chars); the Go stdlib's is 108 bytes (216 hex chars).
 * The generous-but-bounded ceiling keeps decode/restore allocations tiny for any
 * attacker-controlled or corrupted state length.
 */
const MAX_DIGEST_CHECKPOINT_STATE_HEX = 4096;

/**
 * Optional serialized whole-file digest state that exactly matches one file's committed
 * checkpoint (V13-PR05). Lets a resuming runtime restore the SHA-256 state instead of
 * re-hashing the persisted prefix — an optimization only.
 *
 * Describes EXACTLY the bytes the journal's committed checkpoint claims: `committedBlocks`
 * must equal the file's committedBlocks and `committedBytes` the committed byte count, or
 * the journal is structurally corrupt and fails closed. The serialized state bytes are
 * opaque and implementation-specific; `format` identifies which runtime produced them so
 * only a compatible implementation may restore them. A valid journal carrying an unusable
 * optional checkpoint (unknown format, undecodable or unrestorable state) still resumes
 * through correctness-first prefix re-hash.
 *
 * Never a source of truth: final whole-file digest verification remains mandatory, and a
 * checkpoint can never advance the journal — commitBlocks is still the only progress API.
 */
export interface JournalDigestCheckpoint {
  /** Digest algorithm + implementation + state-format version (see DIGEST_CHECKPOINT_FORMAT_*). */
  format: string;
  /** Exact committed block count the state covers; must equal the file's committedBlocks. */
  committedBlocks: number;
  /** Exact committed byte count the state covers; must equal min(committedBlocks*blockSize, size). */
  committedBytes: number;
  /** Serialized digest state, lowercase hex, size-bounded. */
  state: string;
}

/**
 * Opaque, versioned identity envelope. The value is deliberately opaque to the journal:
 * its content and derivation are defined by the durability implementation that writes it
 * (destination-location identity in PR02/PR03) or by the resume-authentication protocol
 * (peer identity binding in PR07). A claim, never a trust anchor.
 */
export interface JournalIdentity {
  version: number;
  value: string;
}

/** One file's durable checkpoint within a journal. */
export interface JournalFileState {
  idx: number;
  name: string;
  size: number;
  mime: string;
  lastModified: number;
  blockSize: number;
  blocks: number;
  fileDigest: string;
  /**
   * Count of leading blocks that are verified, durably persisted AND checkpointed. The
   * only progress representation: whole-block granularity, never byte offsets.
   * Invariant: 0 <= committedBlocks <= blocks.
   */
  committedBlocks: number;
  /**
   * Optional serialized digest state covering exactly this file's committed checkpoint
   * (V13-PR05). Omitted when the digest state is not serializable or the transfer predates
   * digest checkpointing; resume then re-hashes the persisted prefix.
   */
  digestCheckpoint?: JournalDigestCheckpoint;
}

/**
 * Opaque, versioned envelope for the minimum resume-secret material the durability model
 * requires. PR01 deliberately does not define its content (cross-session authenticated
 * resume is PR07). Never carries the raw SPAKE2/session master key, directional traffic
 * keys, live AEAD counters, or unrelated credentials.
 */
export interface JournalResumeSecret {
  version: number;
  value: string;
}

/** Versioned durable-transfer journal (schema version 1). */
export interface DurableJournal {
  /** On-disk schema identifier (JOURNAL_SCHEMA_VERSION). */
  schemaVersion: number;
  /** Stable 128-bit hex id carried by the authenticated manifest. */
  transferId: string;
  /** Canonical SHA-256 (hex) of the validated manifest (see manifestFingerprint). */
  manifestFingerprint: string;
  /** Wire-protocol version the transfer ran under (recorded, never implied). */
  protocolVersion: string;
  /** Durability resume protocol version (JOURNAL_RESUME_VERSION). */
  resumeVersion: number;
  /** Transfer's negotiated logical block size; every file entry must match it. */
  blockSize: number;
  /** Journal creation time, unix milliseconds. */
  createdAt: number;
  /** Last checkpoint-advance time, unix milliseconds; always >= createdAt. */
  updatedAt: number;
  /** Opaque claim about the sender, bound by the resume protocol. */
  sourceIdentity: JournalIdentity;
  /** Opaque claim about the local destination, bound by the durability implementation. */
  destinationIdentity: JournalIdentity;
  /** Per-file durable checkpoints, in manifest index order. */
  files: JournalFileState[];
  /** Optional opaque resume-secret envelope (PR07). Omitted when absent. */
  resumeSecret?: JournalResumeSecret;
  /** SHA-256 over the canonical JSON of every other field; a write-time derivation. */
  checksum?: string;
}

const isLowerHex = (s: string, n: number): boolean => s.length === n && /^[0-9a-f]+$/.test(s);

const OPAQUE_HEX = /^[0-9a-f]+$/;
const OPAQUE_B64 = /^[A-Za-z0-9_-]+$/;

function validateOpaqueValue(v: string, label: string): void {
  if (v.length === 0) throw new Error(`journal: ${label} value must not be empty`);
  if (v.length > 2048) throw new Error(`journal: ${label} value is too long`);
  if (!OPAQUE_HEX.test(v) && !OPAQUE_B64.test(v)) {
    throw new Error(`journal: ${label} value must be hex or base64url`);
  }
}

function validateIdentity(id: JournalIdentity, label: string): void {
  if (id.version !== 1) throw new Error(`journal: unsupported ${label} version ${id.version}`);
  validateOpaqueValue(id.value, label);
}

function validateEnvelope(e: JournalResumeSecret, label: string): void {
  if (e.version !== 1) throw new Error(`journal: unsupported ${label} version ${e.version}`);
  validateOpaqueValue(e.value, label);
}

/**
 * Canonical SHA-256 (hex) of a validated manifest — the same bytes JSON.stringify
 * produces for the canonical manifest, byte-identical to the Go twin, so it pins the
 * file set a journal's checkpoints refer to. A binding claim, not a trust anchor.
 */
export async function manifestFingerprint(manifest: Manifest): Promise<string> {
  const canonical = validateManifest(manifest);
  return bytesToHex(await sha256(utf8(JSON.stringify(canonical))));
}

async function fingerprintFromFiles(
  transferId: string,
  files: JournalFileState[],
): Promise<string> {
  const entries: FileEntry[] = files.map((f) => ({
    idx: f.idx,
    name: f.name,
    size: f.size,
    mime: f.mime,
    lastModified: f.lastModified,
    blockSize: f.blockSize,
    blocks: f.blocks,
    fileDigest: f.fileDigest,
  }));
  const totalSize = entries.reduce((acc, f) => acc + f.size, 0);
  return manifestFingerprint({
    type: FrameType.Manifest,
    ...(transferId !== '' ? { transferId } : {}),
    files: entries,
    totalSize,
  });
}

/**
 * Build a fresh schema-v1 journal with zero committed checkpoints. `transferId` must be
 * the stable 128-bit hex id carried by the authenticated manifest, and `manifest` must
 * carry that same id (a manifest without one never opted into resumption).
 */
export async function newJournal(
  transferId: string,
  manifest: Manifest,
  source: JournalIdentity,
  destination: JournalIdentity,
  nowMs: number,
): Promise<DurableJournal> {
  if (!isLowerHex(transferId, 32)) {
    throw new Error('journal: transferId must be 32 lowercase hex characters');
  }
  if (manifest.transferId !== transferId) {
    throw new Error('journal: transferId must match the authenticated manifest');
  }
  const fingerprint = await manifestFingerprint(manifest);
  const files: JournalFileState[] = manifest.files.map((f) => ({
    idx: f.idx,
    name: f.name,
    size: f.size,
    mime: f.mime,
    lastModified: f.lastModified,
    blockSize: f.blockSize,
    blocks: f.blocks,
    fileDigest: f.fileDigest,
    committedBlocks: 0,
  }));
  const j: DurableJournal = {
    schemaVersion: JOURNAL_SCHEMA_VERSION,
    transferId,
    manifestFingerprint: fingerprint,
    protocolVersion: PROTOCOL_VERSION,
    resumeVersion: JOURNAL_RESUME_VERSION,
    blockSize: manifest.files[0]!.blockSize,
    createdAt: nowMs,
    updatedAt: nowMs,
    sourceIdentity: source,
    destinationIdentity: destination,
    files,
  };
  await validateJournal(j);
  return j;
}

/**
 * Structural validation plus fingerprint self-consistency. Does NOT verify the checksum
 * (a serialization property checked by decodeJournal) and treats no field as a trust
 * anchor. Async only because the fingerprint recompute uses WebCrypto.
 */
export async function validateJournal(j: DurableJournal): Promise<void> {
  if (j.schemaVersion !== JOURNAL_SCHEMA_VERSION) {
    throw new Error(`journal: unsupported schema version ${j.schemaVersion}`);
  }
  if (j.resumeVersion !== JOURNAL_RESUME_VERSION) {
    throw new Error(`journal: unsupported resume version ${j.resumeVersion}`);
  }
  if (j.protocolVersion !== PROTOCOL_VERSION) {
    throw new Error(`journal: unsupported protocol version ${j.protocolVersion}`);
  }
  if (!isLowerHex(j.transferId, 32)) {
    throw new Error('journal: transferId must be 32 lowercase hex characters');
  }
  if (!isLowerHex(j.manifestFingerprint, 64)) {
    throw new Error('journal: manifestFingerprint must be 64 lowercase hex characters');
  }
  if (
    !Number.isSafeInteger(j.createdAt) ||
    !Number.isSafeInteger(j.updatedAt) ||
    j.createdAt <= 0 ||
    j.updatedAt <= 0 ||
    j.updatedAt < j.createdAt
  ) {
    throw new Error('journal: invalid timestamps');
  }
  if (
    !Number.isSafeInteger(j.blockSize) ||
    j.blockSize <= 0 ||
    j.blockSize > MAX_MANIFEST_BLOCK_BYTES
  ) {
    throw new Error(`journal: invalid block size ${j.blockSize}`);
  }
  validateIdentity(j.sourceIdentity, 'sourceIdentity');
  validateIdentity(j.destinationIdentity, 'destinationIdentity');
  if (j.resumeSecret !== undefined) validateEnvelope(j.resumeSecret, 'resumeSecret');
  if (j.files.length === 0 || j.files.length > MAX_TRANSFER_FILES) {
    throw new Error(`journal: invalid file count ${j.files.length}`);
  }
  const recomputed = await fingerprintFromFiles(j.transferId, j.files);
  if (recomputed !== j.manifestFingerprint) {
    throw new Error('journal: manifest fingerprint mismatch');
  }
  const seen = new Set<string>();
  for (let i = 0; i < j.files.length; i++) {
    const f = j.files[i]!;
    if (f.idx !== i) throw new Error('journal: file indexes must be contiguous');
    for (const [label, value] of [
      ['size', f.size],
      ['lastModified', f.lastModified],
      ['blockSize', f.blockSize],
      ['blocks', f.blocks],
    ] as const) {
      if (!Number.isSafeInteger(value))
        throw new Error(`journal: file ${i} ${label} is not a safe integer`);
    }
    if (f.size < 0 || f.lastModified < 0 || f.blockSize <= 0 || f.blocks < 0) {
      throw new Error(`journal: file ${f.idx} has invalid geometry`);
    }
    if (f.blockSize > MAX_MANIFEST_BLOCK_BYTES) {
      throw new Error(
        `journal: file ${f.idx} block size ${f.blockSize} exceeds the ${MAX_MANIFEST_BLOCK_BYTES}-byte ceiling`,
      );
    }
    if (f.blocks !== Math.ceil(f.size / f.blockSize)) {
      throw new Error(`journal: file ${f.idx} has invalid block geometry`);
    }
    if (f.blockSize !== j.blockSize) {
      throw new Error(
        `journal: file ${f.idx} block size ${f.blockSize} differs from journal block size ${j.blockSize}`,
      );
    }
    if (!isLowerHex(f.fileDigest, 64)) {
      throw new Error(`journal: file ${f.idx} fileDigest must be 64 lowercase hex characters`);
    }
    if (
      !Number.isInteger(f.committedBlocks) ||
      f.committedBlocks < 0 ||
      f.committedBlocks > f.blocks
    ) {
      throw new Error(
        `journal: committedBlocks ${f.committedBlocks} out of range for file ${f.idx} (blocks ${f.blocks})`,
      );
    }
    validateDigestCheckpoint(f);
    const name = normalizeTransferPath(f.name);
    const key = name.toLowerCase();
    if (seen.has(key)) throw new Error('journal: duplicate file path');
    seen.add(key);
  }
}

/**
 * Structural validation of an optional digest checkpoint. Any violation is a corrupt
 * journal and fails closed — an impossible checkpoint claim must never be trusted. The
 * format identifier and state bytes are opaque claims (an unsupported format or
 * unrestorable state falls back to re-hash at resume time, which is a different, safe
 * case).
 */
function validateDigestCheckpoint(f: JournalFileState): void {
  const cp = f.digestCheckpoint;
  if (cp === undefined) return;
  if (!DIGEST_CHECKPOINT_FORMAT_PATTERN.test(cp.format)) {
    throw new Error(`journal: file ${f.idx} digestCheckpoint has an invalid format identifier`);
  }
  if (cp.committedBlocks !== f.committedBlocks) {
    throw new Error(
      `journal: file ${f.idx} digestCheckpoint block count ${cp.committedBlocks} does not match committedBlocks ${f.committedBlocks}`,
    );
  }
  const wantBytes = Math.min(cp.committedBlocks * f.blockSize, f.size);
  if (cp.committedBytes !== wantBytes) {
    throw new Error(
      `journal: file ${f.idx} digestCheckpoint byte count ${cp.committedBytes} does not match its committed blocks (${wantBytes})`,
    );
  }
  if (
    cp.state.length % 2 !== 0 ||
    !isLowerHex(cp.state, cp.state.length) ||
    cp.state.length === 0 ||
    cp.state.length > MAX_DIGEST_CHECKPOINT_STATE_HEX
  ) {
    throw new Error(`journal: file ${f.idx} digestCheckpoint state is out of bounds`);
  }
}

/**
 * The canonical key-ordered body of a journal (every field except the checksum). The key
 * order is the schema contract and MUST match the Go struct declaration order.
 */
function canonicalBody(j: DurableJournal): Record<string, unknown> {
  return {
    schemaVersion: j.schemaVersion,
    transferId: j.transferId,
    manifestFingerprint: j.manifestFingerprint,
    protocolVersion: j.protocolVersion,
    resumeVersion: j.resumeVersion,
    blockSize: j.blockSize,
    createdAt: j.createdAt,
    updatedAt: j.updatedAt,
    sourceIdentity: { version: j.sourceIdentity.version, value: j.sourceIdentity.value },
    destinationIdentity: {
      version: j.destinationIdentity.version,
      value: j.destinationIdentity.value,
    },
    files: j.files.map((f) => ({
      idx: f.idx,
      name: f.name,
      size: f.size,
      mime: f.mime,
      lastModified: f.lastModified,
      blockSize: f.blockSize,
      blocks: f.blocks,
      fileDigest: f.fileDigest,
      committedBlocks: f.committedBlocks,
      ...(f.digestCheckpoint !== undefined
        ? {
            digestCheckpoint: {
              format: f.digestCheckpoint.format,
              committedBlocks: f.digestCheckpoint.committedBlocks,
              committedBytes: f.digestCheckpoint.committedBytes,
              state: f.digestCheckpoint.state,
            },
          }
        : {}),
    })),
    ...(j.resumeSecret !== undefined
      ? { resumeSecret: { version: j.resumeSecret.version, value: j.resumeSecret.value } }
      : {}),
  };
}

/**
 * Serialize a journal to its canonical JSON, appending the checksum (SHA-256 over the
 * canonical JSON of every other field, recomputed on every encode). Output is
 * byte-identical to the Go twin (pinned by docs/test-vectors/durable-journal.json).
 */
export async function encodeJournal(j: DurableJournal): Promise<Uint8Array> {
  await validateJournal(j);
  const body = canonicalBody(j);
  const checksum = bytesToHex(await sha256(utf8(JSON.stringify(body))));
  return utf8(JSON.stringify({ ...body, checksum }));
}

/**
 * Parse, version-dispatch, validate, and checksum-verify a journal, failing closed on ANY
 * deviation: malformed JSON, unknown fields, an unsupported or corrupt schema version,
 * invalid content, or a checksum mismatch. Version policy: only schema version 1 is
 * accepted; newer versions fail closed (COMPAT, "newer than this build supports"), and a
 * missing/zero/negative/fractional version fails closed as corrupt. Downgrading a newer
 * journal to an older reader is not supported.
 */ export async function decodeJournal(data: Uint8Array): Promise<DurableJournal> {
  let obj: unknown;
  try {
    obj = JSON.parse(new TextDecoder().decode(data));
  } catch {
    throw new Error('journal: invalid JSON');
  }
  if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) {
    throw new Error('journal: not an object');
  }
  const m = obj as Record<string, unknown>;
  const schemaVersion = m.schemaVersion;
  if (typeof schemaVersion !== 'number' || !Number.isInteger(schemaVersion)) {
    throw new Error('journal: missing or corrupt schemaVersion');
  }
  if (schemaVersion === JOURNAL_SCHEMA_VERSION) return decodeAndVerifyV1(m);
  if (schemaVersion > JOURNAL_SCHEMA_VERSION) {
    throw new Error(
      `journal: schema version ${schemaVersion} is newer than this build supports (${JOURNAL_SCHEMA_VERSION})`,
    );
  }
  throw new Error(`journal: corrupt schema version ${schemaVersion}`);
}

const JOURNAL_V1_KEYS = [
  'schemaVersion',
  'transferId',
  'manifestFingerprint',
  'protocolVersion',
  'resumeVersion',
  'blockSize',
  'createdAt',
  'updatedAt',
  'sourceIdentity',
  'destinationIdentity',
  'files',
  'resumeSecret',
  'checksum',
];

const FILE_V1_KEYS = [
  'idx',
  'name',
  'size',
  'mime',
  'lastModified',
  'blockSize',
  'blocks',
  'fileDigest',
  'committedBlocks',
  'digestCheckpoint',
];

const ENVELOPE_KEYS = ['version', 'value'];

function assertKeys(m: Record<string, unknown>, allowed: string[], what: string): void {
  for (const key of Object.keys(m)) {
    if (!allowed.includes(key)) throw new Error(`journal: unexpected ${what} field ${key}`);
  }
}

function intField(m: Record<string, unknown>, key: string): number {
  const v = m[key];
  if (typeof v !== 'number' || !Number.isSafeInteger(v)) {
    throw new Error(`journal: ${key} is not a safe integer`);
  }
  return v;
}

function strField(m: Record<string, unknown>, key: string): string {
  const v = m[key];
  if (typeof v !== 'string') throw new Error(`journal: ${key} is not a string`);
  return v;
}

function envelopeField(m: Record<string, unknown>, key: string): JournalIdentity {
  const v = m[key];
  if (typeof v !== 'object' || v === null || Array.isArray(v)) {
    throw new Error(`journal: ${key} is not an object`);
  }
  const e = v as Record<string, unknown>;
  assertKeys(e, ENVELOPE_KEYS, `${key} envelope`);
  return { version: intField(e, 'version'), value: strField(e, 'value') };
}

function digestCheckpointField(v: unknown): JournalDigestCheckpoint {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) {
    throw new Error('journal: digestCheckpoint is not an object');
  }
  const c = v as Record<string, unknown>;
  assertKeys(c, ['format', 'committedBlocks', 'committedBytes', 'state'], 'digestCheckpoint');
  return {
    format: strField(c, 'format'),
    committedBlocks: intField(c, 'committedBlocks'),
    committedBytes: intField(c, 'committedBytes'),
    state: strField(c, 'state'),
  };
}

function fileField(v: unknown): JournalFileState {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) {
    throw new Error('journal: file entry is not an object');
  }
  const f = v as Record<string, unknown>;
  assertKeys(f, FILE_V1_KEYS, 'file entry');
  const state: JournalFileState = {
    idx: intField(f, 'idx'),
    name: strField(f, 'name'),
    size: intField(f, 'size'),
    mime: strField(f, 'mime'),
    lastModified: intField(f, 'lastModified'),
    blockSize: intField(f, 'blockSize'),
    blocks: intField(f, 'blocks'),
    fileDigest: strField(f, 'fileDigest'),
    committedBlocks: intField(f, 'committedBlocks'),
  };
  if (f.digestCheckpoint !== undefined) {
    state.digestCheckpoint = digestCheckpointField(f.digestCheckpoint);
  }
  return state;
}

function decodeJournalV1(m: Record<string, unknown>): DurableJournal {
  assertKeys(m, JOURNAL_V1_KEYS, 'journal');
  const files = m.files;
  if (!Array.isArray(files) || files.length === 0)
    throw new Error('journal: files missing or empty');
  if (files.length > MAX_TRANSFER_FILES) {
    throw new Error(`journal: invalid file count ${files.length}`);
  }
  const j: DurableJournal = {
    schemaVersion: intField(m, 'schemaVersion'),
    transferId: strField(m, 'transferId'),
    manifestFingerprint: strField(m, 'manifestFingerprint'),
    protocolVersion: strField(m, 'protocolVersion'),
    resumeVersion: intField(m, 'resumeVersion'),
    blockSize: intField(m, 'blockSize'),
    createdAt: intField(m, 'createdAt'),
    updatedAt: intField(m, 'updatedAt'),
    sourceIdentity: envelopeField(m, 'sourceIdentity'),
    destinationIdentity: envelopeField(m, 'destinationIdentity'),
    files: files.map(fileField),
  };
  if (m.resumeSecret !== undefined) j.resumeSecret = envelopeField(m, 'resumeSecret');
  if (m.checksum !== undefined) j.checksum = strField(m, 'checksum');
  return j;
}

async function verifyChecksum(j: DurableJournal): Promise<void> {
  const stored = j.checksum;
  if (stored === undefined || !isLowerHex(stored, 64))
    throw new Error('journal: malformed checksum');
  const body = canonicalBody(j);
  const sum = bytesToHex(await sha256(utf8(JSON.stringify(body))));
  if (sum !== stored) throw new Error('journal: checksum mismatch (corrupt or tampered)');
} /**
 * Full v1 pipeline: strict parse, validation, checksum verification. The returned
 * journal keeps its stored checksum so re-encoding is byte-identical; encodeJournal
 * recomputes it on the next write.
 */
async function decodeAndVerifyV1(m: Record<string, unknown>): Promise<DurableJournal> {
  const j = decodeJournalV1(m);
  await validateJournal(j);
  await verifyChecksum(j);
  return j;
}

/**
 * Advance one file's durable high-water checkpoint — the ONLY way committed progress may
 * be recorded. Documented precondition: every block in [0, committedBlocks) has been
 * verified, written, and made durable BEFORE this call. Refuses regression and values
 * beyond the file's block count; stamps updatedAt. The optional digestCheckpoint (V13-PR05)
 * is persisted atomically with the checkpoint and MUST cover exactly these committed
 * blocks (enforced); omitting it clears the file's checkpoint (it could not cover the new
 * high-water mark). Returns a new journal (the checksum is stale afterwards and recomputed
 * by encodeJournal).
 */
export function commitBlocks(
  j: DurableJournal,
  fileIdx: number,
  committedBlocks: number,
  nowMs: number,
  digestCheckpoint?: JournalDigestCheckpoint,
): DurableJournal {
  if (!Number.isInteger(fileIdx) || fileIdx < 0 || fileIdx >= j.files.length) {
    throw new Error(`journal: no file ${fileIdx} in journal`);
  }
  const f = j.files[fileIdx]!;
  if (!Number.isInteger(committedBlocks) || committedBlocks < 0 || committedBlocks > f.blocks) {
    throw new Error(
      `journal: committedBlocks ${committedBlocks} out of range for file ${fileIdx} (blocks ${f.blocks})`,
    );
  }
  if (committedBlocks < f.committedBlocks) {
    throw new Error(
      `journal: committed progress may not regress (file ${fileIdx}: ${f.committedBlocks} -> ${committedBlocks})`,
    );
  }
  if (digestCheckpoint !== undefined && digestCheckpoint.committedBlocks !== committedBlocks) {
    throw new Error(
      `journal: digestCheckpoint block count ${digestCheckpoint.committedBlocks} does not match committedBlocks ${committedBlocks}`,
    );
  }
  return {
    schemaVersion: j.schemaVersion,
    transferId: j.transferId,
    manifestFingerprint: j.manifestFingerprint,
    protocolVersion: j.protocolVersion,
    resumeVersion: j.resumeVersion,
    blockSize: j.blockSize,
    createdAt: j.createdAt,
    updatedAt: nowMs,
    sourceIdentity: j.sourceIdentity,
    destinationIdentity: j.destinationIdentity,
    files: j.files.map((entry, i) => {
      if (i !== fileIdx) return entry;
      const updated = { ...entry, committedBlocks };
      delete updated.digestCheckpoint;
      if (digestCheckpoint !== undefined) updated.digestCheckpoint = digestCheckpoint;
      return updated;
    }),
    ...(j.resumeSecret !== undefined ? { resumeSecret: j.resumeSecret } : {}),
  };
}

/** Durable byte count a file's checkpoint claims: whole committed blocks, final block capped. */
export function committedBytes(j: DurableJournal, fileIdx: number): number {
  if (!Number.isInteger(fileIdx) || fileIdx < 0 || fileIdx >= j.files.length) {
    throw new Error(`journal: no file ${fileIdx} in journal`);
  }
  const f = j.files[fileIdx]!;
  return Math.min(f.committedBlocks * f.blockSize, f.size);
}
