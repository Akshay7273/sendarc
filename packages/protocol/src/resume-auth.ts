/**
 * Cross-session authenticated resume protocol (V13-PR07). Design: docs/adr/0005.
 *
 * The TypeScript twin of `packages/wire/resumeauth.go`: derives the transfer-scoped resume
 * credential from the ORIGINAL authenticated session master, persists it as an opaque
 * 256-bit envelope, and runs the transport-agnostic mutual-authentication handshake that
 * lets the same original sender and receiver resume a transfer after the original
 * process/session is gone — without persisting the master, the directional keys, the AEAD
 * salts/counters, or the invite code.
 *
 * The engine is deliberately independent of the transport that carries its messages (PR08
 * owns discovery/reconnection): both sides already know the transferId, the canonical
 * manifest fingerprint, their stable role, and the resumeSecret; the transferId and
 * fingerprint are NEVER transmitted — they enter only through the canonical transcript.
 * The server/network cannot forge a resume authentication: proofs are HMAC-SHA256 under
 * role-separated subkeys over a transcript bound to fresh per-attempt nonces, the
 * transferId, the manifest fingerprint, and the resume-auth version.
 *
 * Must produce byte-identical outputs to the Go twin; pinned by
 * docs/test-vectors/resume-auth.json.
 */

import { PROTOCOL_VERSION } from './constants.js';
import {
  bytesToBase64url,
  base64urlToBytes,
  bytesToHex,
  hexToBytes,
  concatBytes,
  utf8,
  constantTimeEqual,
} from './bytes.js';
import { hkdfSha256, hmacSha256 } from './webcrypto.js';
import { deriveTransferKeys, type TransferKeys } from './keyschedule.js';

/** The two stable roles, matching the wire roles (offerer = sender, joiner = receiver). */
export type ResumeRole = 'offerer' | 'joiner';

/** Version of the cross-session resume-auth protocol (bound into derivation + transcript). */
export const RESUME_AUTH_VERSION = 1;

/**
 * Capability name announced in caps (`features`) that gates the resume-auth protocol within
 * sendbeam/1. Defined, documented, and negotiation-tested here but deliberately NOT
 * advertised in production defaults: automatic cross-session resume stays disabled until
 * PR08 / lead approval.
 */
export const RESUME_AUTH_CAPABILITY = 'resume-auth-v1';

/** Fresh challenge nonce length, one per peer per attempt (256 bits). */
export const RESUME_NONCE_BYTES = 32;
/** HMAC-SHA256 proof length. */
export const RESUME_PROOF_BYTES = 32;
/** Derived transfer-scoped credential length (256 bits). */
export const RESUME_SECRET_BYTES = 32;
/** The authenticated session master length (the SendBeam handshake always derives 32). */
export const RESUME_MASTER_BYTES = 32;

/**
 * Shared semantic ceiling for one resume-auth wire message, mirrored in Go
 * (MaxResumeAuthMessageBytes). The largest legitimate message is resume_challenge: ~two
 * 43-char base64url fields plus JSON framing, well under 256 bytes. 1024 bounds
 * attacker-controlled payloads before any JSON/base64 allocation while leaving ample
 * headroom for future versioned fields.
 */
export const MAX_RESUME_AUTH_MESSAGE_BYTES = 1024;

/** Canonical unpadded base64url length of n bytes (4*ceil(n/3) minus omitted padding). */
function b64urlLen(n: number): number {
  const groups = Math.ceil(n / 3);
  const pad = (3 - (n % 3)) % 3;
  return 4 * groups - pad;
}

/** Domain-separated HKDF info strings (ADR 0005 §3/§6.4/§7). */
const INFO_RESUME_ROOT = `${PROTOCOL_VERSION} resume root`;
const INFO_RESUME_SECRET = `${PROTOCOL_VERSION} resume secret`;
const INFO_RESUME_PROOF_OFFERER = `${PROTOCOL_VERSION} resume offerer proof`;
const INFO_RESUME_PROOF_JOINER = `${PROTOCOL_VERSION} resume joiner proof`;
const INFO_RESUME_MASTER = `${PROTOCOL_VERSION} resume master`;
const RESUME_TRANSCRIPT_DOMAIN = `${PROTOCOL_VERSION} resume-auth`;

/** Per-message proof tags appended to the transcript (ADR 0005 §6.4). */
const RESUME_PROOF_TAG_JOINER = 0x01; // resume_challenge
const RESUME_PROOF_TAG_OFFERER = 0x02; // resume_confirm
const RESUME_PROOF_TAG_READY = 0x03; // resume_ready

const isLowerHex = (s: string, n: number): boolean => s.length === n && /^[0-9a-f]+$/.test(s);

/** u32 big-endian — the fixed-width version encoding in derivation + transcript. */
function u32be(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff)
    throw new RangeError(`value ${n} is not a u32`);
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

/**
 * Derive the transient, transfer-scoped resume root from the ORIGINAL authenticated session
 * master: `HKDF-SHA256(master, nil, "sendbeam/1 resume root", 32)`.
 *
 * The root is deliberately narrow: it exists only to derive transfer-specific resume
 * secrets and must never be persisted, logged, or returned to the UI. The original master
 * cannot be recovered from it (HKDF one-wayness), which is what lets the browser main
 * thread pass the root into the transfer worker without leaking the session master.
 */
export async function deriveResumeRoot(master: Uint8Array): Promise<Uint8Array> {
  // The SendBeam handshake master is exactly 32 bytes (deriveMaster outLen). Anything else
  // is a miswired caller, not a valid master: reject it rather than derive a low-entropy or
  // wrong-length root from it.
  if (master.length !== RESUME_MASTER_BYTES) {
    throw new Error(
      `resume: original session master must be ${RESUME_MASTER_BYTES} bytes, got ${master.length}`,
    );
  }
  return hkdfSha256(master, new Uint8Array(0), utf8(INFO_RESUME_ROOT), RESUME_SECRET_BYTES);
}

/**
 * Derive the 256-bit transfer-scoped resume credential from the resume root:
 *
 * `HKDF-SHA256(resumeRoot, nil, "sendbeam/1 resume secret" || u32be(version) || transferId(16) || manifestFingerprint(32), 32)`
 *
 * transferId must be validated 32 lowercase hex chars and manifestFingerprint validated 64
 * lowercase hex chars; anything else is rejected before any derivation. The version, the
 * transfer id, and the manifest fingerprint are bound with explicit fixed-width binary
 * fields (no ambiguous delimiters, no ad-hoc string concatenation).
 */
export async function deriveResumeSecret(
  resumeRoot: Uint8Array,
  version: number,
  transferId: string,
  manifestFingerprint: string,
): Promise<Uint8Array> {
  // The resume root is the 32-byte output of deriveResumeRoot; a different length means the
  // caller passed something else (a raw master, a string, an empty slice).
  if (resumeRoot.length !== RESUME_SECRET_BYTES) {
    throw new Error(
      `resume: resume root must be ${RESUME_SECRET_BYTES} bytes, got ${resumeRoot.length}`,
    );
  }
  if (version !== RESUME_AUTH_VERSION) {
    throw new Error(`resume: unsupported resume-auth version ${version}`);
  }
  if (!isLowerHex(transferId, 32)) {
    throw new Error('resume: transferId must be 32 lowercase hex characters');
  }
  if (!isLowerHex(manifestFingerprint, 64)) {
    throw new Error('resume: manifestFingerprint must be 64 lowercase hex characters');
  }
  const info = concatBytes(
    utf8(INFO_RESUME_SECRET),
    u32be(version),
    hexToBytes(transferId),
    hexToBytes(manifestFingerprint),
  );
  return hkdfSha256(resumeRoot, new Uint8Array(0), info, RESUME_SECRET_BYTES);
}

/** The persisted shape of the transfer-scoped credential (ADR 0005 §4). */
export interface ResumeSecretEnvelope {
  version: number;
  /** Exactly 64 lowercase hex characters (32 bytes). */
  value: string;
}

/** Wrap a derived 32-byte secret into its persisted envelope. */
export function encodeResumeSecretEnvelope(secret: Uint8Array): ResumeSecretEnvelope {
  if (secret.length !== RESUME_SECRET_BYTES) {
    throw new Error(`resume: resume secret must be ${RESUME_SECRET_BYTES} bytes`);
  }
  return { version: RESUME_AUTH_VERSION, value: bytesToHex(secret) };
}

/**
 * Strictly decode a persisted envelope: version must be exactly RESUME_AUTH_VERSION and the
 * value exactly 64 lowercase hex characters (32 bytes). An arbitrary old opaque value is
 * never reinterpreted as a valid key.
 */
export function decodeResumeSecretEnvelope(e: ResumeSecretEnvelope | undefined): Uint8Array {
  if (e === undefined) throw new Error('resume: missing resume secret envelope');
  if (e.version !== RESUME_AUTH_VERSION) {
    throw new Error(`resume: unsupported resume secret version ${e.version}`);
  }
  if (!isLowerHex(e.value, 64)) {
    throw new Error('resume: resume secret must be 64 lowercase hex characters');
  }
  const out = hexToBytes(e.value);
  if (out.length !== RESUME_SECRET_BYTES) {
    throw new Error('resume: malformed resume secret value');
  }
  return out;
}

/**
 * Canonical binary transcript for one resume-auth attempt (ADR 0005 §6.3):
 *
 * `"sendbeam/1 resume-auth" || u32be(version) || transferId(16) || manifestFingerprint(32) || offererNonce(32) || joinerNonce(32)`
 *
 * Both peers compute the same bytes; the nonce positions are role-fixed, which is part of
 * the role binding. Lengths are validated before construction.
 */
export async function resumeTranscript(
  version: number,
  transferId: string,
  manifestFingerprint: string,
  offererNonce: Uint8Array,
  joinerNonce: Uint8Array,
): Promise<Uint8Array> {
  if (version !== RESUME_AUTH_VERSION) {
    throw new Error(`resume: unsupported resume-auth version ${version}`);
  }
  if (!isLowerHex(transferId, 32)) {
    throw new Error('resume: transferId must be 32 lowercase hex characters');
  }
  if (!isLowerHex(manifestFingerprint, 64)) {
    throw new Error('resume: manifestFingerprint must be 64 lowercase hex characters');
  }
  if (offererNonce.length !== RESUME_NONCE_BYTES) {
    throw new Error(`resume: offerer nonce must be ${RESUME_NONCE_BYTES} bytes`);
  }
  if (joinerNonce.length !== RESUME_NONCE_BYTES) {
    throw new Error(`resume: joiner nonce must be ${RESUME_NONCE_BYTES} bytes`);
  }
  return concatBytes(
    utf8(RESUME_TRANSCRIPT_DOMAIN),
    u32be(version),
    hexToBytes(transferId),
    hexToBytes(manifestFingerprint),
    offererNonce,
    joinerNonce,
  );
}

async function proofKey(secret: Uint8Array, info: string): Promise<Uint8Array> {
  if (secret.length !== RESUME_SECRET_BYTES) {
    throw new Error(`resume: resume secret must be ${RESUME_SECRET_BYTES} bytes`);
  }
  return hkdfSha256(secret, new Uint8Array(0), utf8(info), RESUME_PROOF_BYTES);
}

async function proofWithTag(
  secret: Uint8Array,
  transcript: Uint8Array,
  tag: number,
  info: string,
): Promise<Uint8Array> {
  const key = await proofKey(secret, info);
  return hmacSha256(key, concatBytes(transcript, new Uint8Array([tag])));
}

/** Offerer proof: `HMAC-SHA256(K_offerer, transcript || 0x02)` (ADR 0005 §6.4). */
export function resumeOffererProof(
  secret: Uint8Array,
  transcript: Uint8Array,
): Promise<Uint8Array> {
  return proofWithTag(secret, transcript, RESUME_PROOF_TAG_OFFERER, INFO_RESUME_PROOF_OFFERER);
}

/** Joiner proof: `HMAC-SHA256(K_joiner, transcript || 0x01)` (ADR 0005 §6.4). */
export function resumeJoinerProof(secret: Uint8Array, transcript: Uint8Array): Promise<Uint8Array> {
  return proofWithTag(secret, transcript, RESUME_PROOF_TAG_JOINER, INFO_RESUME_PROOF_JOINER);
}

/** Joiner final key-confirmation: `HMAC-SHA256(K_joiner, transcript || 0x03)` (ADR 0005 §6.4). */
export function resumeReadyProof(secret: Uint8Array, transcript: Uint8Array): Promise<Uint8Array> {
  return proofWithTag(secret, transcript, RESUME_PROOF_TAG_READY, INFO_RESUME_PROOF_JOINER);
}

/**
 * Fresh resumed session master after MUTUAL authentication:
 * `HKDF-SHA256(resumeSecret, nil, "sendbeam/1 resume master" || transcript, 32)`. Feed it
 * into {@link deriveTransferKeys} for the fresh directional keys (ADR 0005 §7).
 */
export async function resumeSessionMaster(
  secret: Uint8Array,
  transcript: Uint8Array,
): Promise<Uint8Array> {
  if (secret.length !== RESUME_SECRET_BYTES) {
    throw new Error(`resume: resume secret must be ${RESUME_SECRET_BYTES} bytes`);
  }
  return hkdfSha256(
    secret,
    new Uint8Array(0),
    concatBytes(utf8(INFO_RESUME_MASTER), transcript),
    RESUME_SECRET_BYTES,
  );
}

/** Constant-time proof verification (lengths checked before comparison). */
async function verifyProof(
  got: Uint8Array,
  secret: Uint8Array,
  transcript: Uint8Array,
  tag: number,
  info: string,
): Promise<boolean> {
  if (got.length !== RESUME_PROOF_BYTES) return false;
  const expected = await proofWithTag(secret, transcript, tag, info);
  return constantTimeEqual(expected, got);
}

// ---------------------------------------------------------------------------
// Message codec (strict, bounded)
// ---------------------------------------------------------------------------

/** One resume-auth message tag (ADR 0005 §6.1). */
export type ResumeMsgType = 'resume_init' | 'resume_challenge' | 'resume_confirm' | 'resume_ready';

export const RESUME_MSG_INIT: ResumeMsgType = 'resume_init';
export const RESUME_MSG_CHALLENGE: ResumeMsgType = 'resume_challenge';
export const RESUME_MSG_CONFIRM: ResumeMsgType = 'resume_confirm';
export const RESUME_MSG_READY: ResumeMsgType = 'resume_ready';

/** One resume-auth message; nonce/proof are base64url (no padding). */
export interface ResumeMessage {
  type: ResumeMsgType;
  version: number;
  role: ResumeRole;
  nonce?: string;
  proof?: string;
}

/** Encode one resume-auth message to canonical wire JSON (byte-identical to JSON.stringify). */
export function encodeResumeMessage(m: ResumeMessage): Uint8Array {
  validateResumeMessage(m);
  return utf8(JSON.stringify(m));
}

function validateResumeMessage(m: ResumeMessage): void {
  if (m.version !== RESUME_AUTH_VERSION) {
    throw new Error(`resume: unsupported resume-auth version ${m.version}`);
  }
  switch (m.type) {
    case RESUME_MSG_INIT:
      if (m.role !== 'offerer') throw new Error('resume: resume_init must carry role "offerer"');
      requireB64Len(m.nonce, RESUME_NONCE_BYTES, 'resume_init nonce');
      if (m.proof !== undefined) throw new Error('resume: resume_init must not carry a proof');
      break;
    case RESUME_MSG_CHALLENGE:
      if (m.role !== 'joiner') throw new Error('resume: resume_challenge must carry role "joiner"');
      requireB64Len(m.nonce, RESUME_NONCE_BYTES, 'resume_challenge nonce');
      requireB64Len(m.proof, RESUME_PROOF_BYTES, 'resume_challenge proof');
      break;
    case RESUME_MSG_CONFIRM:
      if (m.role !== 'offerer') throw new Error('resume: resume_confirm must carry role "offerer"');
      if (m.nonce !== undefined) throw new Error('resume: resume_confirm must not carry a nonce');
      requireB64Len(m.proof, RESUME_PROOF_BYTES, 'resume_confirm proof');
      break;
    case RESUME_MSG_READY:
      if (m.role !== 'joiner') throw new Error('resume: resume_ready must carry role "joiner"');
      if (m.nonce !== undefined) throw new Error('resume: resume_ready must not carry a nonce');
      requireB64Len(m.proof, RESUME_PROOF_BYTES, 'resume_ready proof');
      break;
    default:
      throw new Error(`resume: unknown message type ${String(m.type)}`);
  }
}

function requireB64Len(s: string | undefined, n: number, what: string): void {
  if (s === undefined) throw new Error(`resume: missing ${what}`);
  // The canonical unpadded base64url length is checked FIRST — before any base64 decoding —
  // so a huge nonce/proof string is rejected without allocation.
  if (s.length !== b64urlLen(n)) {
    throw new Error(`resume: ${what} must be ${n} bytes`);
  }
  // Reject any character outside the base64url alphabet before decoding (padded '=' spellings
  // are caught here as well, since '=' is not in the alphabet).
  if (!/^[A-Za-z0-9_-]+$/.test(s)) {
    throw new Error(`resume: non-base64url ${what} encoding`);
  }
  const decoded = base64urlToBytes(s);
  if (decoded.length !== n) throw new Error(`resume: ${what} must be ${n} bytes`);
  // Re-encode to reject non-canonical spellings of the same bytes.
  if (bytesToBase64url(decoded) !== s) throw new Error(`resume: non-canonical ${what} encoding`);
}

/**
 * Strictly decode one resume-auth message: unknown fields, missing fields, wrong types,
 * invalid versions/roles, non-canonical encodings, wrong nonce/proof lengths, and trailing
 * data are all rejected. The payload ceiling is enforced BEFORE any JSON parsing, and every
 * binary field's canonical base64url length is enforced before any base64 decoding, so there
 * are no attacker-controlled unbounded allocations.
 */
export function decodeResumeMessage(payload: Uint8Array): ResumeMessage {
  if (payload.length > MAX_RESUME_AUTH_MESSAGE_BYTES) {
    throw new Error(`resume: message exceeds ${MAX_RESUME_AUTH_MESSAGE_BYTES} bytes`);
  }
  let obj: unknown;
  try {
    obj = JSON.parse(new TextDecoder().decode(payload));
  } catch {
    throw new Error('resume: invalid JSON');
  }
  if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) {
    throw new Error('resume: not an object');
  }
  const m = obj as Record<string, unknown>;
  const allowed = ['type', 'version', 'role', 'nonce', 'proof'];
  for (const key of Object.keys(m)) {
    if (!allowed.includes(key)) throw new Error(`resume: unexpected field ${key}`);
  }
  const type = m.type;
  if (typeof type !== 'string') throw new Error('resume: missing type');
  const version = m.version;
  if (typeof version !== 'number' || !Number.isInteger(version))
    throw new Error('resume: missing version');
  const role = m.role;
  if (typeof role !== 'string') throw new Error('resume: missing role');
  if (role !== 'offerer' && role !== 'joiner') throw new Error(`resume: invalid role ${role}`);
  const nonce =
    m.nonce === undefined
      ? undefined
      : typeof m.nonce === 'string'
        ? m.nonce
        : (() => {
            throw new Error('resume: nonce is not a string');
          })();
  const proof =
    m.proof === undefined
      ? undefined
      : typeof m.proof === 'string'
        ? m.proof
        : (() => {
            throw new Error('resume: proof is not a string');
          })();
  const msg: ResumeMessage = {
    type: type as ResumeMsgType,
    version,
    role,
    ...(nonce !== undefined ? { nonce } : {}),
    ...(proof !== undefined ? { proof } : {}),
  };
  validateResumeMessage(msg);
  return msg;
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

/** Local resume context one peer supplies; transferId and fingerprint are never sent. */
export interface ResumeAuthContext {
  /** Resume-auth protocol version (RESUME_AUTH_VERSION). */
  version: number;
  /** Stable 128-bit hex id of the transfer being resumed. */
  transferId: string;
  /** Canonical manifest fingerprint of the transfer. */
  manifestFingerprint: string;
  /** This peer's stable role: offerer (sender) or joiner (receiver). */
  role: ResumeRole;
  /** The 32-byte transfer-scoped credential derived from the ORIGINAL session. */
  resumeSecret: Uint8Array;
  /** Fresh random nonce source (32 bytes); defaults to crypto.getRandomValues. */
  nonceSource?(n: number): Uint8Array;
}

/** One Handle result: the outbound message to send (if any) and/or the final result. */
export interface ResumeAuthOutcome {
  out?: ResumeMessage;
  result?: ResumeAuthResult;
}

/** All-or-nothing outcome of a successful mutual authentication. */
export interface ResumeAuthResult {
  role: ResumeRole;
  transferId: string;
  /** Fresh resumed directional keys (already through the standard derivation). */
  keys: TransferKeys;
  /** Fresh-session counter start (0) — safe only because the keys+salts are new. */
  sendCounter: number;
  recvCounter: number;
}

type ResumeAuthState =
  'idle' | 'await-challenge' | 'await-ready' | 'await-confirm' | 'done' | 'failed';

/**
 * One transport-agnostic mutual-authentication attempt. The offerer calls {@link start}
 * (emits resume_init); both sides feed inbound messages with {@link handle} and read the
 * outbound message and the final result from its return.
 */
export class ResumeAuthSession {
  private readonly ctx: ResumeAuthContext;
  private state: ResumeAuthState = 'idle';
  private offererNonce: Uint8Array | undefined;
  private joinerNonce: Uint8Array | undefined;
  private transcript: Uint8Array | undefined;
  private result: ResumeAuthResult | undefined;
  /**
   * A small fixed snapshot per handshake step: the canonical encoding of each accepted
   * inbound message plus the exact outbound snapshot generated for it (undefined when the
   * accepted message had no response). An exact duplicate of any accepted message is
   * idempotently re-answered with the SAME snapshot for the rest of the session (including
   * after done) — never a fresh nonce/proof for a retry; any other message of a type that
   * was already accepted is a conflicting duplicate and fails closed.
   */
  private steps: { accepted: Uint8Array; responded: Uint8Array | undefined }[] = [];
  private settledErr: Error | undefined;
  /**
   * Serializes ALL inbound handshake processing in arrival order (Blocker 4): WebCrypto
   * awaits inside acceptInit/acceptChallenge make bare async handlers racy — two concurrent
   * handle(sameInit) calls could both observe idle and mint different joiner nonces. The
   * promise chain guarantees exactly one inbound message mutates state at a time, that an
   * exact duplicate concurrent message receives the SAME snapshotted response, that a
   * conflicting concurrent duplicate fails closed deterministically, and that a failure is
   * terminal (later queued work sees `failed` and cannot resurrect the session).
   */
  private queue: Promise<void> = Promise.resolve();

  constructor(ctx: ResumeAuthContext) {
    if (ctx.version !== RESUME_AUTH_VERSION) {
      throw new Error(`resume: unsupported resume-auth version ${ctx.version}`);
    }
    if (!isLowerHex(ctx.transferId, 32)) {
      throw new Error('resume: transferId must be 32 lowercase hex characters');
    }
    if (!isLowerHex(ctx.manifestFingerprint, 64)) {
      throw new Error('resume: manifestFingerprint must be 64 lowercase hex characters');
    }
    if (ctx.role !== 'offerer' && ctx.role !== 'joiner') {
      throw new Error(`resume: invalid role ${String(ctx.role)}`);
    }
    if (ctx.resumeSecret.length !== RESUME_SECRET_BYTES) {
      throw new Error(
        `resume: missing or invalid resume secret (${ctx.resumeSecret.length} bytes)`,
      );
    }
    this.ctx = { ...ctx, version: RESUME_AUTH_VERSION };
  }

  /**
   * Begin the handshake. The offerer generates its fresh nonce and returns resume_init; the
   * joiner cannot initiate and throws.
   */
  start(): ResumeMessage {
    if (this.state !== 'idle') throw new Error(`resume: start called in state ${this.state}`);
    if (this.ctx.role !== 'offerer') throw new Error('resume: joiner cannot start the handshake');
    const nonce = this.randomNonce();
    this.offererNonce = nonce;
    this.state = 'await-challenge';
    return {
      type: RESUME_MSG_INIT,
      version: RESUME_AUTH_VERSION,
      role: 'offerer',
      nonce: bytesToBase64url(nonce),
    };
  }

  /**
   * Feed one inbound message. Returns the outbound message to send (if any) and, when mutual
   * authentication completes, the fresh resumed keys. A message from an impossible state, a
   * conflicting duplicate, or a failed proof settles the session failed. All inbound
   * processing is serialized in arrival order (see {@link queue}); failures are terminal and
   * later queued work cannot resurrect or overwrite the failed state.
   */
  async handle(payload: Uint8Array): Promise<ResumeAuthOutcome> {
    const run = this.queue.then(() => this.handleSerialized(payload));
    // The chain always continues: a rejection is delivered to the caller of `run` and the
    // queue swallows it so no unhandled rejection leaks and later queued work still runs
    // (it will observe the terminal `failed` state and fail closed itself).
    this.queue = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  private async handleSerialized(payload: Uint8Array): Promise<ResumeAuthOutcome> {
    if (this.state === 'failed') throw this.settledErr;
    try {
      const msg = decodeResumeMessage(payload);
      // Idempotent replay first: an exact duplicate of ANY accepted message (current or
      // settled step) is re-answered with the SAME snapshot for the rest of the session —
      // including after done — so a lost response is retransmitted identically, never with a
      // fresh nonce/proof. A snapshot with no response (offerer's accepted ready) is a
      // settled no-op; a snapshot that produced a response re-answers it with the same
      // bytes. (A decode failure of our own snapshot cannot happen; if it somehow did, the
      // catch below settles the session failed rather than leaving a half-processed state.)
      const step = this.steps.find((s) => bytesEqual(payload, s.accepted));
      if (step) {
        if (step.responded === undefined) {
          return this.result === undefined ? {} : { result: this.result };
        }
        const out = decodeResumeMessage(step.responded);
        return this.result === undefined ? { out } : { out, result: this.result };
      }
      if (this.ctx.role === 'offerer') return await this.handleOfferer(msg, payload);
      return await this.handleJoiner(msg, payload);
    } catch (e) {
      // EVERY inbound-processing failure after construction is terminal (Blocker 1): a
      // decode error (oversized/malformed JSON/unknown field/bad version/role/noncanonical
      // nonce/proof), a proof failure, an out-of-state message, or an internal crypto
      // failure settles the session `failed`. Go behaves the same (DecodeResumeMessage
      // failure calls failLocked). A later valid message must observe the SAME terminal
      // failure — never continue a partially-processed handshake. If a handler already
      // failed the session (it throws `this.fail(...)`), rethrow the settled error verbatim
      // instead of double-wrapping it.
      // `settledErr` is set exactly when the session is failed (fail() sets both), and this
      // sidesteps TS control-flow narrowing that would otherwise reject the state check.
      if (this.settledErr !== undefined) throw this.settledErr;
      throw this.fail(e instanceof Error ? e : new Error(String(e)));
    }
  }

  private async handleOfferer(msg: ResumeMessage, payload: Uint8Array): Promise<ResumeAuthOutcome> {
    switch (msg.type) {
      case RESUME_MSG_CHALLENGE: {
        // A challenge that is not an exact duplicate of the accepted one is a conflicting
        // duplicate (challenge replacement after proof is forbidden).
        if (this.state !== 'await-challenge') {
          throw this.fail(new Error('resume: conflicting duplicate resume_challenge'));
        }
        return this.acceptChallenge(msg, payload);
      }
      case RESUME_MSG_READY: {
        if (this.state !== 'await-ready') {
          throw this.fail(new Error(`resume: unexpected resume_ready in state ${this.state}`));
        }
        const proof = base64urlToBytes(msg.proof!);
        if (
          !(await verifyProof(
            proof,
            this.ctx.resumeSecret,
            this.transcript!,
            RESUME_PROOF_TAG_READY,
            INFO_RESUME_PROOF_JOINER,
          ))
        ) {
          throw this.fail(new Error('resume: joiner ready proof verification failed'));
        }
        // Snapshot the accepted ready (no outbound response): an exact duplicate after done
        // is a settled no-op; a different ready is a conflicting duplicate that fails.
        this.steps.push({ accepted: payload.slice(), responded: undefined });
        this.state = 'done';
        const result = await this.buildResult();
        this.result = result;
        return { result };
      }
      default:
        throw this.fail(new Error(`resume: offerer received unexpected ${msg.type}`));
    }
  }

  private async acceptChallenge(
    msg: ResumeMessage,
    payload: Uint8Array,
  ): Promise<ResumeAuthOutcome> {
    this.joinerNonce = base64urlToBytes(msg.nonce!);
    this.transcript = await resumeTranscript(
      this.ctx.version,
      this.ctx.transferId,
      this.ctx.manifestFingerprint,
      this.offererNonce!,
      this.joinerNonce,
    );
    const proof = base64urlToBytes(msg.proof!);
    if (
      !(await verifyProof(
        proof,
        this.ctx.resumeSecret,
        this.transcript,
        RESUME_PROOF_TAG_JOINER,
        INFO_RESUME_PROOF_JOINER,
      ))
    ) {
      throw this.fail(new Error('resume: joiner proof verification failed'));
    }
    const offererProof = await resumeOffererProof(this.ctx.resumeSecret, this.transcript);
    const confirm: ResumeMessage = {
      type: RESUME_MSG_CONFIRM,
      version: RESUME_AUTH_VERSION,
      role: 'offerer',
      proof: bytesToBase64url(offererProof),
    };
    // Snapshot both the accepted challenge and the generated confirm so a retransmission is
    // re-answered with the SAME proof (never a fresh nonce/proof).
    this.steps.push({ accepted: payload.slice(), responded: encodeResumeMessage(confirm) });
    this.state = 'await-ready';
    return { out: confirm };
  }

  private async handleJoiner(msg: ResumeMessage, payload: Uint8Array): Promise<ResumeAuthOutcome> {
    switch (msg.type) {
      case RESUME_MSG_INIT: {
        // A second, different init (challenge replacement after proof is forbidden) is a
        // conflicting duplicate; an exact duplicate was already re-answered above.
        if (this.state !== 'idle') {
          throw this.fail(new Error('resume: conflicting duplicate resume_init'));
        }
        return this.acceptInit(msg, payload);
      }
      case RESUME_MSG_CONFIRM: {
        if (this.state !== 'await-confirm') {
          throw this.fail(new Error('resume: conflicting duplicate resume_confirm'));
        }
        const proof = base64urlToBytes(msg.proof!);
        if (
          !(await verifyProof(
            proof,
            this.ctx.resumeSecret,
            this.transcript!,
            RESUME_PROOF_TAG_OFFERER,
            INFO_RESUME_PROOF_OFFERER,
          ))
        ) {
          throw this.fail(new Error('resume: offerer proof verification failed'));
        }
        const readyProof = await resumeReadyProof(this.ctx.resumeSecret, this.transcript!);
        const ready: ResumeMessage = {
          type: RESUME_MSG_READY,
          version: RESUME_AUTH_VERSION,
          role: 'joiner',
          proof: bytesToBase64url(readyProof),
        };
        // Snapshot the accepted confirm and its ready response: the settled joiner re-answers
        // an exact duplicate confirm with the SAME ready (a lost ready never stalls the
        // offerer); a different confirm is a conflicting duplicate that fails.
        this.steps.push({ accepted: payload.slice(), responded: encodeResumeMessage(ready) });
        this.state = 'done';
        const result = await this.buildResult();
        this.result = result;
        return { out: ready, result };
      }
      default:
        throw this.fail(new Error(`resume: joiner received unexpected ${msg.type}`));
    }
  }

  private async acceptInit(msg: ResumeMessage, payload: Uint8Array): Promise<ResumeAuthOutcome> {
    this.offererNonce = base64urlToBytes(msg.nonce!);
    const nonce = this.randomNonce();
    this.joinerNonce = nonce;
    this.transcript = await resumeTranscript(
      this.ctx.version,
      this.ctx.transferId,
      this.ctx.manifestFingerprint,
      this.offererNonce,
      this.joinerNonce,
    );
    const joinerProof = await resumeJoinerProof(this.ctx.resumeSecret, this.transcript);
    const challenge: ResumeMessage = {
      type: RESUME_MSG_CHALLENGE,
      version: RESUME_AUTH_VERSION,
      role: 'joiner',
      nonce: bytesToBase64url(nonce),
      proof: bytesToBase64url(joinerProof),
    };
    this.steps.push({ accepted: payload.slice(), responded: encodeResumeMessage(challenge) });
    this.state = 'await-confirm';
    return { out: challenge };
  }

  private async buildResult(): Promise<ResumeAuthResult> {
    const master = await resumeSessionMaster(this.ctx.resumeSecret, this.transcript!);
    const keys = await deriveTransferKeys(master);
    return {
      role: this.ctx.role,
      transferId: this.ctx.transferId,
      keys,
      sendCounter: 0,
      recvCounter: 0,
    };
  }

  private randomNonce(): Uint8Array {
    if (this.ctx.nonceSource) {
      const b = this.ctx.nonceSource(RESUME_NONCE_BYTES);
      if (b.length !== RESUME_NONCE_BYTES) {
        throw new Error(
          `resume: nonce source returned ${b.length} bytes, want ${RESUME_NONCE_BYTES}`,
        );
      }
      return b;
    }
    return crypto.getRandomValues(new Uint8Array(RESUME_NONCE_BYTES));
  }

  private fail(err: Error): Error {
    if (!this.settledErr) this.settledErr = err;
    this.state = 'failed';
    return err;
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return constantTimeEqual(a, b);
}

/**
 * Whether both peers advertised the resume-auth-v1 capability. The security invariant that
 * MUST hold (ADR 0005 §2/§9) is: capability absent, stripped, or otherwise untrusted =>
 * authenticated cross-session resume is UNAVAILABLE — never a fallback to unauthenticated
 * durable progress reuse. PR08 owns the discovery path that obtains the authenticated
 * capability state for a cross-session attempt; this predicate only computes the boolean
 * from whatever features are presented.
 */
export function negotiateResumeAuth(
  localFeatures: readonly string[],
  remoteFeatures: readonly string[],
): boolean {
  return (
    localFeatures.includes(RESUME_AUTH_CAPABILITY) &&
    remoteFeatures.includes(RESUME_AUTH_CAPABILITY)
  );
}
