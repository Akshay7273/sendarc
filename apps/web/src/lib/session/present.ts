/**
 * Presentation helpers for the rendezvous UI — the pure, DOM-free functions the Svelte
 * component leans on. Keeping them here (rather than inline in App.svelte) makes the
 * fingerprint, link, and formatting logic unit-testable without a browser harness, and lets
 * the fingerprint stay provably identical to the Go CLI's short authentication string.
 */

import {
  bytesToHex,
  concatBytes,
  sha256,
  utf8,
  type CapsPayload,
  type RendezvousPhase,
} from '@sendarc/protocol';

/** The minimal shape describeError reads — satisfied by a RendezvousError instance. */
export interface ErrorLike {
  readonly code: string;
  readonly message: string;
}

/** Human labels for each handshake phase, shown live as the connection progresses. */
const PHASE_LABEL: Record<RendezvousPhase, string> = {
  idle: 'Starting…',
  allocating: 'Reserving a room…',
  waiting: 'Waiting for the other side…',
  handshaking: 'Establishing a secure channel…',
  confirming: 'Confirming the code…',
  'exchanging-caps': 'Exchanging capabilities…',
  established: 'Connected',
  failed: 'Failed',
};

export function phaseLabel(p: RendezvousPhase): string {
  return PHASE_LABEL[p] ?? p;
}

/**
 * Short authentication string derived from the master key: a domain-separated hash (so no
 * raw key bytes are exposed) truncated to 32 bits and shown as two hex groups. It is byte
 * -for-byte identical to the Go CLI's fingerprint, so a browser peer and a terminal peer
 * can read the same value to each other as an out-of-band check on top of SPAKE2.
 */
export async function sasFingerprint(master: Uint8Array): Promise<string> {
  const digest = await sha256(concatBytes(utf8('sendarc/sas\0'), master));
  const hex = bytesToHex(digest.subarray(0, 4));
  return `${hex.slice(0, 4)} ${hex.slice(4, 8)}`;
}

/** The current page URL with the invite code carried in the fragment (never sent to a server). */
export function inviteLinkFor(href: string, code: string): string {
  const u = new URL(href);
  u.hash = code;
  return u.toString();
}

/** The invite code embedded in a URL fragment, or '' if there is none. */
export function codeFromHash(hash: string): string {
  return hash.trim().replace(/^#/, '').trim();
}

/** Byte counts as IEC units on exact multiples, matching the CLI's humanBytes. */
export function humanBytes(n: number): string {
  if (n >= 1 << 20 && n % (1 << 20) === 0) return `${n >> 20} MiB`;
  if (n >= 1 << 10 && n % (1 << 10) === 0) return `${n >> 10} KiB`;
  return `${n} B`;
}

export function describeCaps(c: CapsPayload): string {
  return `${c.version} · ${humanBytes(c.maxFrame)} frames · ${humanBytes(c.blockSize)} blocks`;
}

/** Integer completion percent (0–100), clamped, safe for a zero total. */
export function progressPercent(done: number, total: number): number {
  if (total <= 0) return 0;
  return Math.min(100, Math.floor((done / total) * 100));
}

/** Human-readable `"<done> / <total> (<pct>%)"` for the progress-bar caption. */
export function progressLabel(done: number, total: number): string {
  return `${humanBytes(done)} / ${humanBytes(total)} (${progressPercent(done, total)}%)`;
}

/** Turn a rendezvous failure into a plain-language line, translating the stable codes. */
export function describeError(e: ErrorLike): string {
  switch (e.code) {
    case 'confirmation_failed':
      return 'The codes did not match. Double-check the invite code and try again.';
    case 'bad_peer_message':
    case 'bad_message':
    case 'too_large':
      return 'The connection was corrupted. Please start over.';
    case 'peer_left':
    case 'peer_gone':
      return 'The other side disconnected.';
    case 'unknown_room':
      return 'That invite link is unknown — it may have expired or been mistyped.';
    case 'already_paired':
    case 'room_taken':
      return 'That room is already in use — ask the sender for a fresh code.';
    case 'expired':
      return 'This invite has expired. Ask the sender for a new one.';
    case 'rate_limited':
      return 'Too many attempts. Wait a moment and try again.';
    case 'aborted':
      return 'Cancelled.';
    default:
      return e.message || 'The connection failed.';
  }
}
