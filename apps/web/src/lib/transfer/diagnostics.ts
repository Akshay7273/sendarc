/**
 * Sanitized connection diagnostics — the browser twin of the Go
 * `apps/cli/internal/diagnostics` package (ADR 0003 / V12-PR06). Both clients emit the
 * same logical shape so a failing client or `sendbeam diagnose` can surface a small, safe
 * snapshot of path/ICE/timing/failure state.
 *
 * Sanitization guarantees: a snapshot never contains invite words/codes, full IP
 * addresses, filenames, SDP, ICE credentials, or payload metadata. Candidate types are kept
 * ("host"/"srflx"/"prflx"/"relay") because they are diagnostic and not sensitive; the
 * addresses themselves are dropped.
 */

import type { ErrorCode as ErrorCodeT } from '@sendbeam/protocol';

export type PathKind = 'direct' | 'direct-turn' | 'relay';

export type PathState =
  'candidate' | 'warming' | 'ready' | 'active' | 'degraded' | 'failed' | 'closed';

export interface PathDiag {
  /** Lifecycle state of the path. */
  state: PathState;
  /** Path kind. */
  kind: PathKind;
  /** Time to open this path, in ms (0 if never opened). */
  setupMs: number;
  /** Ordered ICE connection-state history for a direct path (absent for relay). */
  iceStates?: string[];
  /** Selected candidate pair type ("host"/"srflx"/"prflx"/"relay"); "" if none/direct. */
  selectedPairType?: string;
}

export interface FailureEvent {
  /** Stable wire error class (ADR 0002). */
  code: ErrorCodeT;
  /** Time since session start, in ms. */
  atMs: number;
  /** Sanitized path kind the failure occurred on, if known. */
  path?: PathKind;
  /** Short sanitized human message. */
  message: string;
}

export interface Snapshot {
  app: 'cli' | 'web';
  role?: 'offerer' | 'joiner';
  /** Pairing+connection time, in ms (0 until connected). */
  setupMs: number;
  /** Time bytes moved, in ms. */
  transferMs?: number;
  /** Wall time from session start to snapshot, in ms. */
  totalMs?: number;
  /** Sanitized final path kind; "" if none yet. */
  selectedPath?: PathKind;
  /** Sanitized selected candidate type for the final path. */
  selectedPairType?: string;
  /** Ordered set of candidate paths that were registered. */
  paths?: PathDiag[];
  /** Ordered set of failures observed. */
  failures?: FailureEvent[];
  /** Count of configured ICE servers (details never exposed). */
  iceServersConfigured?: number;
  /** Whether a TURN server was configured (never its details). */
  turnConfigured?: boolean;
}

/**
 * Apply the shared redaction rules to a string: removes full IP addresses, credentials,
 * invite codes, and filesystem paths. Used for any free text (e.g. failure messages)
 * before it enters a Snapshot.
 */
export function sanitize(s: string): string {
  return s
    .replace(/\[[0-9a-fA-F:]+\]/g, '<ip>')
    .replace(
      /(?:(?:\d{1,3}\.){3}\d{1,3}\b|(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F]{0,4}\b)(?:[-:]\d{1,5})?/g,
      '<ip>',
    )
    .replace(
      /\b(?:credential|token|secret|password|passwd|key|username)\s*[=:]\s*(\S+)/gi,
      '<redacted>',
    )
    .replace(/\b\d+-[a-z]+(?:-[a-z]+)+\b/g, '<code>')
    .replace(/(?:\/\/?)[a-zA-Z0-9_.-]+(?:\/[a-zA-Z0-9_.-]+)+/g, '<path>')
    .replace(/(?:[A-Za-z]:\\)[\\a-zA-Z0-9_.-]+/g, '<path>');
}

/** Returns the snapshot as a JSON string. */
export function toJSON(s: Snapshot): string {
  return JSON.stringify(s);
}
