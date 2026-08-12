/**
 * Stable machine-readable error classes shared with the Go wire package
 * (ADR 0002 — error taxonomy). Externally visible errors carry exactly one
 * class; UI and future automation key on it.
 */
export const ErrorCode = {
  Auth: 'AUTH',
  Protocol: 'PROTOCOL',
  Connection: 'CONNECTION',
  Relay: 'RELAY',
  RetryExhausted: 'RETRY_EXHAUSTED',
  Canceled: 'CANCELED',
  Storage: 'STORAGE',
  SourceIO: 'SOURCE_IO',
  DestIO: 'DEST_IO',
  Compat: 'COMPAT',
  Internal: 'INTERNAL',
} as const;
export type ErrorCode = (typeof ErrorCode)[keyof typeof ErrorCode];
