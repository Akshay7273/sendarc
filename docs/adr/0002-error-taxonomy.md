# ADR 0002 — Error taxonomy and stable error codes

Status: accepted
Scope: v1.1 (SB-1108..SB-1110)
Applies to: `packages/wire` (Go), `packages/protocol` (TS), `apps/cli`, `apps/web`

## Context

Errors today are bare strings (`"transfer: signaling closed"`, `errors.New(...)`)
or wire `fail` reasons. Callers cannot classify failures, UI cannot show the
right recovery action, and automation (v1.5 `--json`) has nothing stable to
match on. This ADR defines one taxonomy shared by Go and TS.

## 1. Error classes (SB-1108)

| Class | Code | Meaning |
| --- | --- | --- |
| Authentication | `AUTH` | SPAKE2 / key confirmation / credential failure. |
| Protocol / integrity | `PROTOCOL` | Malformed frame, replay, counter, manifest, digest mismatch. |
| Connection | `CONNECTION` | Direct path or signaling connection failure. |
| Relay | `RELAY` | Relay open / relay switch / relay transport failure. |
| Retry exhausted | `RETRY_EXHAUSTED` | Bounded retry budget consumed. |
| User canceled | `CANCELED` | User or host cancellation. |
| Storage / quota | `STORAGE` | Quota exceeded, destination collision, storage unavailable. |
| Source I/O | `SOURCE_IO` | Source read failure, source changed mid-transfer. |
| Destination I/O | `DEST_IO` | Sink write / flush / close / rename failure. |
| Compatibility | `COMPAT` | Peer or version incompatibility. |
| Internal | `INTERNAL` | Invariant violation; bugs. |

Every externally visible error has exactly one class. Wire `fail` reasons map
into classes: `auth_failed`, `key_confirmation_failed` → `AUTH`; `integrity`,
`protocol`, `unsupported` → `PROTOCOL`/`COMPAT`; `canceled` → `CANCELED`;
everything else → `INTERNAL`.

## 2. Machine codes and messages (SB-1109)

- Every externally visible error carries a stable machine code (the class
  constant above) and a human-facing message.
- Go: `wire.Error` carries `Code ErrorCode`; `wire.CodeOf(err)` walks the
  `Unwrap()` chain to classify wrapped errors. CLI prints
  `sendbeam: <command> failed [CODE]: <message>`.
- TS: `TransferError` carries `reason` (wire tag) plus `code` (class);
  `RendezvousError` already carries a signal code and is mapped to a class at
  the web boundary where needed.

## 3. Message hygiene (SB-1110)

Human-facing messages must not expose:

- raw SDP / ICE candidates or full IPs,
- invite words or invite codes,
- master keys, nonces, or key material,
- absolute filesystem paths unless they are the user's own local paths being
  reported back to them (CLI send source errors may name the user's path).

Sanitization is applied at the error construction site; logs may carry more
detail than UI messages.

## Consequences

- New errors at external boundaries must use `wire.Errorf(code, ...)` /
  `TransferError` with a code; bare `errors.New` is allowed only for internal
  invariants.
- Exit-code mapping (SB-1184) and structured output (SB-1186/v1.5) consume
  `CodeOf`/`code`.
