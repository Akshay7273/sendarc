# ADR 0001 — Transfer lifecycle, ownership, and generations

Status: accepted
Scope: v1.1 (SB-1101..SB-1105, SB-1107)
Applies to: `packages/protocol`, `packages/wire`, `apps/web/src/lib/session/transfer.ts`, `apps/cli/internal/transfer`

## Context

The transfer pipeline spans a signaling socket, an authenticated direct path, an
encrypted relay fallback, a worker/goroutine-owned crypto engine, a disk sink, and
timers. Post-v1.0 hardening (PR #88) fixed concrete lifecycle defects, but the
states, ownership, and cleanup rules were implicit. This ADR makes them explicit
so web and Go can share one mental model and future generations of the code keep
the guarantees.

## 1. Lifecycle states (SB-1101)

A transfer is always in exactly one of:

| State | Meaning |
| --- | --- |
| `idle` | Controller created, nothing started. |
| `pairing` | Invite/room exchange before the SPAKE2 handshake completes. |
| `authenticating` | SPAKE2 / key confirmation in progress. |
| `connecting` | Direct path negotiation or relay open in progress. |
| `running` | Blocks flowing on an established path. |
| `paused` | Sender stops producing new frames; buffered bytes may drain. |
| `switching-path` | Cutover direct → relay (or recovery) in progress. |
| `recovering` | Network change observed; ICE restart / path recovery attempt. |
| `completing` | Final digest verified; `Complete`/`Done` exchange or output materialization. |
| `completed` | Terminal: output verified and committed. |
| `failed` | Terminal: explicit failure. |
| `canceled` | Terminal: user cancellation or host teardown. |

The web UI collapses `pairing`/`authenticating`/`connecting` into a single
"connecting" presentation today; the states above are the engine contract, and
presentation may merge them. `idle`, `recovering`, and `completing` may be
transient (non-observable) where the host has no checkpoint to expose.

## 2. Legal transitions (SB-1102)

Allowed edges (any unlisted edge is illegal):

```
idle → pairing
pairing → authenticating | failed | canceled
authenticating → connecting | failed | canceled
connecting → running | switching-path | recovering | failed | canceled
running → paused | switching-path | recovering | completing | failed | canceled
paused → running | canceling-equivalent (canceled) | failed
switching-path → running | recovering | failed | canceled
recovering → running | switching-path | failed | canceled
completing → completed | failed | canceled
```

Terminal rules (SB-1102):

- `completed`, `failed`, and `canceled` are absorbing. No event may move a
  terminal transfer to any other state.
- `failed` is preferred over `canceled` when both conditions are observed at the
  same instant (failure wins).
- A transfer that was canceled may still report a late `failed`-class cleanup
  error only through logs; the public outcome remains `canceled`.

## 3. Ownership (SB-1103)

Every resource has exactly one owner; owners are the only code that closes or
terminates them:

| Resource | Owner |
| --- | --- |
| Signaling socket | Host controller (web `transfer.ts` `run`; CLI `driver.go`). |
| Direct path (WebRTC / ICE) | Host controller while `connecting`; engine during `running`. |
| Relay allocation | Host controller. |
| Transfer worker / engine goroutine | Host controller; engine terminates on `Complete` or its `abort()`. |
| Sink / destination | Engine; host owns the durable staging location. |
| Temporary output (OPFS / `.part`) | Host controller during cleanup. |
| Timers (relay fallback, cancel, switch timeout) | The scope that created them; canceled in `cleanup()`. |
| Wake lock / progress renderer | Host controller (UI concern, not protocol). |

## 4. Idempotent cleanup (SB-1104)

`cleanup()` runs on every terminal path (`completed`, `failed`, `canceled`) and
must be safe to call twice:

- Every teardown primitive (`close()`, `abort()`, `terminate()`) is idempotent.
- `cleanup()` never throws; each step's error is logged.
- Late resource creation (e.g. a worker message arriving during teardown) must
  not resurrect a closed resource: creation sites check the terminal flag.

## 5. Generations (SB-1105..SB-1107)

A **generation** is a monotonically increasing integer owned by the controller.
Every asynchronous continuation (worker message handler, socket callback, timer,
`switchToRelay`/path event) captures the generation at the moment it is created
and checks it before any mutation of controller state or resource handles. A
stale continuation is inert: it may return early, log, or drop the event, but
must not:

- resolve/reject the transfer outcome;
- open, close, or write to a path or socket;
- start a relay fallback;
- mutate progress state.

- Web (SB-1106): `transfer.ts` `run()` bumps the generation in `cleanup()`;
  every closure compares its captured generation before acting. The existing
  `settled` flag remains as the terminal-outcome guard; the generation is the
  general staleness guard.
- Go (SB-1107): engine objects (`Sender`/`Receiver`) serialize `Handle` with a
  mutex and settle once; the host `driver` loop is the single goroutine that
  owns the connection, so host-side race windows are closed by construction
  plus bounded waits (relay switch timeout, PR #88).

## Consequences

- New transports (v1.2 supervisor) must present as path resources owned by the
  controller, not transfer engines.
- UI state machines must map onto the states above and never invent absorbing
  behavior.
- Code review gate: any new callback/goroutine/timer must name its owner and
  generation capture.
