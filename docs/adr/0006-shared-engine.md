# ADR 0006 — Shared Go engine module

Status: accepted
Scope: v1.4 (native product & distribution) — V14-PR01
Applies to: the `packages/engine` Go module, the CLI host in `apps/cli`, and any future
desktop host

## Context

SendBeam's connection and transfer pipeline lives today under `apps/cli/internal`: SPAKE2
rendezvous authentication, capability negotiation, the authenticated WebRTC direct path,
the encrypted WebSocket relay, the adaptive connection supervisor, the transfer driver,
durable receive journals, sender restart records, and sanitized diagnostics. v1.4's mission
is "one reusable Go engine and a first-class desktop client": CLI and desktop must consume
the same connection/transfer implementation, and the engine must be reusable outside a
terminal process.

The wire crypto core already lives in its own module (`packages/wire`, `github.com/sendbeam/wire`).
Everything above the wire layer was packaged under the CLI's `internal/` tree, so it could
not be imported by a second host without forking or duplicating code.

## Decision

Extract the engine into a new sibling module `packages/engine`
(`github.com/sendbeam/engine`) with seven public packages, moved behavior-preservingly
(no logic changes; only import paths changed):

| Package       | Responsibility                                                                                                                                                            |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `rendezvous`  | Blind rendezvous handshake (SPAKE2), capability negotiation, signaling messages                                                                                           |
| `rtc`         | Authenticated WebRTC peer, data channel, ICE restart / recovery                                                                                                           |
| `relay`       | Encrypted WebSocket relay transport                                                                                                                                       |
| `supervisor`  | Path state machine; direct/relay switching and cutover safety                                                                                                             |
| `transfer`    | End-to-end driver (`transfer.Run`), sources, durable receive (`DurableDestination`/`DurableStore`), sender restart state (`SenderStore`/`PrepareSender`), adaptive policy |
| `diagnostics` | Sanitized failure/telemetry snapshots                                                                                                                                     |
| `wsclient`    | Reconnecting signaling websocket client                                                                                                                                   |

The engine depends only on `github.com/sendbeam/wire` (the crypto core) and third-party
transport libraries (`pion/webrtc/v4`, `coder/websocket`). It is resolved both in the
`go.work` workspace and in standalone module builds via a local `replace`, exactly like the
existing `wire` module pattern (CI builds every module standalone with `GOWORK=off`).

## Boundaries (what stays out of the engine)

- **Flags, argument parsing, terminal UI, styling, progress rendering, and updater
  presentation stay in the host** (`apps/cli/cmd/sendbeam` today; the desktop shell later).
- The engine exposes configuration and callbacks (`transfer.Spec`, `rendezvous.Options`,
  progress/transport/state hooks) rather than presentation.
- Hosts drive transfers through the exported API only. There is no back-dependency: the
  engine module does not import, and physically cannot import, any `apps/*` module (they are
  separate modules it does not require), so "CLI and desktop consume the same
  implementation" is enforced by the module graph itself.

## Parity testing

Behavior is pinned two ways:

1. The moved CLI test suites (all existing unit/integration/race/fault tests) now run
   against the engine module unchanged.
2. New external tests in `packages/engine/parity` exercise the engine strictly through its
   exported API — no internals, no CLI code — and pin behavior parity: a full transfer with
   verified byte-identical output over the direct (WebRTC) path, over the forced encrypted
   relay, and an interrupted transfer that resumes only through authenticated
   cross-session resume-auth.

## Consequences

- The CLI loses its `internal/` engine tree; its command layer imports
  `github.com/sendbeam/engine/...`.
- Desktop (V14-PR02+) imports the same module; protocol, transport, durability, and trust
  logic stay in Go and stay shared.
- `go.work`, the justfile Go module loops, and the CI Go matrix now cover four modules
  (`packages/wire`, `packages/engine`, `apps/server`, `apps/cli`).
- The `internal/` visibility boundary is dropped for these packages: exported identifiers
  become the public engine API, so API additions need the same care as any public surface.
- This ADR does not change wire compatibility: no `sendbeam/2`; the protocol is untouched.
