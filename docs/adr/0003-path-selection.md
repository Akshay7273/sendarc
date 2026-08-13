# ADR 0003 — Direct path selection: direct-only, direct+TURN, and hybrid relay

Status: accepted
Scope: v1.2 (V12-PR06)
Applies to: `packages/wire` (Go), `packages/protocol` (TS), `apps/cli`, `apps/web`, `apps/server`

## Context

SendBeam moves bytes over one of three byte paths: an authenticated WebRTC
DataChannel (direct), a TURN-relayed WebRTC DataChannel (direct still, but the
transport is allocated through a TURN server), or the encrypted WebSocket relay
(the zero-extra-service fallback). V12-PR06 asks us to decide, in one short ADR,
how these should nest so that default self-hosting needs no extra service while
optional TURN remains available for restrictive networks without weakening E2EE.

## Options

### A. Direct-only (no TURN)

Clients gather host/srflx candidates over the bundled STUN server and, if the
direct path does not connect, fall back to the encrypted WebSocket relay.

- Pros: no extra service; the smallest moving surface; E2EE unchanged.
- Cons: users whose network blocks or de-prioritizes UDP for WebRTC (some
  hotels, symmetric/CGNAT-heavy operators, or UDP-blocking firewalls) always ride
  the relay, so relay pressure grows and direct latency is never recovered.

### B. Direct + optional TURN, encrypted WS relay as fallback

Clients use operator-published ICE servers (STUN and, optionally, TURN). When a
TURN server is configured, a relay candidate can be gathered and raced against
host/srflx candidates; when it is not, behavior is identical to option A. The
encrypted WebSocket relay remains the last-resort fallback and the default when
no TURN is configured.

- Pros: restrictive networks can recover a WebRTC path without touching the
  transfer engine; the WS relay remains the zero-extra fallback by default;
  TURN credentials are optional and short-lived; E2EE stays at the application
  layer on every candidate. Direct latency when healthy is unchanged.
- Cons: requires an operator to operate a TURN server for those networks.

### C. Hybrid TURN allocation + WS relay racing

Treat a TURN relay candidate exactly like the WS relay: warm both in parallel and
race. This is a superset of B but doubles the number of fallback paths a peer may
hold open.

- Pros: maximum reachability.
- Cons: more concurrent allocations (relay pressure, cost, memory), more states
  to reason about in the supervisor, and the WS relay alone already provides the
  same reachability with fewer moving parts (WebSocket over the same origin).

## Decision

Adopt **option B**.

- Default self-hosting publishes no TURN URL, so `sendbeamd` out of the box
  requires no extra service; the encrypted WebSocket relay is the fallback.
- Operators who want better restricted-network reachability publish optional
  TURN URLs via the existing `SENDBEAM_ICE_SERVERS` config. Clients already parse
  and apply TURN entries (`wire.ParseICEServer` / `protocol.parseIceServer`) into
  their WebRTC ICE agent, so a relay candidate can be gathered and raced against
  direct candidates with no engine change.
- TURN credentials are short-lived and served with `Cache-Control: no-cache`;
  clients never cache a fetched ICE config past `wire.ICEConfigTTL`
  (15 minutes) and never embed long-lived TURN credentials in the web bundle.
  The browser fetches `/config.json` at runtime and applies the operator's
  servers, matching the CLI's `--ice-server`.
- We do **not** adopt C: the encrypted WS relay is the single fallback racing
  surface. TURN's job is only to give the direct WebRTC path a relayed candidate,
  not to add a second fallback plane.
- Application-layer AES-GCM (the existing frame sealing) remains active on every
  candidate — direct, TURN-relayed, and WS relay. A TURN server observes only
  encrypted WebRTC datagrams and never plaintext file contents.

## Consequences

- Reference docs (`docs/protocol.md`, `docs/HOSTING.md`, `docs/threat-model.md`)
  describe TURN as optional and never required for default self-hosting.
- The supervisor must treat a TURN relayed candidate as a _direct-path_ candidate
  (same epoch, same path identity), never as a relay fallback.
- Sanitized diagnostics report whether the selected WebRTC candidate was a TURN
  relay, so operators can see when TURN is actually being used — without
  exposing candidates, credentials, or full IPs.
