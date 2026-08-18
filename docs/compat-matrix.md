# Compatibility matrix

Scope: how SendBeam behaves across NAT topologies, degraded networks, and browsers — on
both the direct WebRTC path and the WebSocket relay path. The network data comes from the
NAT lab (`apps/cli/cmd/natlab`), which builds five Linux network namespaces — two peer
hosts, two userspace NAT boxes, and a public segment with the signaling/relay server and a
STUN server — connected by 9 KB-MTU veths through a bridge. Each row below was run as a
real CLI transfer (`sendbeam send` / `sendbeam receive`, 4 MiB payload, SHA-256 verified).

## NAT topologies (no degradation)

| NAT A / NAT B                   | Transport | Digest | Notes                                             |
| ------------------------------- | --------- | ------ | ------------------------------------------------- |
| full-cone/full-cone             | direct    | ✓      |                                                   |
| restricted/restricted           | direct    | ✓      |                                                   |
| port-restricted/port-restricted | direct    | ✓      |                                                   |
| symmetric/symmetric             | relay     | ✓      | Direct ICE fails; relay fallback picks up         |
| full-cone/symmetric             | direct    | ✓      | Full-cone maps to the symmetric box's pinned port |

## Degraded networks (4 MiB transfer, wall-clock per combo)

| Scenario    | Direct (full-cone/full-cone) | Relay (symmetric/symmetric) |
| ----------- | ---------------------------- | --------------------------- |
| Baseline    | 1.8s ✓                       | 8.3s ✓                      |
| 3% loss     | 10.1s ✓ (retransmits)        | 8.3s ✓ (TCP hides it)       |
| 50 ms RTT   | 5.7s ✓                       | 9.8s ✓                      |
| 10 Mbit cap | 5.2s ✓                       | 11.6s ✓                     |

All rows end with the receiver's recomputed SHA-256 matching the sender's (digest ✓).

## Restrictive-network fallback timing

Time from sender start until the selected transport is engaged, measured in the NAT lab
(`-measure`, 4 MiB payload, digest verified). These numbers gauge the adaptive racing
policy's fallback speed, not throughput.

| NAT combo               | Transport | Time to active path |
| ----------------------- | --------- | ------------------- |
| full-cone/full-cone     | direct    | ~1.2s               |
| udp-blocked/udp-blocked | relay     | ~5.2s               |
| symmetric/symmetric     | relay     | ~11.2s              |

- **udp-blocked** (WebRTC UDP fully dropped): gathering yields host-only candidates with no
  server-reflexive hint, so the relay warms once the bounded no-hint escalation elapses
  (~5s). This is a material improvement over the legacy blind ~8s relay timer (~8.3s).
- **symmetric NAT**: a server-reflexive candidate is gathered but is unreachable by the
  peer, so the policy keeps racing direct (to preserve a slow-but-healthy direct path) until
  ICE connectivity fails (~11s). This is the residual cost of not preempting a direct path
  that has a server-reflexive hint.

### How to reproduce

```sh
cd apps/cli
go build -o ../../bin/natlab ./cmd/natlab
go build -o ../../bin/sendbeamd ../server/cmd/sendbeamd
# All NAT combos, no degradation:
sudo unshare -Urnm ../../bin/natlab -server-bin ../../bin/sendbeamd
# Degraded networks (loss / delay / bandwidth cap), direct + relay:
sudo unshare -Urnm ../../bin/natlab -server-bin ../../bin/sendbeamd \
  -combos full-cone/full-cone,symmetric/symmetric -netem "loss 3%"
```

The `-netem` profile is applied with `tc` to the egress of both public bridge legs, so it
shapes the sender→receiver downlink on the direct path and the server→receiver relay leg.
Profiles: `loss 3%`, `delay 50ms`, `rate 10mbit`.

## Browser compatibility

SendBeam targets evergreen desktop browsers. The browser E2E suite (Playwright) runs in CI
on every change and round-trips a 100 MiB file both ways through the real server; WebKit
is opt-in locally and not part of CI.

| Capability                                   | Chromium (Chrome/Edge) | Firefox       | WebKit (Safari)     |
| -------------------------------------------- | ---------------------- | ------------- | ------------------- |
| WebRTC DataChannel (direct path)             | ✓ CI-tested            | ✓ CI-tested   | opt-in, best-effort |
| WebSocket + encrypted relay fallback         | ✓ CI-tested            | ✓ CI-tested   | opt-in, best-effort |
| WebCrypto (AES-GCM, HKDF-SHA256, SHA-256)    | ✓ CI-tested            | ✓ CI-tested   | supported, untested |
| OPFS sink (`navigator.storage.getDirectory`) | ✓ CI-tested            | ✓ CI-tested   | supported, untested |
| File System Access API (direct-file sink)    | ✓ Chromium             | ✗ not exposed | ✗ not exposed       |
| ZIP archive sink (fallback)                  | ✓                      | ✓             | best-effort         |
| Quota checks (`navigator.storage.estimate`)  | ✓                      | ✓             | supported, untested |

Sink fallback ladder, in order of preference: **direct-file** (File System Access API,
Chromium-only) → **OPFS** (all evergreen engines) → **ZIP archive** (always available).
A sender that picks a folder triggers the receiver's archive sink; single files prefer
direct-file/OPFS. The ZIP fallback is capped at 4 GiB.

### Mobile

Not yet CI-tested. iOS Safari and Android Chrome share the WebKit/Chromium engines above,
so WebRTC/WebCrypto/OPFS are expected to work, but file-handle behavior and OPFS support
differ by version; treat mobile as best-effort until the opt-in suite covers it.

## Cross-Client Interoperability Matrix (Browser ↔ CLI ↔ Desktop)

SendBeam implements one uniform wire protocol (`sendbeam/1`) shared across all client hosts:
- **CLI** and **Desktop** execute the shared Go transfer engine (`packages/engine` + `packages/wire`).
- **Web App** executes the protocol-equivalent TypeScript engine (`@sendbeam/protocol`).

All 9 directional client pairs are tested and supported across direct WebRTC and fallback encrypted WebSocket relay paths:

| Sender → Receiver | Direct WebRTC | Fallback Relay | File Formats | Folder / Trees | Durable Resume (`resume-auth-v1`) | SHA-256 Digest |
| :--- | :---: | :---: | :--- | :--- | :---: | :---: |
| **Browser → Browser** | ✓ | ✓ | All files | ZIP archive sink | ✓ (OPFS / IndexedDB) | ✓ |
| **CLI → CLI** | ✓ | ✓ | All files | Directory structure | ✓ (`.sendbeam` journal) | ✓ |
| **Desktop → Desktop** | ✓ | ✓ | All files | Directory structure | ✓ (`.sendbeam` journal) | ✓ |
| **Browser → CLI** | ✓ | ✓ | All files | Directory structure | ✓ | ✓ |
| **CLI → Browser** | ✓ | ✓ | All files | ZIP archive sink | ✓ | ✓ |
| **Browser → Desktop** | ✓ | ✓ | All files | Directory structure | ✓ | ✓ |
| **Desktop → Browser** | ✓ | ✓ | All files | ZIP archive sink | ✓ | ✓ |
| **CLI → Desktop** | ✓ | ✓ | All files | Directory structure | ✓ | ✓ |
| **Desktop → CLI** | ✓ | ✓ | All files | Directory structure | ✓ | ✓ |

### Transport & Feature Parity Guarantees
- **End-to-End Encryption:** SPAKE2 password-authenticated key exchange followed by AES-GCM-256 authenticated frame encryption on both direct and relay transports.
- **Relay Fallback Immunity:** If WebRTC direct connectivity is dropped or blocked by hostile NAT/firewalls, transfers switch to the encrypted WebSocket relay without losing committed progress or exposing plaintext.
- **Path Safety:** Path traversal (`..`), absolute paths, and symlink escapes are sanitized and verified against the chosen destination root before writing on all native hosts (`packages/wire/safe_path.go`).
- **Digest Invariant:** Every transfer terminates with a cryptographically verified SHA-256 whole-file digest comparison; unverified or corrupted bytes are never committed.

## Durable resume

Cross-session durable resume (v1.3) — a process/page/session death followed by an
authenticated resume against the verified durable checkpoint — is supported across host
combinations through the shared `sendbeam/1` wire protocol with the additive
`resume-auth-v1` capability. The resume-auth handshake, transcript, proofs, and fresh key
derivation are pinned byte-for-byte by `docs/test-vectors/resume-auth.json`, asserted by
both the Go and TypeScript hosts, so browser↔CLI sessions negotiate and authenticate over
identical semantics.

| Host pair (sender → receiver)   | Resume supported | Verified by                                                                                                                                                                                                                                                                                                                                                                  |
| ------------------------------- | ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CLI → CLI                       | ✓                | `packages/engine/transfer/driver_test.go` (`TestDriverAuthenticatedCrossSessionResume`) + `resume_driver_test.go` (`TestDriverResumeTransfersZeroBytesWhenAllCommitted`, crash/resume tests), `durable_test.go` (`TestDurableResumeFromCheckpointEndToEnd`, auth-scoped-to-selected-journal tests), wire loopback sender/receiver resume suites.                             |
| Desktop → Desktop               | ✓                | `apps/desktop/internal/engine/durability_test.go` (`TestDesktopDurabilityService_ResumeInterrupted`, `TestDesktopDurabilityService_DiscardInterrupted`), `transfer_service_test.go` (native desktop resume events, progress telemetry, reveal boundary verification).                                                                                                      |
| Browser → Browser               | ✓                | `apps/web/src/App.test.ts` (exact receive-attempt flow, resume sender/binding tests), `apps/web/src/lib/transfer/durable-destination.test.ts` (reload resume, checkpoint reuse only after auth, streams only missing blocks), `packages/protocol/src/resume-auth.test.ts` (fresh keys per attempt).                                                                          |
| Browser → CLI / Desktop         | ✓                | Same wire protocol + byte-identical resume-auth vectors (Go + TS assert the same `resume-auth.json`); capability negotiation (`resume-auth-v1`) tested on both hosts (`packages/wire/resumeauth_test.go` `TestResumeAuthNegotiation`, `apps/web/src/App.test.ts` capability-gate tests); native receiver auth gate scoped to the selected journal (`durable_test.go`). |
| CLI / Desktop → Browser         | ✓                | Same protocol/vector grounding as Browser → CLI; browser receiver advertises `resume-auth-v1` only for an armed interrupted-receive attempt and reuses the verified checkpoint only after the preamble succeeds (`durable-destination.test.ts`, `App.test.ts`).                                                                                                              |
| CLI ↔ Desktop                   | ✓                | Both native clients share the Go transfer engine (`packages/engine/transfer`); journal inspection, resumption, and discard APIs share exact `.sendbeam/journals` format (`durability_test.go`, `service_test.go`).                                                                                                                                                        |
| Any → legacy/no-credential peer | ✗ (fails closed) | Peer without the capability (or with a stripped/absent capability, or a host without the local credential) never receives resume-auth messages and never reuses old durable progress; the receiver keeps the journal and proceeds fresh or refuses — `resume_driver_test.go` (`TestDriverReceiverResumeWithoutCapableSenderFallsBackFresh`), `App.test.ts` capability tests. |
| Credential on one side only     | ✗ (fails closed) | No credential is fabricated or replaced; authenticated resume is unavailable and explicit fresh restart/discard is offered — `sender_state_test.go` (`TestAttachResumeSecretPersistsOnceAndNeverReplaces`, legacy v1 migration), `durable_test.go` (never-fabricated-secret tests).                                                                                          |


### Resume limits

- Resume is **block-granular**: only whole missing blocks beyond the committed high-water
  are retransmitted; the whole-file digest is always verified at the end.
- Browser durable receive survives reload and worker death via OPFS partials + the
  IndexedDB journal and lease; the direct-file and direct-directory save modes are
  capability-gated and are **not** reload-durable. Safari's async sink advances its
  checkpoint at file close (honest granularity), never block-by-block.
- Sender reattachment needs the same browser + origin (persisted handle/record are
  origin-scoped) or an explicit re-selection of the original source; a changed source is a
  hard resume refusal. There is **no cross-device resume**.
- Legacy pre-PR07 records/journals have no resume credential: their durable data may stay
  locally but cross-session resume is unavailable (fresh restart/discard only).
- Mobile browsers are best-effort (see Browser compatibility); resume limits follow the
  engine's OPFS/WebCrypto behavior.
- No cloud backup/history, accounts, or server-side presence — durable state is purely
  local.

## Interpretation

- **Restrictive networks engage the relay without a blind fixed wait**: there is no fixed
  ~8s selection timer in production. When ICE shows a direct path is not viable the relay is
  warmed promptly (udp-blocked → ~5.2s to active path) and raced; healthy direct still wins
  in ~1.2s and is never preempted once a server-reflexive hint appears. The only unbounded
  residual is symmetric NAT, where an unreachable-but-present serve-reflexive candidate is
  indistinguishable from a slow healthy direct, so the policy waits for ICE connectivity to
  fail before falling back (~11s).
- **Packet loss**: the direct path degrades markedly (SCTP/DTLS retransmission backoff),
  while the relay (TCP) is unaffected — TCP's retransmission and congestion control hide
  3% loss behind the scenes.
- **Latency and bandwidth caps** slow both paths proportionally; neither path has a
  fixed timeout that a 50 ms RTT or a 10 Mbit cap can trip. The relay's byte-credit flow
  control (receiver-granted window) paces a slow network correctly instead of buffering
  without bound.
- **Bounded memory is unaffected** by any scenario: frames are 16 KiB on both paths,
  the relay is credit-bounded, and the direct path is bounded by the datachannel's
  buffered-amount watermark. See `BENCHMARKS.md` for the engine numbers.

## Lab history worth keeping

- The public bridge and its ports must match the endpoint MTU (9000). With the bridge at
  the default 1500 while endpoints negotiated MSS 8948, relayed TCP connections wedged
  irreversibly once flow control forced a non-GSO partial segment — it was silently
  dropped, congestion window collapsed to 2, retransmissions vanished, and the connection
  died with `connection timed out` at ~7.8 s. The stall point varied (≈52 KiB–527 KiB)
  because it was a race, not a fixed buffer. Direct (UDP) transfers were unaffected,
  which made the relay failure look like a relay bug rather than a lab bug.
