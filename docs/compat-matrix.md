# Compatibility matrix

Scope: how SendBeam behaves across NAT topologies, degraded networks, and browsers — on
both the direct WebRTC path and the WebSocket relay path. The network data comes from the
NAT lab (`apps/cli/cmd/natlab`), which builds five Linux network namespaces — two peer
hosts, two userspace NAT boxes, and a public segment with the signaling/relay server and a
STUN server — connected by 9 KB-MTU veths through a bridge. Each row below was run as a
real CLI transfer (`sendarc send` / `sendarc receive`, 4 MiB payload, SHA-256 verified).

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

## Interpretation

- **Relay baseline is ~8s, not the transfer**: symmetric NAT has no usable direct path,
  so the client waits out the ICE gathering/connectivity phase (~7.6s) before the relay
  is selected. The relay transfer itself adds well under a second at these sizes.
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
