# Benchmarks

Reproducible numbers for the `sendbeam/1` transfer engine. These measure the engine
itself (crypto + block/ack state machine) on loopback; end-to-end throughput is bounded
by the transport and the network, not by these figures — see the notes and
[compat-matrix.md](./compat-matrix.md) for path-level numbers.

## Reproducing

```sh
cd packages/wire
go test -bench . -benchmem -run xxx -benchtime 2s .
```

## Results

Machine: Intel Core i5-6200U @ 2.30 GHz (4 cores), Linux, `go test` without `-race`.

| Benchmark                                                                                 |       ns/op |  MB/s |        B/op | allocs/op |
| ----------------------------------------------------------------------------------------- | ----------: | ----: | ----------: | --------: |
| `BenchmarkSeal` (AES-256-GCM frame, 16 KiB payload)                                       |      12,474 | 1,313 |      19,752 |         5 |
| `BenchmarkOpen` (verify + decrypt 16 KiB frame)                                           |      12,473 | 1,313 |      17,744 |         5 |
| `BenchmarkSignSignal` (SDP/ICE HMAC)                                                      |       1,890 |    16 |         560 |         7 |
| `BenchmarkTransferLoopback` (full 16 MiB transfer, 1 MiB blocks, 16 KiB frames, window 8) | 266,403,435 |    63 | 252,657,719 |    12,870 |

### Reading the numbers

- **Frame crypto is ~1.3 GB/s per core**: a 16 KiB frame seals or opens in ~12.5 µs. The
  19.7 KB allocation per seal is the frame buffer itself, recycled per transfer.
- **The engine sustains ~63 MB/s on this laptop** in the in-memory loopback — the same
  state machine the DataChannel and relay paths run. The ~252 MB/op allocation is the
  loopback's copy-heavy plumbing (frame copies + sink buffering), not a leak; real
  transfers bound memory differently (below).
- **Signaling MACs are negligible**: ~1.9 µs each, a handful per session.

## Memory model (independent of transport)

- **Frames are 16 KiB** on both paths (`DEFAULT_FRAME_BYTES`); the relay caps a single
  frame at 128 KiB (`SENDBEAM_RELAY_MAX_FRAME_BYTES`).
- **Sender side**: at most `DEFAULT_INFLIGHT_BLOCKS = 8` blocks (1 MiB each) in flight
  ahead of receiver confirmation, and the DataChannel buffered-amount watermark paces at
  ~8 MiB (`BUFFERED_AMOUNT_HIGH`).
- **Receiver side**: RAM is bounded by the same 8-block window regardless of sink speed —
  a slow sink causes backpressure, never growth.
- **Relay**: per-connection window 1 MiB, queue 2 MiB, throughput token bucket 32 MiB/s
  (`SENDBEAM_RELAY_*`); a busy instance stays in the low tens of MiB.

So a 100 MiB file does not imply 100 MiB of buffers anywhere in the chain: the memory
ceiling is a small constant, not the file size.

## Path-level throughput

Measured in the NAT lab (netns, 9 KB MTU, 4 MiB payload; see compat-matrix.md):

| Path                | Scenario      | Wall-clock |                 Implied throughput |
| ------------------- | ------------- | ---------: | ---------------------------------: |
| Direct (WebRTC)     | baseline      |      1.8 s |           ~2.2 MB/s (lab loopback) |
| Relay (WS over TCP) | baseline      |      8.3 s | ~0.5 MB/s incl. ~7.6 s ICE timeout |
| Relay (WS over TCP) | transfer only |       <1 s |                                  — |
| Direct              | 10 Mbit cap   |      5.2 s |                          ~0.8 MB/s |
| Direct              | 3% loss       |     10.1 s |        ~0.4 MB/s (SCTP retransmit) |
| Relay               | 3% loss       |      8.3 s |               TCP absorbs the loss |

These are lab-loopback figures (both peers on one machine); real internet transfers are
faster on the direct path (no veth overhead) and slower on the relay (internet RTT and
the 32 MiB/s relay ceiling). Browser-level E2E (100 MiB round-trip, Playwright) passes in
CI on Chromium and Firefox; timing is CI-host-dependent and not a spec number.

## Path-selection timing

Measured separately from throughput (`apps/cli/internal/rtc/peer_bench_test.go`, loopback
direct) and guarding the adaptive racing policy's "connect fast" goal on a healthy direct
path:

```text
BenchmarkPeerTimeToActivePathDirect        ~6.8 ms/active-path
BenchmarkPeerTimeToFirstPayloadDirect      ~6.1 ms/first-payload
BenchmarkAdaptivePolicyObserveThroughput    ~42 ns/op (0 allocs/op)
```

The two peer benchmarks are the time to an open DataChannel and to the first delivered
frame on the direct path; the policy-observe number is the per-ICE-event cost of the
adaptive selection decision. These are host/CI dependent and are relative, not spec
numbers.

### Restrictive-network fallback (time-to-active-path)

Measured in the NAT lab with `-measure` and the adaptive policy (see compat-matrix.md). On
a UDP-blocked network the relay fallback engages in ~5.2s — a material improvement over the
legacy blind ~8s relay timer — while a healthy direct path still connects in ~1.2s and is
never preempted once a server-reflexive hint appears. Symmetric NAT remains bounded by ICE
connectivity-check failure (~11s) because its unusable server-reflexive candidate is
indistinguishable from a slow-but-healthy direct path.

## Digest-checkpoint (V13-PR05)

A resumed receive can either restore the serialized digest state — O(1), ~5 µs — or
re-hash the whole persisted prefix through SHA-256. These benchmarks quantify that
trade-off. Build-tagged (`-tags benchmark`), so normal test runs never execute them;
run one at a time:

```sh
cd packages/wire
SENDBEAM_BENCH_PREFIX_GIB=4 go test -tags benchmark -bench DigestCheckpoint -benchtime=1x -benchmem ./...
```

The target prefix size is parameterized with `SENDBEAM_BENCH_PREFIX_GIB` (default 4) and
is always streamed in 1 MiB chunks, so the working set stays small at any size. Every
row below is a measured run — numbers are never extrapolated from another size.

| Machine                                                   |  Prefix |    Rehash (fallback) | Restore (checkpointed) |
| --------------------------------------------------------- | ------: | -------------------: | ---------------------: |
| i5-6200U @ 2.30 GHz, Linux, go1.24                        |   4 GiB |  ~17.0 s @ ~253 MB/s |                ~5.1 µs |
| GitHub-hosted ubuntu-latest, 4 vCPU AMD EPYC 7763, go1.25 |  10 GiB |  6.77 s @ 1,586 MB/s |                5.13 µs |
| GitHub-hosted ubuntu-latest, 4 vCPU AMD EPYC 7763, go1.25 | 100 GiB |  67.7 s @ 1,586 MB/s |                4.97 µs |
| GitHub-hosted ubuntu-latest, 4 vCPU AMD EPYC 7763, go1.25 | 256 GiB | 173.2 s @ 1,587 MB/s |                6.58 µs |

Rehash cost is linear in the prefix (1,586 MB/s on the runner at every size — a
consistent measurement, not an extrapolation); restore is a constant ~5 µs regardless
of prefix size. At 256 GiB that is roughly 26 million times faster than re-hashing, and
the restore cost does not grow with transfer size.

## CPU

Crypto is the only CPU-heavy step: ~12.5 µs per 16 KiB frame, or ~0.8 s of one core per
gigabyte (split between the peers). Hashing is off-thread (Web Worker on the web side)
and never blocks the transfer loop. The relay does no crypto at all — it forwards sealed
bytes — so server CPU per byte is memcpy-class.
