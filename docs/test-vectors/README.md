# Test vectors

Deterministic, published vectors for the `sendbeam/1` protocol and its crypto, so an
independent implementation can be validated against the reference without running the
reference code. All hex is unprefixed lowercase.

| File | Contents | Consumed by |
| --- | --- | --- |
| `rfc9382-p256.json` | The official RFC 9382 §6 P-256 SPAKE2 vectors (fixed identities `A`/`B`, scalar `w`, shares, transcript, `Ke`/`Ka`, confirmation MACs). | `packages/protocol/src/spake2.test.ts`, `packages/wire/spake2_test.go` |
| `sendbeam-crypto.json` | SendBeam domain-specific KATs: invite-code → SPAKE2 scalar `w` (`HKDF "sendbeam/1 spake2 w"`), the full SPAKE2 exchange with fixed secrets, `HKDF(Ke, "sendbeam/1 master" \|\| TT)` master derivation, directional AEAD keys (`sendbeam/1 o2j` / `j2o`), one AES-256-GCM seal vector (salt+counter nonce, header as AAD), and the SDP/ICE HMAC (`authmac`). | `packages/protocol/src/{spake2,keyschedule,aead,authmac}.test.ts`, `packages/wire/{spake2,authmac}_test.go` |
| `transfer.json` | A complete 40-byte single-file transfer: derived keys, the file bytes and canonical SHA-256, and the byte-exact wire frame log (`s2r` frames the sender emitted, `r2s` frames the receiver replied). Replay the `s2r` frames in order through any receiver and expect the recorded `r2s` replies, the exact file bytes, and the recorded digest. | `packages/wire/transfer_vector_test.go` |

## How the vectors are checked in CI

- The TypeScript side (`@sendbeam/protocol`) asserts `rfc9382-p256.json` and
  `sendbeam-crypto.json` against WebCrypto/noble-curves implementations (vitest).
- The Go side (`packages/wire`) asserts the same files against its nistec-based
  implementation (`go test -race`), and replays `transfer.json` through its receiver.
- The two suites are independent implementations of the same spec: a vector that both
  reproduce byte-identically pins the wire format for good.

## Regenerating

The vector files are committed artifacts and must not change unless the protocol does.
To regenerate the Go-produced files after a deliberate wire change:

```sh
cd packages/wire
GENERATE_VECTORS=1 go test -run TestGenerateTransferVector ./...
```

The generator drives a real sender/receiver over deterministic channels; it is also
guarded by a normal (non-generated) test that fails if the committed vector stops
reproducing. `sendbeam-crypto.json` and `rfc9382-p256.json` were produced once by the
original implementation; only touch them with a protocol change, and update every
consumer test in the same change.

## Validation status

- **In-repo cross-language check (done, CI-gated):** the Go (nistec) and TypeScript
  (noble-curves/WebCrypto) implementations reproduce every vector byte-identically.
  They are two independent implementations of the same spec, but both were written by
  the same author, so this is a consistency check, not independent validation.
- **Independent reimplementation (open):** no third-party implementation has yet
  reproduced these vectors. This is the remaining M7 exit criterion. Validation
  requires no SendBeam code: load the JSON files and recompute the values with your own
  primitives (see below). If you have done this, please report it in an issue so the
  status can be updated.

## Validating your own implementation

1. Load the JSON file(s).
2. Recompute each listed value with your implementation's primitives.
3. Compare byte-for-byte; every mismatch is a spec violation, not a tolerance.

For `transfer.json`: parse each `wireLog` entry, decrypt frames with the recorded
directional keys using the nonce `salt || counter_be(8)` (counter starts at 0 per
direction), verify the GCM tag over `header || ciphertext`, then drive your receiver
state machine. You must end with the recorded file bytes and SHA-256.
