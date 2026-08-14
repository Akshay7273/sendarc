//go:build benchmark

package wire

import (
	"os"
	"strconv"
	"testing"
)

// Benchmarks for the V13-PR05 digest-checkpoint seam (packages/wire/transfer_ports.go):
// a resumed receive can either restore the serialized digest state (O(1)) or re-hash the
// persisted prefix. Run one at a time (laptop rule) — never several in parallel:
//
//	go test -tags benchmark -bench DigestCheckpoint -benchmem ./...
//
// The target prefix size is parameterized via SENDBEAM_BENCH_PREFIX_GIB (default 4).
// Any size is streamed in 1 MiB chunks, so the working set stays small and no giant
// file or allocation dominates the measurement. Large sizes hash in real time (e.g.
// 100 GiB is ~1-2 minutes on one core); use -benchtime=1x so each benchmark runs exactly
// one op, and never extrapolate a measurement to a size that was not run.

func benchChunk1MiB() []byte {
	chunk := make([]byte, 1<<20)
	for i := range chunk {
		chunk[i] = byte((i*131 + 7) & 0xff)
	}
	return chunk
}

// benchTotal returns the target prefix size in bytes: SENDBEAM_BENCH_PREFIX_GIB GiB,
// defaulting to 4 GiB when the variable is unset or invalid.
func benchTotal() int64 {
	if raw := os.Getenv("SENDBEAM_BENCH_PREFIX_GIB"); raw != "" {
		if gib, err := strconv.ParseInt(raw, 10, 64); err == nil && gib > 0 {
			return gib << 30
		}
	}
	return 4 << 30
}

// BenchmarkDigestCheckpointResumeRehash is the fallback path: stream the whole persisted
// prefix through a fresh digest. Throughput is the SHA-256 rate.
func BenchmarkDigestCheckpointResumeRehash(b *testing.B) {
	chunk := benchChunk1MiB()
	total := benchTotal()
	b.Logf("prefix %d GiB", total>>30)
	b.SetBytes(total)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		d := NewSHA256Digest()
		for n := int64(0); n < total; n += int64(len(chunk)) {
			d.Update(chunk)
		}
		_ = d.HexDigest()
	}
}

// BenchmarkDigestCheckpointResumeRestore is the checkpointed path: restore the state
// covering the full prefix once, then hash only the tail. Restore itself is O(1); the
// timed loop feeds a tiny tail (64 bytes) so the restore cost — not hashing — is what is
// measured. State creation (a one-off pass over the full prefix) happens before
// ResetTimer and is not part of the measured restore cost.
func BenchmarkDigestCheckpointResumeRestore(b *testing.B) {
	chunk := benchChunk1MiB()
	total := benchTotal()
	b.Logf("prefix %d GiB", total>>30)
	live := NewSHA256Digest()
	for n := int64(0); n < total; n += int64(len(chunk)) {
		live.Update(chunk)
	}
	state, err := live.(DigestState).MarshalState()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.SetBytes(64)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		d, err := RestoreSHA256Digest(state)
		if err != nil {
			b.Fatal(err)
		}
		d.Update(chunk[:64])
		_ = d.HexDigest()
	}
}
