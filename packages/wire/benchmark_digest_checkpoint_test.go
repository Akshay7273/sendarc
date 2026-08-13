//go:build benchmark

package wire

import (
	"testing"
)

// Benchmarks for the V13-PR05 digest-checkpoint seam (packages/wire/transfer_ports.go):
// a resumed receive can either restore the serialized digest state (O(1)) or re-hash the
// persisted prefix. Run one at a time (laptop rule):
//
//	go test -tags benchmark -bench DigestCheckpoint -benchmem ./...
//
// 4 GiB is streamed in 1 MiB chunks, so the working set stays small and no giant
// allocation dominates the measurement.

func benchChunk1MiB() []byte {
	chunk := make([]byte, 1<<20)
	for i := range chunk {
		chunk[i] = byte((i*131 + 7) & 0xff)
	}
	return chunk
}

const digestCheckpointBenchTotal = 4 << 30 // 4 GiB per op

// BenchmarkDigestCheckpointResumeRehash is the fallback path: stream the whole persisted
// prefix through a fresh digest. Throughput is the SHA-256 rate.
func BenchmarkDigestCheckpointResumeRehash(b *testing.B) {
	chunk := benchChunk1MiB()
	b.SetBytes(digestCheckpointBenchTotal)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		d := NewSHA256Digest()
		for n := 0; n < digestCheckpointBenchTotal; n += len(chunk) {
			d.Update(chunk)
		}
		_ = d.HexDigest()
	}
}

// BenchmarkDigestCheckpointResumeRestore is the checkpointed path: restore the state
// covering the 4 GiB prefix once, then hash only the tail. Restore itself is O(1); the
// timed loop feeds a tiny tail (64 bytes) so the restore cost — not hashing — is what is
// measured. State creation (a one-off 4 GiB pass) happens before ResetTimer.
func BenchmarkDigestCheckpointResumeRestore(b *testing.B) {
	chunk := benchChunk1MiB()
	live := NewSHA256Digest()
	for n := 0; n < digestCheckpointBenchTotal; n += len(chunk) {
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
