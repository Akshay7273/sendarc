package wire

import (
	"testing"
)

// Benchmarks for the transfer engine's hot path. Run with:
//
//	go test -bench . -benchmem ./...
//
// The loopback benchmark drives a full sender→receiver transfer over in-memory channels
// and reports aggregate throughput; Seal/Open and the MAC bench the per-frame crypto.

var benchPayload = func() []byte {
	p := make([]byte, 16*1024)
	for i := range p {
		p[i] = byte((i*131 + 7) & 0xff)
	}
	return p
}()

func benchDir() DirectionalKey {
	key := make([]byte, 32)
	salt := []byte{0x01, 0x02, 0x03, 0x04}
	for i := range key {
		key[i] = byte(i)
	}
	return DirectionalKey{Key: key, Salt: salt}
}

func BenchmarkSeal(b *testing.B) {
	dir := benchDir()
	h := FrameHeaderInput{Version: 1, Type: 3, FileIdx: 0, BlockIdx: 1, FrameOff: 2}
	b.SetBytes(int64(len(benchPayload)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Seal(dir, uint64(i), h, benchPayload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOpen(b *testing.B) {
	dir := benchDir()
	h := FrameHeaderInput{Version: 1, Type: 3, FileIdx: 0, BlockIdx: 1, FrameOff: 2}
	sealed, err := Seal(dir, 0, h, benchPayload)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(benchPayload)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Open(dir, 0, sealed); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignSignal(b *testing.B) {
	kAuth := benchDir().Key
	body := "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n"
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		SignSignal(kAuth, SignalSDP, 7, uint32(i), body)
	}
}

func BenchmarkTransferLoopback(b *testing.B) {
	data := make([]byte, 16<<20) // 16 MiB
	for i := range data {
		data[i] = byte((i*131 + 7) & 0xff)
	}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		res := runLoopback(b, data, 1<<20, 16<<10, 8, false)
		if res.runErr != nil {
			b.Fatalf("sender: %v", res.runErr)
		}
		if res.recvErr != nil {
			b.Fatalf("receiver: %v", res.recvErr)
		}
	}
}
