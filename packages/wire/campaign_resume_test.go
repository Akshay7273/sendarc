//go:build campaign

// V13-PR08 campaign: prove a very large logical transfer (>= 100 GiB by default) can resume
// from a deep durable checkpoint with bounded memory and no full-file staging.
//
// Methodology:
//   - The source is DETERMINISTIC and GENERATED on the fly (never materialized): each chunk is
//     computed from its absolute offset by a fixed formula, so both the sender's digest pass and
//     its block stream reproduce identical bytes without ever holding the file in RAM or on disk.
//   - The receiver sink is a VERIFYING COUNTER: it recomputes the expected bytes for every write
//     from the offset (a streaming self-check), counts acknowledged blocks, and keeps a rolling
//     digest — it never stores more than one block.
//   - Resume from a deep checkpoint: haveBlocks = 68% of the transfer's blocks (the default).
//     The seed digest is built by streaming the generated prefix (bounded memory), and the
//     resumed leg must send ONLY the missing suffix.
//   - Whole-file correctness is enforced by the receiver's mandatory final digest check against
//     the manifest (which the sender computes by streaming the same generated content), plus an
//     independent expected-digest computed once here.
//   - Peak memory is sampled every 10ms via runtime.ReadMemStats during the resumed leg and
//     asserted against a hard bound far below the logical size.
//
// This is a CI-only harness: `go test -tags campaign ./packages/wire/ -run TestCampaign -v`.
// Logical size is configurable: SENDBEAM_CAMPAIGN_GIB=100 (default). Do NOT run 100 GiB on a
// laptop — the GitHub Actions job owns the full campaign.

package wire

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// campaignSourceChunk bounds each generated chunk (64 KiB, matching the CLI source).
const campaignSourceChunk = 64 * 1024

// campaignGeneratedSource streams deterministic bytes derived from the absolute offset:
// byte(i) = (i*29 + 7) & 0xff. Same formula on every Stream call, so the sender's digest pass
// and its block pass (and the receiver's independent check) all agree without storage.
type campaignGeneratedSource struct {
	size  int64
	meta  FileMeta
	chunk int64
}

func newCampaignSource(size int64, name string) *campaignGeneratedSource {
	return &campaignGeneratedSource{
		size:  size,
		meta:  FileMeta{Name: name, Size: size, Mime: "application/octet-stream", LastModified: 1},
		chunk: campaignSourceChunk,
	}
}

func (g *campaignGeneratedSource) Meta() FileMeta { return g.meta }

func (g *campaignGeneratedSource) Stream(fn func(chunk []byte) error) error {
	buf := make([]byte, g.chunk)
	var off int64
	for off < g.size {
		n := g.chunk
		if off+n > g.size {
			n = g.size - off
		}
		fillCampaignBytes(buf[:n], off)
		if err := fn(buf[:n]); err != nil {
			return err
		}
		off += n
	}
	return nil
}

// campaignLUT is the 256-byte period of the generated sequence (29 is coprime with 256, so
// (i*29+7) mod 256 is a full permutation with period 256). Filling is a table copy per period
// instead of a per-byte multiply, which matters when streaming hundreds of GiB in CI.
var campaignLUT = func() [256]byte {
	var lut [256]byte
	for i := range lut {
		lut[i] = byte(i*29 + 7)
	}
	return lut
}()

// fillCampaignBytes writes the deterministic byte sequence for [base, base+len(b)). The
// sequence is periodic with period 256, so a chunk is the LUT rotated by base mod 256; fill
// is memcpy-based (finish the current period, then full periods) rather than byte-wise.
func fillCampaignBytes(b []byte, base int64) {
	start := int(base % 256)
	n := copy(b, campaignLUT[start:])
	if n < len(b) && start > 0 {
		n += copy(b[n:], campaignLUT[:start])
	}
	for n < len(b) {
		n += copy(b[n:], campaignLUT[:])
	}
}

// errCampaignPrefixDone stops the source stream once the prefix digest is complete, so the
// full source is never generated for a prefix-only digest.
var errCampaignPrefixDone = fmt.Errorf("campaign prefix digest complete")

// campaignDigestOfPrefix streams [0, bytes) of the generated content through a digest without
// materializing the prefix — the same path a reloaded receiver's seed rebuild would take.
func campaignDigestOfPrefix(size, bytes int64) Digest {
	d := NewSHA256Digest()
	src := newCampaignSource(size, "f")
	remaining := bytes
	_ = src.Stream(func(chunk []byte) error {
		if remaining <= 0 {
			return errCampaignPrefixDone // stop early; do not generate the rest of the source
		}
		n := int64(len(chunk))
		if n > remaining {
			n = remaining
		}
		d.Update(chunk[:n])
		remaining -= n
		return nil
	})
	return d
}

// campaignSink verifies every write against the generated formula, counts acknowledged blocks,
// and keeps a rolling digest. It stores at most one block's bytes — the full transfer is never
// staged in memory (no full-file staging, streamed block processing).
type campaignSink struct {
	blockSize   int64
	verified    int64 // bytes verified so far (monotonic, ordered writes only)
	blocks      int64 // complete blocks verified
	digest      Digest
	mu          sync.Mutex
	failOnWrite atomic.Bool
}

func newCampaignSink(blockSize int64) *campaignSink {
	return &campaignSink{blockSize: blockSize, digest: NewSHA256Digest()}
}

func (s *campaignSink) Write(offset int64, data []byte) error {
	if s.failOnWrite.Load() {
		return fmt.Errorf("campaign sink: forced write failure (crash injection)")
	}
	expected := make([]byte, len(data))
	fillCampaignBytes(expected, offset)
	if !bytes.Equal(data, expected) {
		for i := range data {
			if data[i] != expected[i] {
				return fmt.Errorf("campaign sink: byte %d mismatch at offset %d (want %d, got %d)", i, offset+int64(i), expected[i], data[i])
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.digest.Update(data)
	s.verified = offset + int64(len(data))
	s.blocks = s.verified / s.blockSize
	return nil
}

func (s *campaignSink) Close() error       { return nil }
func (s *campaignSink) Abort(string) error { return nil }

// campaignPeakMemory samples peak HeapAlloc while the resumed leg runs.
type campaignPeakMemory struct {
	stop  chan struct{}
	done  chan struct{}
	peak  atomic.Int64
	bytes atomic.Int64 // total bytes allocated during the window (cumulative)
}

func newCampaignPeakMemory() *campaignPeakMemory {
	m := &campaignPeakMemory{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(m.done)
		var ms runtime.MemStats
		for {
			select {
			case <-m.stop:
				return
			default:
			}
			runtime.ReadMemStats(&ms)
			if int64(ms.HeapAlloc) > m.peak.Load() {
				m.peak.Store(int64(ms.HeapAlloc))
			}
			m.bytes.Store(int64(ms.TotalAlloc))
			time.Sleep(10 * time.Millisecond)
		}
	}()
	return m
}

func (m *campaignPeakMemory) close() {
	close(m.stop)
	<-m.done
}

// runCampaignLeg wires the sender to the receiver over ordered buffered channels and runs the
// resumed leg to completion. Returns the receiver result and the number of DISTINCT blocks the
// sender streamed (only missing blocks may be sent). The frame header rides as plaintext AAD
// (counter(8) || header(16) || ...), so type and block index are readable without decrypting:
// Type at byte 9, BlockIdx (big-endian u32) at bytes 14:18.
func runCampaignLeg(t *testing.T, src FileSource, resume *ReceiverResume, sink *campaignSink, blockSize, window int) (recvRes ReceiveResult, blocksSent int64) {
	t.Helper()
	keys, err := DeriveTransferKeys(loopbackMaster())
	if err != nil {
		t.Fatal(err)
	}
	s2r := make(chan []byte, 4096)
	r2s := make(chan []byte, 4096)
	cp := func(f []byte) []byte { return append([]byte(nil), f...) }

	sender := NewSender(SenderOptions{
		File:       src,
		Send:       func(f []byte) error { s2r <- cp(f); return nil },
		SendDir:    keys.O2J,
		RecvDir:    keys.J2O,
		BlockSize:  blockSize,
		FrameSize:  16 * 1024, // production-shaped 16 KiB frames; Seal caps payloads at u16 max
		Window:     window,
		TransferID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	receiver := NewReceiver(ReceiverOptions{
		Send:         func(f []byte) error { r2s <- cp(f); return nil },
		SendDir:      keys.J2O,
		RecvDir:      keys.O2J,
		Sink:         sink,
		CreateDigest: NewSHA256Digest,
		Resume:       resume,
	})
	// Distinct block indices seen on the wire; one block may span many frames.
	seen := make(map[uint32]struct{})
	var seenMu sync.Mutex
	go func() {
		for f := range s2r {
			if len(f) >= 18 && f[9] == FrameBlockData {
				idx := uint32(f[14])<<24 | uint32(f[15])<<16 | uint32(f[16])<<8 | uint32(f[17])
				seenMu.Lock()
				seen[idx] = struct{}{}
				seenMu.Unlock()
			}
			receiver.Handle(f)
		}
	}()
	go func() {
		for f := range r2s {
			sender.Handle(f)
		}
	}()

	runErrCh := make(chan error, 1)
	go func() {
		_, e := sender.Run(context.Background())
		runErrCh <- e
	}()
	recvCh := make(chan struct{})
	var recvOut ReceiveResult
	var recvErr error
	go func() {
		recvOut, recvErr = receiver.Wait(context.Background())
		close(recvCh)
	}()
	timer := time.NewTimer(85 * time.Minute)
	defer timer.Stop()
	for done := false; !done; {
		select {
		case runErr := <-runErrCh:
			if runErr != nil {
				t.Fatalf("sender: %v", runErr)
			}
			done = true
		case <-recvCh:
			if recvErr != nil {
				t.Fatalf("receiver: %v", recvErr)
			}
			done = true
		case <-timer.C:
			t.Fatal("campaign leg did not settle within 60 minutes")
		}
	}
	close(s2r)
	close(r2s)
	seenMu.Lock()
	blocksSent = int64(len(seen))
	seenMu.Unlock()
	return recvOut, blocksSent
}

// TestCampaign100GiBResume proves a >= 100 GiB logical transfer resumes from a deep durable
// checkpoint: only the missing suffix is sent, the whole file is still verified, and peak
// memory stays far below the logical size (bounded memory, no full-file staging).
func TestCampaign100GiBResume(t *testing.T) {
	gib := int64(100)
	if v := os.Getenv("SENDBEAM_CAMPAIGN_GIB"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			t.Fatalf("SENDBEAM_CAMPAIGN_GIB must be a positive integer, got %q", v)
		}
		gib = n
	}
	const blockSize = 1024 * 1024 // 1 MiB blocks (matches negotiated production geometry)
	size := gib * 1024 * 1024 * 1024
	blocks := (size-1)/blockSize + 1
	// Deep checkpoint: 68% of the transfer is already durable from the interrupted session.
	haveBlocks := blocks * 68 / 100
	if haveBlocks < 1 {
		haveBlocks = 1
	}
	t.Logf("campaign: logical size = %d GiB (%d bytes), %d blocks of %d bytes, resume from %d blocks (%.1f%%)",
		gib, size, blocks, blockSize, haveBlocks, float64(haveBlocks)/float64(blocks)*100)

	// Independent expected digest: stream the generated content once, bounded memory.
	expected := campaignDigestOfPrefix(size, size)

	// Seed digest over the durable prefix [0, haveBlocks*blockSize) — what a reloaded receiver
	// would rebuild from its verified partial.
	prefixBytes := haveBlocks * blockSize
	if prefixBytes > size {
		prefixBytes = size
	}
	seed := campaignDigestOfPrefix(size, prefixBytes)

	// The resume claims the SAME manifest the sender is about to stream (V13-PR06 binding).
	src := newCampaignSource(size, "f")
	// Compute the canonical manifest fingerprint from the sender's geometry.
	manifest := Manifest{
		Type:       FrameManifest,
		TransferID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Files: []FileEntry{{
			Idx: 0, Name: "f", Size: size, Mime: "application/octet-stream",
			LastModified: 1, BlockSize: blockSize, Blocks: int(blocks),
			FileDigest: expected.HexDigest(),
		}},
		TotalSize: size,
	}
	fingerprint, err := ManifestFingerprint(manifest)
	if err != nil {
		t.Fatal(err)
	}
	resume := &ReceiverResume{
		TransferID:          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ManifestFingerprint: fingerprint,
		Files: map[int]ResumeFileProgress{
			0: {HaveBlocks: int(haveBlocks), SeedDigest: seed},
		},
	}

	sink := newCampaignSink(blockSize)
	peak := newCampaignPeakMemory()
	start := time.Now()
	recvRes, blockFrames := runCampaignLeg(t, src, resume, sink, blockSize, 8)
	elapsed := time.Since(start)
	peak.close()

	// Only the missing suffix may be sent.
	wantFrames := blocks - haveBlocks
	if blockFrames != wantFrames {
		t.Errorf("sent %d block frames, want exactly %d (only the missing suffix)", blockFrames, wantFrames)
	}
	// The receiver verified the FULL file (seed + missing suffix) against the manifest digest.
	if recvRes.Digest != expected.HexDigest() {
		t.Errorf("receiver digest = %s, want %s", recvRes.Digest, expected.HexDigest())
	}
	// The sink verified every byte against the generated formula and saw the whole file.
	if sink.verified != size {
		t.Errorf("sink verified %d bytes, want %d", sink.verified, size)
	}
	if sink.blocks != blocks {
		t.Errorf("sink counted %d blocks, want %d", sink.blocks, blocks)
	}

	peakBytes := peak.peak.Load()
	t.Logf("campaign: resumed leg completed in %s; peak HeapAlloc = %d bytes (%.2f MiB); "+
		"logical size = %d bytes; logical/peak ratio = %.0fx", elapsed, peakBytes,
		float64(peakBytes)/1024/1024, size, float64(size)/float64(peakBytes))

	// Hard bound: peak heap must stay far below the logical size. The sender's window + frames
	// keep live memory to a few MiB regardless of the 100+ GiB logical transfer.
	bound := int64(512 * 1024 * 1024) // 512 MiB
	if peakBytes > bound {
		t.Errorf("peak heap %d bytes exceeds the %d-byte bound; the campaign must stream with bounded memory", peakBytes, bound)
	}
}

// TestCampaignZeroByteResumeAfterAllDurable proves a successful resume may transfer ZERO file
// bytes: when every block was already durable before the restart, resume_state claims all
// blocks, the sender streams nothing, and whole-file verification still occurs (V13-PR08).
func TestCampaignZeroByteResumeAfterAllDurable(t *testing.T) {
	const size = 8 * 1024 * 1024 * 1024 // 8 GiB logical (the zero-byte property is size-independent)
	const blockSize = 1024 * 1024
	blocks := size / blockSize
	haveBlocks := blocks // all durable

	src := newCampaignSource(size, "f")
	expected := campaignDigestOfPrefix(size, size)
	seed := campaignDigestOfPrefix(size, size)
	manifest := Manifest{
		Type:       FrameManifest,
		TransferID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Files: []FileEntry{{
			Idx: 0, Name: "f", Size: size, Mime: "application/octet-stream",
			LastModified: 1, BlockSize: blockSize, Blocks: int(blocks),
			FileDigest: expected.HexDigest(),
		}},
		TotalSize: size,
	}
	fingerprint, err := ManifestFingerprint(manifest)
	if err != nil {
		t.Fatal(err)
	}
	resume := &ReceiverResume{
		TransferID:          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ManifestFingerprint: fingerprint,
		Files: map[int]ResumeFileProgress{
			0: {HaveBlocks: int(haveBlocks), SeedDigest: seed},
		},
	}
	sink := newCampaignSink(blockSize)
	peak := newCampaignPeakMemory()
	start := time.Now()
	recvRes, blockFrames := runCampaignLeg(t, src, resume, sink, blockSize, 8)
	elapsed := time.Since(start)
	peak.close()

	if blockFrames != 0 {
		t.Errorf("sent %d block frames, want 0 (everything was already durable)", blockFrames)
	}
	if recvRes.Digest != expected.HexDigest() {
		t.Errorf("receiver digest = %s, want %s", recvRes.Digest, expected.HexDigest())
	}
	t.Logf("campaign: zero-byte resume completed in %s; peak HeapAlloc = %.2f MiB", elapsed,
		float64(peak.peak.Load())/1024/1024)
}
