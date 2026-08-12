package wire

import (
	"errors"
	"os"
	"testing"
	"time"
)

// faultSink wraps a MemorySink and fails a chosen write (1-based) or Close with
// a chosen error, mirroring disk failures on the receive side (SB-1125).
type faultSink struct {
	*MemorySink
	failWriteAt int
	writeErr    error
	closeErr    error
	writes      int
}

func (f *faultSink) Write(offset int64, bytes []byte) error {
	f.writes++
	if f.writes == f.failWriteAt && f.writeErr != nil {
		return f.writeErr
	}
	return f.MemorySink.Write(offset, bytes)
}

func (f *faultSink) Close() error {
	if f.closeErr != nil {
		return f.closeErr
	}
	return f.MemorySink.Close()
}

// faultDestination fails on Open (destination collision) or Close (commit/flush
// failure) exactly where the wire layer must surface FailSinkError (SB-1125).
type faultDestination struct {
	openErr  error
	closeErr error
	sinks    []*faultSink
}

func (d *faultDestination) Prepare(Manifest) error { return nil }

func (d *faultDestination) Open(FileEntry) (Sink, error) {
	if d.openErr != nil {
		return nil, d.openErr
	}
	s := &faultSink{MemorySink: &MemorySink{}}
	d.sinks = append(d.sinks, s)
	return s, nil
}

func (d *faultDestination) Close() error { return d.closeErr }

func (d *faultDestination) Abort(reason string) error {
	for _, s := range d.sinks {
		_ = s.Abort(reason)
	}
	return nil
}

// faultSource serves a different byte stream per pass so tests can inject file
// disappearance, mid-read failure, and file mutation between the digest pass
// and the transfer pass (SB-1126). Stream is called exactly twice by Sender.Run.
type faultSource struct {
	meta   FileMeta
	passes [2][]byte
	errs   [2]error
	failAt [2]int // bytes emitted before failing on this pass; 0 fails immediately
	calls  int
}

func (s *faultSource) Meta() FileMeta { return s.meta }

func (s *faultSource) Stream(fn func(chunk []byte) error) error {
	if s.calls > 1 {
		return errors.New("faultSource: Stream called more than twice")
	}
	pass := s.calls
	s.calls++
	data := s.passes[pass]
	limit := len(data)
	if s.failAt[pass] > 0 && s.failAt[pass] < limit {
		limit = s.failAt[pass]
	}
	for off := 0; off < limit; off += 512 {
		end := off + 512
		if end > limit {
			end = limit
		}
		if err := fn(data[off:end]); err != nil {
			return err
		}
	}
	return s.errs[pass]
}

// failReasonOf extracts the transfer fail reason from an error, or reports no.
func failReasonOf(err error) (FailReason, bool) {
	var te *TransferError
	if errors.As(err, &te) {
		return te.Reason, true
	}
	return "", false
}

// TestFaultDroppedManifestFailsClosed pins that a manifest lost without a path
// change still fails the transfer cleanly: pre-manifest data is ignored, the
// sender exhausts its retries, and the peer learns of the failure.
func TestFaultDroppedManifestFailsClosed(t *testing.T) {
	data := testData(64_000, 79)
	res := runFaultLoopback(t, data, 1024, 256, 4,
		faultScript{}.at(dirS2R, FrameManifest, fDrop), nil,
		faultRunOptions{ackTimeout: 120 * time.Millisecond, maxRetries: 3, deadline: 4 * time.Second})
	if res.runErr == nil {
		t.Fatal("sender must fail when the manifest is lost")
	}
	if res.recvSettled {
		t.Fatal("receiver must not settle without a manifest")
	}
	if reason, ok := failReasonOf(res.runErr); !ok || reason != FailRetryExhausted {
		t.Fatalf("sender reason = %q, %v; want retry exhaustion", reason, res.runErr)
	}
}

// TestFaultManifestRetransmittedOnCutover pins that a path change after the
// manifest was lost retransmits it, and the receiver's ignored pre-manifest
// data plus the identical-duplicate tolerance let the transfer complete.
func TestFaultManifestRetransmittedOnCutover(t *testing.T) {
	data := testData(64_000, 83)
	res := runFaultLoopback(t, data, 1024, 256, 4,
		faultScript{}.at(dirS2R, FrameManifest, fDrop), nil,
		faultRunOptions{
			cutover: func(_ *faultLink, sender *Sender) { sender.TransportChanged() },
		})
	res.wantSuccess(t, data)
}

// TestFaultDuplicateManifestIsIgnored pins that a path change retransmitting an
// identical manifest does not abort the transfer.
func TestFaultDuplicateManifestIsIgnored(t *testing.T) {
	data := testData(32_000, 97)
	res := runFaultLoopback(t, data, 1024, 256, 4,
		faultScript{}.at(dirS2R, FrameManifest, fDuplicate), nil,
		faultRunOptions{
			cutover: func(_ *faultLink, sender *Sender) { sender.TransportChanged() },
		})
	res.wantSuccess(t, data)
}

// TestFaultSinkQuotaAbortsTransfer pins that a typed FailQuota returned by the
// sink survives as-is on both sides and the partial output is discarded.
func TestFaultSinkQuotaAbortsTransfer(t *testing.T) {
	data := testData(200_000, 41)
	s := &faultSink{MemorySink: &MemorySink{},
		failWriteAt: 5, writeErr: NewTransferError(FailQuota, "no space left on device")}
	res := runFaultLoopback(t, data, 1024, 256, 4, faultScript{}, nil,
		faultRunOptions{sink: s})
	if reason, ok := failReasonOf(res.recvErr); !ok || reason != FailQuota {
		t.Fatalf("receiver reason = %q, %v; want FailQuota", reason, res.recvErr)
	}
	if reason, ok := failReasonOf(res.runErr); !ok || reason != FailQuota {
		t.Fatalf("sender reason = %q, %v; want FailQuota", reason, res.runErr)
	}
	if s.AbortReason() == "" {
		t.Fatal("sink was not aborted after a quota failure")
	}
	if s.IsClosed() {
		t.Fatal("sink was closed despite the failure")
	}
}

// TestFaultSinkWriteFailureAborts pins that a plain disk error surfaces as
// FailSinkError on both sides and no bytes are ever committed.
func TestFaultSinkWriteFailureAborts(t *testing.T) {
	data := testData(120_000, 43)
	s := &faultSink{MemorySink: &MemorySink{},
		failWriteAt: 3, writeErr: errors.New("permission revoked: open /mnt/out/f: EACCES")}
	res := runFaultLoopback(t, data, 1024, 256, 4, faultScript{}, nil,
		faultRunOptions{sink: s})
	if reason, ok := failReasonOf(res.recvErr); !ok || reason != FailSinkError {
		t.Fatalf("receiver reason = %q, %v; want FailSinkError", reason, res.recvErr)
	}
	if reason, ok := failReasonOf(res.runErr); !ok || reason != FailSinkError {
		t.Fatalf("sender reason = %q, %v; want FailSinkError", reason, res.runErr)
	}
	if s.AbortReason() == "" {
		t.Fatal("sink was not aborted after a write failure")
	}
}

// TestFaultSinkCloseFailureAborts pins that a failing Close on the fully
// received file still aborts the transfer instead of committing it.
func TestFaultSinkCloseFailureAborts(t *testing.T) {
	data := testData(64_000, 47)
	s := &faultSink{MemorySink: &MemorySink{},
		closeErr: errors.New("flush failed: EIO")}
	res := runFaultLoopback(t, data, 1024, 256, 4, faultScript{}, nil,
		faultRunOptions{sink: s})
	if reason, ok := failReasonOf(res.recvErr); !ok || reason != FailSinkError {
		t.Fatalf("receiver reason = %q, %v; want FailSinkError", reason, res.recvErr)
	}
	if reason, ok := failReasonOf(res.runErr); !ok || reason != FailSinkError {
		t.Fatalf("sender reason = %q, %v; want FailSinkError", reason, res.runErr)
	}
	if s.AbortReason() == "" {
		t.Fatal("sink was not aborted when Close failed")
	}
	if s.IsClosed() {
		t.Fatal("sink Close must not be considered successful")
	}
}

// TestFaultDestinationCollisionAborts pins that a destination refusing to open
// (file already exists, no overwrite) aborts before a single byte is written.
func TestFaultDestinationCollisionAborts(t *testing.T) {
	data := testData(80_000, 53)
	dest := &faultDestination{openErr: errors.New("destination exists; refusing to overwrite")}
	res := runFaultLoopback(t, data, 1024, 256, 4, faultScript{}, nil,
		faultRunOptions{destination: dest})
	if reason, ok := failReasonOf(res.recvErr); !ok || reason != FailSinkError {
		t.Fatalf("receiver reason = %q, %v; want FailSinkError", reason, res.recvErr)
	}
	if reason, ok := failReasonOf(res.runErr); !ok || reason != FailSinkError {
		t.Fatalf("sender reason = %q, %v; want FailSinkError", reason, res.runErr)
	}
	if len(dest.sinks) != 0 {
		t.Fatalf("destination opened %d sinks on a collision; want 0", len(dest.sinks))
	}
}

// TestFaultDestinationFlushFailureAborts pins that a commit-time (flush)
// failure after every block was verified still discards the output.
func TestFaultDestinationFlushFailureAborts(t *testing.T) {
	data := testData(64_000, 59)
	dest := &faultDestination{closeErr: errors.New("flush failed: EIO")}
	res := runFaultLoopback(t, data, 1024, 256, 4, faultScript{}, nil,
		faultRunOptions{destination: dest})
	if reason, ok := failReasonOf(res.recvErr); !ok || reason != FailSinkError {
		t.Fatalf("receiver reason = %q, %v; want FailSinkError", reason, res.recvErr)
	}
	if reason, ok := failReasonOf(res.runErr); !ok || reason != FailSinkError {
		t.Fatalf("sender reason = %q, %v; want FailSinkError", reason, res.runErr)
	}
	if len(dest.sinks) != 1 {
		t.Fatalf("destination opened %d sinks; want 1", len(dest.sinks))
	}
	if got := string(dest.sinks[0].Bytes()); got != string(data) {
		t.Fatal("all bytes were verified and written before the flush failure")
	}
	if dest.sinks[0].AbortReason() == "" {
		t.Fatal("written output was not aborted after the flush failure")
	}
}

// TestFaultSourceDisappearsBeforeDigest pins that a source vanishing before the
// digest pass fails the sender with SOURCE_IO and the receiver never settles.
func TestFaultSourceDisappearsBeforeDigest(t *testing.T) {
	data := testData(100_000, 61)
	src := &faultSource{meta: FileMeta{Name: "gone", Size: int64(len(data))}}
	src.passes[0] = data
	src.errs[0] = os.ErrNotExist
	res := runFaultLoopback(t, data, 1024, 256, 4, faultScript{}, nil,
		faultRunOptions{source: src, deadline: 2 * time.Second})
	if res.runErr == nil || CodeOf(res.runErr) != CodeSourceIO {
		t.Fatalf("sender error = %v; want SOURCE_IO", res.runErr)
	}
	if res.recvSettled {
		t.Fatal("receiver settled although no manifest was ever sent")
	}
}

// TestFaultSourceReadFailsMidTransfer pins that a read failure after the digest
// pass fails the sender with SOURCE_IO and the partial transfer never commits.
func TestFaultSourceReadFailsMidTransfer(t *testing.T) {
	data := testData(200_000, 67)
	src := &faultSource{meta: FileMeta{Name: "bad", Size: int64(len(data))}}
	src.passes[0] = data
	src.passes[1] = data
	src.failAt[1] = 4096
	src.errs[1] = errors.New("read /dev/sda1: EIO")
	res := runFaultLoopback(t, data, 1024, 256, 4, faultScript{}, nil,
		faultRunOptions{source: src, ackTimeout: 120 * time.Millisecond, deadline: 2 * time.Second})
	if res.runErr == nil || CodeOf(res.runErr) != CodeSourceIO {
		t.Fatalf("sender error = %v; want SOURCE_IO", res.runErr)
	}
	if res.recvSettled {
		t.Fatal("receiver settled on a partial transfer")
	}
	if res.recvErr == nil {
		t.Fatal("receiver must report an error on an aborted source")
	}
}

// TestFaultSourceMutatesBetweenPasses pins that a file changing between the
// digest pass and the transfer pass fails closed on digest verification.
func TestFaultSourceMutatesBetweenPasses(t *testing.T) {
	data := testData(200_000, 71)
	src := &faultSource{meta: FileMeta{Name: "mut", Size: int64(len(data))}}
	src.passes[0] = data
	src.passes[1] = testData(150_000, 73)
	res := runFaultLoopback(t, data, 1024, 256, 4, faultScript{}, nil,
		faultRunOptions{source: src, ackTimeout: 120 * time.Millisecond})
	if res.recvErr == nil {
		t.Fatal("receiver accepted a file that changed mid-transfer")
	}
	reason, ok := failReasonOf(res.recvErr)
	if !ok || (reason != FailDigestMismatch && reason != FailIntegrity) {
		t.Fatalf("receiver reason = %q, %v; want digest mismatch or integrity", reason, res.recvErr)
	}
	if res.runErr == nil {
		t.Fatal("sender must fail once the receiver rejects the mutation")
	}
	if res.sink.AbortReason() == "" {
		t.Fatal("output was not discarded after the mutation was detected")
	}
}
