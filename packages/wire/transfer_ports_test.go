package wire

import (
	"bytes"
	"testing"
)

// TestSHA256DigestStateRoundTrip pins the V13-PR05 digest checkpoint capability: a
// serialized state restores to exactly the digest of the prefix fed so far, restore fails
// closed on foreign or truncated bytes, and MarshalState never disturbs the live digest.
func TestSHA256DigestStateRoundTrip(t *testing.T) {
	prefix := []byte("the quick brown fox jumps over the lazy dog")
	suffix := []byte(" and then some more bytes past a compression boundary")

	live := NewSHA256Digest()
	live.Update(prefix)
	state, err := live.(DigestState).MarshalState()
	if err != nil {
		t.Fatalf("MarshalState: %v", err)
	}
	if len(state) == 0 {
		t.Fatal("serialized state is empty")
	}
	// The digest remains usable after marshaling, exactly like Sum.
	live.Update(suffix)
	want := live.HexDigest()

	restored, err := RestoreSHA256Digest(state)
	if err != nil {
		t.Fatalf("RestoreSHA256Digest: %v", err)
	}
	restored.Update(suffix)
	if got := restored.HexDigest(); got != want {
		t.Fatalf("restored digest = %s, want %s (restore must equal hashing the prefix)", got, want)
	}

	// A state covering a DIFFERENT prefix must produce a different final digest — the
	// state is trusted only insofar as the final verification catches it.
	other := NewSHA256Digest()
	other.Update([]byte("different prefix"))
	otherState, err := other.(DigestState).MarshalState()
	if err != nil {
		t.Fatalf("MarshalState: %v", err)
	}
	restoredOther, err := RestoreSHA256Digest(otherState)
	if err != nil {
		t.Fatalf("RestoreSHA256Digest(other): %v", err)
	}
	restoredOther.Update(suffix)
	if got := restoredOther.HexDigest(); got == want {
		t.Fatal("restore of a different prefix must not equal the original digest")
	}

	// Foreign and truncated state fail closed — never guessed.
	if _, err := RestoreSHA256Digest([]byte("not a sha256 state")); err == nil {
		t.Fatal("garbage state must be rejected")
	}
	if _, err := RestoreSHA256Digest(state[:len(state)-1]); err == nil {
		t.Fatal("truncated state must be rejected")
	}
	if _, err := RestoreSHA256Digest(nil); err == nil {
		t.Fatal("empty state must be rejected")
	}

	// Cross-check against a full re-hash on a longer input spanning block boundaries.
	big := make([]byte, 3*1024)
	for i := range big {
		big[i] = byte(i * 7)
	}
	a := NewSHA256Digest()
	a.Update(big[:900])
	bigState, err := a.(DigestState).MarshalState()
	if err != nil {
		t.Fatalf("MarshalState(big): %v", err)
	}
	b, err := RestoreSHA256Digest(bigState)
	if err != nil {
		t.Fatalf("RestoreSHA256Digest(big): %v", err)
	}
	a.Update(big[900:])
	b.Update(big[900:])
	if a.HexDigest() != b.HexDigest() {
		t.Fatal("restore + continuation must equal one-shot hashing")
	}
	oneShot := NewSHA256Digest()
	oneShot.Update(big)
	if b.HexDigest() != oneShot.HexDigest() {
		t.Fatal("restored continuation must equal one-shot hashing of the whole input")
	}
}

func TestMemorySinkReassemblesOutOfOrder(t *testing.T) {
	var s MemorySink
	if err := s.Write(4, []byte{5, 6, 7, 8}); err != nil {
		t.Fatal(err)
	}
	if err := s.Write(0, []byte{1, 2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if got, want := s.Bytes(), []byte{1, 2, 3, 4, 5, 6, 7, 8}; !bytes.Equal(got, want) {
		t.Errorf("Bytes() = %v, want %v", got, want)
	}
	if !s.IsClosed() {
		t.Error("IsClosed() = false after Close()")
	}
}

func TestMemorySinkCopiesWrites(t *testing.T) {
	var s MemorySink
	buf := []byte{1, 2, 3}
	if err := s.Write(0, buf); err != nil {
		t.Fatal(err)
	}
	buf[0] = 9 // mutate the caller's buffer; the sink must have copied.
	if got := s.Bytes(); got[0] != 1 {
		t.Errorf("sink retained caller buffer: got[0] = %d, want 1", got[0])
	}
}

func TestMemorySinkAbortRefusesWrites(t *testing.T) {
	var s MemorySink
	if err := s.Abort("integrity"); err != nil {
		t.Fatal(err)
	}
	if got := s.AbortReason(); got != "integrity" {
		t.Errorf("AbortReason() = %q, want %q", got, "integrity")
	}
	if err := s.Write(0, []byte{1}); err == nil {
		t.Error("Write after Abort should fail")
	}
}

func TestMemorySinkAbortDefaultReason(t *testing.T) {
	var s MemorySink
	if err := s.Abort(""); err != nil {
		t.Fatal(err)
	}
	if got := s.AbortReason(); got != "aborted" {
		t.Errorf("AbortReason() = %q, want %q", got, "aborted")
	}
}

func TestBytesSourceReStreamsInChunks(t *testing.T) {
	data := make([]byte, 200)
	for i := range data {
		data[i] = byte(i % 256)
	}
	src := BytesSource(data, FileMeta{Name: "f", Size: 200}, 64)

	// Re-callable: two independent passes must yield identical bytes and chunk sizes.
	for pass := 0; pass < 2; pass++ {
		var got []byte
		var sizes []int
		if err := src.Stream(func(c []byte) error {
			sizes = append(sizes, len(c))
			got = append(got, c...)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, data) {
			t.Errorf("pass %d: bytes mismatch", pass)
		}
		if want := []int{64, 64, 64, 8}; !equalInts(sizes, want) {
			t.Errorf("pass %d: chunk sizes = %v, want %v", pass, sizes, want)
		}
	}
}

func TestBytesSourceEmpty(t *testing.T) {
	src := BytesSource(nil, FileMeta{Name: "f"}, 0) // chunk 0 -> default; empty data.
	calls := 0
	if err := src.Stream(func([]byte) error { calls++; return nil }); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Errorf("empty source yielded %d chunks, want 0", calls)
	}
}

func TestBytesSourceStreamPropagatesError(t *testing.T) {
	src := BytesSource([]byte{1, 2, 3, 4}, FileMeta{}, 2)
	sentinel := NewTransferError(FailSinkError, "boom")
	calls := 0
	err := src.Stream(func([]byte) error { calls++; return sentinel })
	if err != sentinel {
		t.Errorf("Stream error = %v, want sentinel", err)
	}
	if calls != 1 {
		t.Errorf("Stream kept going after error: %d calls, want 1", calls)
	}
}

func TestTransferErrorMessage(t *testing.T) {
	if got := NewTransferError(FailDigestMismatch, "").Error(); got != "digest_mismatch" {
		t.Errorf("bare reason = %q, want %q", got, "digest_mismatch")
	}
	if got := NewTransferError(FailIntegrity, "block 3").Error(); got != "integrity: block 3" {
		t.Errorf("reason+message = %q, want %q", got, "integrity: block 3")
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
