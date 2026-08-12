package wire

import (
	"math"
	"testing"
)

// SB-1141 (wire): fuzz the transfer control-message decoders via DecodeControl.
// Every per-type decoder is exercised by arbitrary payloads; the fragment sizes
// and numeric ranges are validated later, so the invariant is "never panic, never
// reject a structurally valid round-trip".
func FuzzDecodeControl(f *testing.F) {
	seeds := []string{
		`{"type":2,"files":[{"idx":0,"name":"a.txt","size":0,"mime":"","lastModified":1,"blockSize":8,"blocks":0,"fileDigest":"aa"}],"totalSize":0}`,
		`{"type":4,"fileIdx":0,"blockIdx":0,"sha256":"aa"}`,
		`{"type":6,"fileIdx":0,"blockIdx":1}`,
		`{"type":7,"fileIdx":0,"blockIdx":1,"reason":"integrity"}`,
		`{"type":8,"op":"pause"}`,
		`{"type":9,"fileDigest":"aa"}`,
		`{"type":11,"reason":"integrity"}`,
		`{"type":12,"transferId":"x","files":[{"idx":0,"haveBlocks":3}]}`,
		`{"type":10}`,
		`{}`,
		`{"type":200}`,
		`not json`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		msg, err := DecodeControl(payload)
		if err != nil {
			return
		}
		// Re-encoding a decoded message must not panic and must stay a valid
		// JSON control frame (round-trip integrity for structurally valid input).
		re, err := EncodeControl(msg)
		if err != nil {
			t.Fatalf("re-encode failed for %T: %v", msg, err)
		}
		msg2, err := DecodeControl(re)
		if err != nil {
			t.Fatalf("re-decode failed for %T: %v", msg, err)
		}
		if msg2.FrameType() != msg.FrameType() {
			t.Fatalf("frame type changed on round-trip: %d -> %d", msg.FrameType(), msg2.FrameType())
		}
	})
}

// SB-1142 (wire): fuzz the frame-header decoder over arbitrary (often truncated)
// buffers. It must never panic and must only accept exactly 16-byte inputs.
func FuzzDecodeFrameHeader(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2, 0, 16})
	f.Add([]byte{1, 2, 3})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, buf []byte) {
		h, err := decodeFrameHeader(buf)
		if err != nil {
			return
		}
		// A successfully decoded header must be expressible in the wire layout.
		enc := encodeFrameHeader(h)
		h2, err := decodeFrameHeader(enc)
		if err != nil {
			t.Fatalf("round-trip decode failed: %v", err)
		}
		if h2 != h {
			t.Fatalf("frame header round-trip mismatch: %+v vs %+v", h, h2)
		}
	})
}

// SB-1142 (wire): fuzz the sealed-frame open path with a fixed valid key.
// Any tampered/truncated/short frame must return an error, never panic and never
// yield a donated plaintext without GCM authentication.
func FuzzOpenSequenced(f *testing.F) {
	keys, err := DeriveTransferKeys(loopbackMaster())
	if err != nil {
		f.Fatal(err)
	}
	// Seed with a handful of adversarially shaped frames.
	f.Add([]byte{})
	f.Add([]byte("short"))
	f.Add(make([]byte, 4096))
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 10, 1, 2, 3, 4, 5, 6, 7})
	f.Fuzz(func(t *testing.T, frame []byte) {
		opened, err := OpenSequenced(keys.O2J, 0, frame)
		if err != nil {
			return
		}
		// A successfully authenticated frame must have a plausible header and
		// a plaintext whose length matches the header's len field.
		if len(opened.Plaintext) != int(opened.Header.Len) {
			t.Fatalf("authenticated frame plaintext %d != header len %d", len(opened.Plaintext), opened.Header.Len)
		}
	})
}

// SB-1143 (wire): fuzz the decode+validate manifest path. The invariant is that
// a validated manifest never carries out-of-range geometry that would drive the
// receiver into an oversized allocation or a divide-by-zero.
func FuzzValidateManifest(f *testing.F) {
	f.Add([]byte(`{"type":2,"files":[{"idx":0,"name":"a.bin","size":9,"mime":"","lastModified":1,"blockSize":8,"blocks":2,"fileDigest":"aa"}],"totalSize":9}`))
	f.Add([]byte(`{"type":2,"files":[{"idx":0,"name":"big","size":100,"mime":"","lastModified":1,"blockSize":1000,"blocks":1,"fileDigest":"aa"}],"totalSize":100}`))
	f.Add([]byte(`{"type":2,"files":[{"idx":0,"name":"zero","size":0,"mime":"","lastModified":0,"blockSize":1,"blocks":0,"fileDigest":"aa"}],"totalSize":0}`))
	f.Add([]byte(`{"type":2,"files":[{"idx":0,"name":"a","size":9,"mime":"","lastModified":1,"blockSize":8,"blocks":2,"fileDigest":"aa"}],"totalSize":99}`))
	f.Fuzz(func(t *testing.T, payload []byte) {
		msg, err := DecodeControl(payload)
		if err != nil {
			return
		}
		m, ok := msg.(*Manifest)
		if !ok {
			return
		}
		valid, err := ValidateManifest(*m)
		if err != nil {
			return
		}
		// The canonical manifest must preserve geometry and be re-encodeable.
		if len(valid.Files) == 0 || len(valid.Files) > MaxTransferFiles {
			t.Fatalf("validated manifest has %d files", len(valid.Files))
		}
		var total int64
		for _, file := range valid.Files {
			if file.Size < 0 || file.BlockSize <= 0 || file.Blocks < 0 {
				t.Fatalf("validated manifest has negative geometry: %+v", file)
			}
			if file.Size > math.MaxInt64-total {
				t.Fatalf("validated manifest size overflows")
			}
			total += file.Size
		}
		if valid.TotalSize != total {
			t.Fatalf("validated manifest total size mismatch: %d != %d", valid.TotalSize, total)
		}
	})
}

// SB-1143 (wire): fuzz the JSON shape-checking of a manifest decoder alone. A
// payload that decodes must never crash on unbounded slice lengths caused by a
// huge literal array; the post-decode ValidateManifest caps at MaxTransferFiles.
func FuzzDecodeManifestShape(f *testing.F) {
	seeds := []string{
		`{"type":2,"files":[],"totalSize":0}`,
		`{"type":2,"files":[{"idx":0}],"totalSize":0}`,
		`{"type":2}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(_ *testing.T, payload []byte) {
		_, _ = DecodeControl(payload)
	})
}
