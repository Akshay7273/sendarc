package wire

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// ProtocolCorpus is a committed regression corpus. Each entry is a real
// protocol shape that was hardened in or after v1.0 — oversized geometry, zero
// block sizes, traversal paths, reserved names, unknown enums, missing fields —
// plus framing-level truncations. Every payload is run through the decoders and
// must be rejected (or accepted) without panicking.
type ProtocolCorpus struct {
	Name    string `json:"name"`
	Payload string `json:"payload"`
}

// TestProtocolCorpus feeds every recorded adversarial payload through the pure
// control-frame and frame-header decoders. The invariant under test is exactly
// "never panic on malformed input": each entry must decode or reject with a
// clean error (nothing is asserted about the specific error reason). A future
// regression that makes any of these crash fails loudly here.
func TestProtocolCorpus(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "protocol-corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	var entries []ProtocolCorpus
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("empty regression corpus")
	}
	for _, e := range entries {
		e := e
		t.Run(e.Name, func(_ *testing.T) {
			// DecodeControl is the entry point exercised by the JSON payloads;
			// decodeFrameHeader is included so truncation-type corpus entries are
			// run through a binary framing decoder too. Neither may panic.
			_, _ = DecodeControl([]byte(e.Payload))
			_, _ = decodeFrameHeader([]byte(e.Payload))
		})
	}
}
