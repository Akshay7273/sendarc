package wire

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// ProtocolCorpus is a committed regression corpus (SB-1147). Each entry is a real
// protocol shape that was hardened in or after v1.0 — oversized geometry, zero
// block sizes, traversal paths, reserved names, unknown enums, missing fields —
// plus the framing-level truncations they once triggered. Every payload must pass
// through the decoders without panicking or allocating unboundedly.
type ProtocolCorpus struct {
	Name    string `json:"name"`
	Payload string `json:"payload"`
}

// TestProtocolProtocolCorpus feeds every recorded adversarial payload through the
// control-frame decoder. The invariant is "no panic, clean reject or bounded
// accept" — a future regression that makes any of these crash fails loudly here.
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
			// decodeFrameHeader and DecodeControl are the two pure decode entry
			// points that this corpus exercises without panicking; anything they
			// don't accept must be a clean error, never a crash.
			_, _ = decodeFrameHeader([]byte(e.Payload))
			_, _ = DecodeControl([]byte(e.Payload))
		})
	}
}
