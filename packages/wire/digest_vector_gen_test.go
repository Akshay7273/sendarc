package wire

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// digestVectorScenario pins the V13-PR05 resume contract in a runtime-independent way: a
// digest that has covered `prefix`, whose serialized state is restored, and which is then
// fed `suffix`, must produce `fullDigest` — byte-identical to one-shot hashing
// prefix+suffix. The serialized state bytes themselves are runtime-specific (the Go
// stdlib's 108-byte sha256 state vs hash-wasm's 116-byte state) and are pinned by
// durable-journal.json (Go format) and the TypeScript digest tests (hash-wasm format);
// this file pins the semantics both formats must implement.
type digestVectorScenario struct {
	Name         string `json:"name"`
	PrefixHex    string `json:"prefixHex"`
	SuffixHex    string `json:"suffixHex"`
	PrefixDigest string `json:"prefixDigest"`
	FullDigest   string `json:"fullDigest"`
}

type digestVectorDoc struct {
	Description string                 `json:"description"`
	Scenarios   []digestVectorScenario `json:"scenarios"`
}

func patternBytes(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func digestVectorScenarios() []digestVectorScenario {
	cases := []struct {
		name   string
		prefix []byte
		suffix []byte
	}{
		{"empty-prefix-short-suffix", []byte{}, []byte("abc")},
		{"empty-prefix-one-block-suffix", []byte{}, patternBytes(64, 0x61)},
		{"block-boundary-prefix-and-suffix", patternBytes(64, 0x01), patternBytes(64, 0x02)},
		{"large-prefix-partial-suffix", patternBytes(4096, 0x77), patternBytes(500, 0x88)},
		{"partial-block-prefix-filled-by-suffix", patternBytes(323, 0x55), []byte{0x66}},
		{"multi-chunk-continuation", patternBytes(1064, 0x11), patternBytes(2048, 0x22)},
	}
	scenarios := make([]digestVectorScenario, 0, len(cases))
	for _, c := range cases {
		prefixSum := NewSHA256Digest()
		prefixSum.Update(c.prefix)
		full := NewSHA256Digest()
		full.Update(c.prefix)
		full.Update(c.suffix)
		scenarios = append(scenarios, digestVectorScenario{
			Name:         c.name,
			PrefixHex:    hex.EncodeToString(c.prefix),
			SuffixHex:    hex.EncodeToString(c.suffix),
			PrefixDigest: prefixSum.HexDigest(),
			FullDigest:   full.HexDigest(),
		})
	}
	return scenarios
}

// TestGenerateDigestCheckpointVector rewrites docs/test-vectors/digest-checkpoint.json
// from the Go implementation. Run with GENERATE_VECTORS=1 (see docs/test-vectors/README.md):
//
//	cd packages/wire && GENERATE_VECTORS=1 go test -run TestGenerateDigestCheckpointVector ./...
func TestGenerateDigestCheckpointVector(t *testing.T) {
	if os.Getenv("GENERATE_VECTORS") != "1" {
		t.Skip("set GENERATE_VECTORS=1 to regenerate docs/test-vectors/digest-checkpoint.json")
	}
	doc := digestVectorDoc{
		Description: "V13-PR05 digest-resume contract, produced by the Go implementation " +
			"(packages/wire/transfer_ports.go). Both Go and TypeScript must reproduce every " +
			"prefixDigest and fullDigest: a digest restored from the serialized state covering " +
			"`prefix`, fed `suffix`, must equal one-shot hashing prefix+suffix.",
		Scenarios: digestVectorScenarios(),
	}
	path := filepath.Join("..", "..", "docs", "test-vectors", "digest-checkpoint.json")
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s", path)
}

// TestDigestCheckpointVector reads the committed vector and verifies the Go digest
// implementation reproduces every scenario, including through save/restore.
func TestDigestCheckpointVector(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "test-vectors", "digest-checkpoint.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc digestVectorDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Scenarios) == 0 {
		t.Fatal("vector has no scenarios")
	}
	for _, s := range doc.Scenarios {
		prefix, err := hex.DecodeString(s.PrefixHex)
		if err != nil {
			t.Fatalf("%s: bad prefixHex: %v", s.Name, err)
		}
		suffix, err := hex.DecodeString(s.SuffixHex)
		if err != nil {
			t.Fatalf("%s: bad suffixHex: %v", s.Name, err)
		}
		prefixSum := NewSHA256Digest()
		prefixSum.Update(prefix)
		if got := prefixSum.HexDigest(); got != s.PrefixDigest {
			t.Errorf("%s: prefix digest = %s, want %s", s.Name, got, s.PrefixDigest)
		}
		live := NewSHA256Digest()
		live.Update(prefix)
		state, err := live.(DigestState).MarshalState()
		if err != nil {
			t.Fatalf("%s: MarshalState: %v", s.Name, err)
		}
		restored, err := RestoreSHA256Digest(state)
		if err != nil {
			t.Fatalf("%s: RestoreSHA256Digest: %v", s.Name, err)
		}
		restored.Update(suffix)
		if got := restored.HexDigest(); got != s.FullDigest {
			t.Errorf("%s: restored digest = %s, want %s", s.Name, got, s.FullDigest)
		}
		whole := NewSHA256Digest()
		whole.Update(prefix)
		whole.Update(suffix)
		if got := whole.HexDigest(); got != s.FullDigest {
			t.Errorf("%s: one-shot full digest = %s, want %s", s.Name, got, s.FullDigest)
		}
	}
}
