package wire

import (
	"regexp"
	"strings"
	"testing"
)

func TestWordlistShape(t *testing.T) {
	if len(wordlist) != wordlistSize {
		t.Fatalf("wordlist has %d entries, want %d", len(wordlist), wordlistSize)
	}
	valid := regexp.MustCompile(`^[a-z]{2,8}$`)
	seen := make(map[string]bool, wordlistSize)
	for i, w := range wordlist {
		if !valid.MatchString(w) {
			t.Errorf("word %d %q is not 2-8 lowercase letters", i, w)
		}
		if seen[w] {
			t.Errorf("duplicate word %q at index %d", w, i)
		}
		seen[w] = true
	}
}

func TestNormalizeCode(t *testing.T) {
	cases := map[string]string{
		"4-Brave-Otter":     "4-brave-otter",
		"  4  brave otter ": "4-brave-otter",
		"4_BRAVE__OTTER":    "4-brave-otter",
		"4-brave-otter":     "4-brave-otter",
		"7-Ant-Ape":         "7-ant-ape",
		"":                  "",
		"---":               "",
	}
	for in, want := range cases {
		if got := NormalizeCode(in); got != want {
			t.Errorf("NormalizeCode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseCodeRoundTrip(t *testing.T) {
	code := FormatCode(4, "brave-otter")
	if code != "4-brave-otter" {
		t.Fatalf("FormatCode = %q", code)
	}
	parsed, err := ParseCode(code)
	if err != nil {
		t.Fatalf("ParseCode: %v", err)
	}
	if parsed.Room != 4 || parsed.Words != "brave-otter" {
		t.Errorf("parsed = %+v", parsed)
	}
}

func TestParseCodeNormalizesFirst(t *testing.T) {
	parsed, err := ParseCode("  4 · Brave · Otter ")
	if err != nil {
		t.Fatalf("ParseCode: %v", err)
	}
	if parsed.Room != 4 || parsed.Words != "brave-otter" {
		t.Errorf("parsed = %+v", parsed)
	}
}

func TestParseCodeRejects(t *testing.T) {
	for _, raw := range []string{"", "brave-otter", "4", "4-", "-brave"} {
		if _, err := ParseCode(raw); err == nil {
			t.Errorf("ParseCode(%q) should have failed", raw)
		}
	}
}

func TestGenerateWords(t *testing.T) {
	words, err := GenerateWords(3)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(words, codeSeparator)
	if len(parts) != 3 {
		t.Fatalf("expected 3 words, got %d (%q)", len(parts), words)
	}
	for _, p := range parts {
		if !inWordlist(p) {
			t.Errorf("generated word %q is not in the wordlist", p)
		}
	}
	if _, err := GenerateWords(0); err == nil {
		t.Error("GenerateWords(0) should fail")
	}
}

func TestGenerateCode(t *testing.T) {
	code, err := GenerateCode(12)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCode(code)
	if err != nil {
		t.Fatalf("generated code %q does not parse: %v", code, err)
	}
	if parsed.Room != 12 {
		t.Errorf("room = %d, want 12", parsed.Room)
	}
	if len(strings.Split(parsed.Words, codeSeparator)) != defaultWordCount {
		t.Errorf("expected %d words in %q", defaultWordCount, parsed.Words)
	}
}

func inWordlist(w string) bool {
	for _, x := range wordlist {
		if x == w {
			return true
		}
	}
	return false
}
