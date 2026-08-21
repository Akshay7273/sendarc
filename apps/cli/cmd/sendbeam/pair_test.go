package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestPairFlagValidation(t *testing.T) {
	var stdout, stderr bytes.Buffer

	// --auto-accept without --dest should fail with exit code 2
	code := executePair([]string{"--auto-accept"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 for --auto-accept without --dest, got %d", code)
	}
	if !strings.Contains(stderr.String(), "--dest is required") {
		t.Errorf("expected error message in stderr, got: %s", stderr.String())
	}
}
