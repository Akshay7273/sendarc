package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestListenCommand(t *testing.T) {
	tmpDir := t.TempDir()

	var stdout, stderr bytes.Buffer
	code := executeListen([]string{"--config-dir", tmpDir, "--once", "--dest", tmpDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("listen exit code %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "SendBeam Trusted Listener") {
		t.Errorf("expected header, got: %s", stdout.String())
	}

	// Test with --json
	stdout.Reset()
	stderr.Reset()
	code = executeListen([]string{"--config-dir", tmpDir, "--once", "--json", "--dest", tmpDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("listen --json exit code %d, stderr: %s", code, stderr.String())
	}
}
