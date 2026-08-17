package main

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

func TestBuildVersionString(t *testing.T) {
	tests := []struct {
		name    string
		version string
		commit  string
		want    string
	}{
		{
			name:    "default development fallback",
			version: "dev",
			commit:  "unknown",
			want:    "sendbeam dev (unknown)",
		},
		{
			name:    "empty fallback",
			version: "",
			commit:  "",
			want:    "sendbeam dev (unknown)",
		},
		{
			name:    "injected version with tag prefix",
			version: "v1.4.0",
			commit:  "1e937f5e07eaf6d74882018c7ce7a42856e22841",
			want:    "sendbeam 1.4.0 (1e937f5e07ea)",
		},
		{
			name:    "injected plain version",
			version: "1.4.0",
			commit:  "abcdef1234567890",
			want:    "sendbeam 1.4.0 (abcdef123456)",
		},
		{
			name:    "short commit preserved",
			version: "dev",
			commit:  "1e937f5e",
			want:    "sendbeam dev (1e937f5e)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildVersionString(tt.version, tt.commit)
			if got != tt.want {
				t.Errorf("buildVersionString(%q, %q) = %q; want %q", tt.version, tt.commit, got, tt.want)
			}
		})
	}
}

func TestPrintVersion(t *testing.T) {
	var buf bytes.Buffer
	printVersion(&buf)
	out := strings.TrimSpace(buf.String())
	if !strings.HasPrefix(out, "sendbeam ") {
		t.Errorf("printVersion() output %q does not start with 'sendbeam '", out)
	}
}

func TestVersionCLIExecution(t *testing.T) {
	// Build a temporary binary with ldflags injected
	tmpDir := t.TempDir()
	binPath := tmpDir + "/sendbeam-test"

	testVersion := "1.4.0-test"
	testCommit := "1e937f5e07eaf6d74882018c7ce7a42856e22841"

	buildCmd := exec.Command("go", "build",
		"-ldflags", "-X main.Version="+testVersion+" -X main.GitCommit="+testCommit,
		"-o", binPath,
		".",
	)
	buildCmd.Dir = "."
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build test binary: %v, output: %s", err, string(out))
	}

	// Test 1: `sendbeam version`
	cmd1 := exec.Command(binPath, "version")
	out1, err := cmd1.Output()
	if err != nil {
		t.Fatalf("sendbeam version failed: %v", err)
	}
	expected1 := "sendbeam 1.4.0-test (1e937f5e07ea)\n"
	if string(out1) != expected1 {
		t.Errorf("sendbeam version output = %q; want %q", string(out1), expected1)
	}

	// Test 2: `sendbeam --version`
	cmd2 := exec.Command(binPath, "--version")
	out2, err := cmd2.Output()
	if err != nil {
		t.Fatalf("sendbeam --version failed: %v", err)
	}
	if string(out2) != expected1 {
		t.Errorf("sendbeam --version output = %q; want %q", string(out2), expected1)
	}

	// Test 3: `sendbeam -v`
	cmd3 := exec.Command(binPath, "-v")
	out3, err := cmd3.Output()
	if err != nil {
		t.Fatalf("sendbeam -v failed: %v", err)
	}
	if string(out3) != expected1 {
		t.Errorf("sendbeam -v output = %q; want %q", string(out3), expected1)
	}
}
