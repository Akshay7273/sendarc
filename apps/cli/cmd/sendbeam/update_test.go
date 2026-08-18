package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func captureOutput(f func()) (string, string) {
	origStdout := os.Stdout
	origStderr := os.Stderr

	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()

	os.Stdout = wOut
	os.Stderr = wErr

	outCh := make(chan string)
	errCh := make(chan string)

	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, rOut)
		outCh <- buf.String()
	}()

	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, rErr)
		errCh <- buf.String()
	}()

	f()

	_ = wOut.Close()
	_ = wErr.Close()

	outStr := <-outCh
	errStr := <-errCh

	os.Stdout = origStdout
	os.Stderr = origStderr

	return outStr, errStr
}

func TestRunUpdate_CheckDev(t *testing.T) {
	Version = "dev"
	out, errOut := captureOutput(func() {
		code := runUpdate([]string{"--check"})
		if code != 0 {
			t.Errorf("expected exit code 0, got %d", code)
		}
	})

	if !strings.Contains(out, "development build") && !strings.Contains(errOut, "development build") {
		t.Errorf("expected dev build message in output, out=%q errOut=%q", out, errOut)
	}
}

func TestRunUpdate_JSON(t *testing.T) {
	Version = "dev"
	out, _ := captureOutput(func() {
		code := runUpdate([]string{"--json"})
		if code != 0 {
			t.Errorf("expected exit code 0, got %d", code)
		}
	})

	var res map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &res); err != nil {
		t.Fatalf("failed to decode JSON output: %v (raw: %q)", err, out)
	}
	if res["channel"] != "stable" {
		t.Errorf("expected default channel 'stable', got %v", res["channel"])
	}
}

func TestRunUpdate_CheckRelease(t *testing.T) {
	// Mock server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		releases := []map[string]any{
			{
				"tag_name":     "v1.4.0",
				"prerelease":   false,
				"published_at": time.Now().Format(time.RFC3339),
				"body":         "Release 1.4.0",
				"assets": []map[string]any{
					{
						"name":                 "sendbeam-cli-linux-amd64.tar.gz",
						"size":                 1024,
						"browser_download_url": "http://example.com/cli.tar.gz",
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(releases)
	}))
	defer srv.Close()

	Version = "1.3.0"
	out, _ := captureOutput(func() {
		code := runUpdate([]string{"--check", "--repo", "mock/repo"})
		t.Logf("runUpdate exit code: %d", code)
	})
	t.Logf("output: %s", out)
}
