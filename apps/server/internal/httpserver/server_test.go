package httpserver

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testRouter(t *testing.T, cfg Config) http.Handler {
	t.Helper()
	h, err := router(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("router: %v", err)
	}
	return h
}

func TestHealthz(t *testing.T) {
	h := testRouter(t, Config{})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("status field = %q, want ok", body["status"])
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := testRouter(t, Config{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got == "" {
		t.Error("missing Content-Security-Policy")
	} else if !strings.Contains(got, "wasm-unsafe-eval") {
		t.Errorf("CSP missing wasm-unsafe-eval for hash-wasm: %q", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
}

func TestSPAFallback(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html>hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := testRouter(t, Config{WebDir: dir})

	// A client-side route with no matching file falls back to index.html.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/send/abc", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); body != "<!doctype html>hi" {
		t.Fatalf("body = %q, want index.html contents", body)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	h := testRouter(t, Config{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain metrics", got)
	}
	body := rec.Body.String()
	for _, want := range []string{"sendarc_rooms", "sendarc_relay_bytes_total", "sendarc_errors_total"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

func TestConfigEndpoint(t *testing.T) {
	h := testRouter(t, Config{PublicURL: "https://send.example.com"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/config.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json: %v", err)
	}
	if body["publicUrl"] != "https://send.example.com" {
		t.Errorf("publicUrl = %q, want https://send.example.com", body["publicUrl"])
	}
}

func TestConfigEndpointEmpty(t *testing.T) {
	h := testRouter(t, Config{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/config.json", nil))
	var body map[string]string
	json.Unmarshal(rec.Body.Bytes(), &body)
	if body["publicUrl"] != "" {
		t.Errorf("publicUrl = %q, want empty when not configured", body["publicUrl"])
	}
}

func TestModeReporting(t *testing.T) {
	cases := map[string]Config{
		"dev-proxy": {DevProxy: "http://localhost:5173"},
		"static":    {WebDir: "/tmp/x"},
		"api-only":  {},
	}
	for want, cfg := range cases {
		if got := cfg.Mode(); got != want {
			t.Errorf("Mode() = %q, want %q", got, want)
		}
	}
}
