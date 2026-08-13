package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStunHostPort(t *testing.T) {
	tests := []struct {
		raw        string
		wantAddr   string
		wantScheme string
	}{
		{"stun:stun.example.com:3478", "stun.example.com:3478", "stun"},
		{"stun://stun.example.com:3478", "stun.example.com:3478", "stun"},
		{"stun:user:pass@stun.example.com:3478", "stun.example.com:3478", "stun"},
		{"stuns:stun.example.com:5349", "stun.example.com:5349", "stuns"},
	}
	for _, tt := range tests {
		addr, scheme := stunHostPort(tt.raw)
		if addr != tt.wantAddr || scheme != tt.wantScheme {
			t.Errorf("stunHostPort(%q) = (%q,%q), want (%q,%q)", tt.raw, addr, scheme, tt.wantAddr, tt.wantScheme)
		}
	}
}

func TestFetchServerConfigSanitizesSummary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"iceServers":[{"urls":["stun:127.0.0.1:3478"]},{"urls":["turn:turn.example.com:3478"],"username":"u","credential":"p"}]}`))
	}))
	defer srv.Close()

	// Convert http://127.0.0.1:PORT to the ws form the CLI accepts.
	ws := "ws://" + srv.Listener.Addr().String() + "/ws"
	cfg, err := fetchServerConfig(context.Background(), ws, false, 2*time.Second)
	if err != nil {
		t.Fatalf("fetchServerConfig: %v", err)
	}
	if len(cfg.ICEServers) != 2 {
		t.Fatalf("got %d ICE servers, want 2", len(cfg.ICEServers))
	}
	if cfg.ICEServers[1].Username != "u" {
		t.Errorf("TURN username leaked %q", cfg.ICEServers[1].Username)
	}
}
