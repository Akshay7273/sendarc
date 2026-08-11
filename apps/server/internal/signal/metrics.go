package signal

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// Metrics is a point-in-time snapshot of server-wide counters, rendered by
// /metrics in the Prometheus text format. Nothing here reveals content: rooms
// count live sessions, relayBytes counts ciphertext, errors counts refusal codes.
type Metrics struct {
	Rooms      int
	RelayBytes int64
	Errors     map[string]int64
}

// Metrics returns a snapshot of the hub's counters. All fields are guarded by
// hub.mu, which also protects room state and relay byte accounting.
func (h *Hub) Metrics() Metrics {
	h.mu.Lock()
	defer h.mu.Unlock()
	m := Metrics{
		Rooms:      len(h.rooms),
		RelayBytes: h.relayBytes,
		Errors:     make(map[string]int64, len(h.errors)),
	}
	for code, n := range h.errors {
		m.Errors[code] = n
	}
	return m
}

// recordError counts one refusal or protocol error by code. It is called from
// peer goroutines and from hub methods; hub.mu serializes it with snapshots.
func (h *Hub) recordError(code string) {
	h.mu.Lock()
	h.errors[code]++
	h.mu.Unlock()
}

// MetricsHandler serves Prometheus text metrics for the demo dashboard.
func (h *Hub) MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		m := h.Metrics()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		var b strings.Builder
		b.WriteString("# HELP sendbeam_rooms Active signaling rooms (live sessions).\n")
		b.WriteString("# TYPE sendbeam_rooms gauge\n")
		fmt.Fprintf(&b, "sendbeam_rooms %d\n", m.Rooms)
		b.WriteString("# HELP sendbeam_relay_bytes_total Ciphertext bytes relayed since server start.\n")
		b.WriteString("# TYPE sendbeam_relay_bytes_total counter\n")
		fmt.Fprintf(&b, "sendbeam_relay_bytes_total %d\n", m.RelayBytes)
		b.WriteString("# HELP sendbeam_errors_total Error frames sent, by refusal code.\n")
		b.WriteString("# TYPE sendbeam_errors_total counter\n")
		codes := make([]string, 0, len(m.Errors))
		for code := range m.Errors {
			codes = append(codes, code)
		}
		sort.Strings(codes)
		for _, code := range codes {
			fmt.Fprintf(&b, "sendbeam_errors_total{code=%q} %d\n", code, m.Errors[code])
		}
		_, _ = w.Write([]byte(b.String()))
	})
}
