package signal

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsSnapshot(t *testing.T) {
	h := testHub(t)

	if m := h.Metrics(); m.Rooms != 0 || m.RelayBytes != 0 || len(m.Errors) != 0 {
		t.Fatalf("fresh hub metrics = %+v, want all zero", m)
	}

	a, b := newTestPeer(), newTestPeer()
	h.createRoom(a)
	h.createRoom(b)
	h.recordError("bad_message")
	h.recordError("bad_message")
	h.recordError("room_full")

	m := h.Metrics()
	if m.Rooms != 2 {
		t.Errorf("Rooms = %d, want 2", m.Rooms)
	}
	if m.Errors["bad_message"] != 2 || m.Errors["room_full"] != 1 {
		t.Errorf("Errors = %v, want bad_message=2 room_full=1", m.Errors)
	}
}

func TestMetricsHandlerRendersPrometheusText(t *testing.T) {
	h := testHub(t)
	h.recordError("room_full")

	rec := httptest.NewRecorder()
	h.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if got := rec.Code; got != 200 {
		t.Fatalf("status = %d, want 200", got)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"# TYPE sendarc_rooms gauge",
		"sendarc_rooms 0",
		"sendarc_relay_bytes_total 0",
		`sendarc_errors_total{code="room_full"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q:\n%s", want, body)
		}
	}
}
