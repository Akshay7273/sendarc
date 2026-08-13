package diagnostics

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sendbeam/wire"
)

func TestSanitizeRedactsSensitive(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string // substrings that must NOT appear
	}{
		{
			name: "ipv4 with port",
			in:   "peer at 203.0.113.7:3478 unreachable",
			want: []string{"203.0.113.7", "203.0.113.7:3478"},
		},
		{
			name: "ipv6",
			in:   "route via 2001:db8::1 failed",
			want: []string{"2001:db8::1"},
		},
		{
			name: "credentials",
			in:   "turn credential=supersecret123 failed",
			want: []string{"supersecret123"},
		},
		{
			name: "invite code",
			in:   "bad room 42-alpha-bravo",
			want: []string{"42-alpha-bravo"},
		},
		{
			name: "filesystem path",
			in:   "could not write /home/me/secret.txt",
			want: []string{"/home/me/secret.txt", "secret.txt"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := Sanitize(tt.in)
			for _, w := range tt.want {
				if strings.Contains(out, w) {
					t.Errorf("Sanitize(%q) = %q, still contains %q", tt.in, out, w)
				}
			}
		})
	}
}

func TestSanitizeKeepsBenignText(t *testing.T) {
	out := Sanitize("direct path recovery failed; relay warmed as fallback")
	if !strings.Contains(out, "direct path recovery failed") {
		t.Fatalf("Sanitize stripped benign text: %q", out)
	}
}

func TestSnapshotJSONShape(t *testing.T) {
	s := &Snapshot{
		App:                  "cli",
		Role:                 "offerer",
		SetupMS:              1200,
		TransferMS:           400,
		TotalMS:              1600,
		SelectedPath:         PathDirect,
		SelectedPairType:     "srflx",
		ICEServersConfigured: 2,
		TURNConfigured:       true,
		Paths: []PathDiag{
			{State: StateActive, Kind: PathDirect, SetupMS: 1100, ICEStates: []string{"new", "connected"}, SelectedPairType: "srflx"},
		},
		Failures: []FailureEvent{
			{Code: wire.CodeConnection, AtMS: 900, Path: PathDirect, Message: "transient disconnect observed"},
		},
	}

	var m map[string]any
	if err := json.Unmarshal(s.JSON(), &m); err != nil {
		t.Fatalf("Snapshot.JSON not valid JSON: %v\n%s", err, s.JSON())
	}
	if m["selectedPath"] != "direct" {
		t.Errorf("selectedPath = %v, want direct", m["selectedPath"])
	}
	if m["turnConfigured"] != true {
		t.Errorf("turnConfigured = %v, want true", m["turnConfigured"])
	}
	paths, ok := m["paths"].([]any)
	if !ok || len(paths) != 1 {
		t.Fatalf("paths = %v, want one entry", m["paths"])
	}
	failures, ok := m["failures"].([]any)
	if !ok || len(failures) != 1 {
		t.Fatalf("failures = %v, want one entry", m["failures"])
	}
}

func TestSnapshotJSONNeverMarshalsSensitiveLiteralLabels(t *testing.T) {
	s := &Snapshot{App: "cli"}
	j := string(s.JSON())
	for _, banned := range []string{"stun:", "credential>", "iceServers>", "sdp"} {
		if strings.Contains(j, banned) {
			t.Errorf("Snapshot.JSON leaked sensitive label %q: %s", banned, j)
		}
	}
}
