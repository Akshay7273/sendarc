package wire

import (
	"strings"
	"testing"
	"time"
)

func TestParseICEServersGroupsURLs(t *testing.T) {
	entries, err := ParseICEServers([]string{
		"stun:stun1.example.com:3478",
		"stun:stun2.example.com:3478",
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len = %d, want 1 folded entry", len(entries))
	}
	got := strings.Join(entries[0].URLs, ",")
	if got != "stun:stun1.example.com:3478,stun:stun2.example.com:3478" {
		t.Fatalf("urls = %q", got)
	}
}

func TestParseICEServersSeparatesCredentialedTURN(t *testing.T) {
	entries, err := ParseICEServers([]string{
		"stun:stun.example.com:3478",
		"turn:turn.example.com:3478?transport=udp",
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len = %d, want 2 (STUN + TURN kept distinct)", len(entries))
	}
}

func TestParseICEServersValidation(t *testing.T) {
	bad := []string{
		"http://stun.example.com:3478", // unknown scheme
		"stun:",                        // missing host/port
		"stun:stun.example.com",        // missing port
		"stun://stun.example.com",      // missing port
		"stun:stun.example.com:abc",    // non-numeric port
		"stun://:3478",                 // empty host
	}
	for _, raw := range bad {
		if _, err := ParseICEServer(raw); err == nil {
			t.Errorf("ParseICEServer(%q): expected error, got none", raw)
		}
	}
}

func TestParseICEServerTurnCredentials(t *testing.T) {
	entry, err := ParseICEServer("turn:user:secret@turn.example.com:3478")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if entry.Username != "user" || entry.Credential != "secret" {
		t.Fatalf("creds = %q/%q, want user/secret", entry.Username, entry.Credential)
	}
}

func TestParseICEServersSkipsBlank(t *testing.T) {
	entries, err := ParseICEServers([]string{"", " ", "stun:stun.example.com:3478"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len = %d, want 1 (blanks skipped)", len(entries))
	}
}

func TestICEConfigCacheTTL(t *testing.T) {
	base := time.Now()
	c := NewICEConfigCache([]ICEEntry{{URLs: []string{"stun:stun.example.com:3478"}}}, base)
	if c.Stale(base.Add(ICEConfigTTL - time.Minute)) {
		t.Error("config marked stale before TTL")
	}
	if !c.Stale(base.Add(ICEConfigTTL + time.Minute)) {
		t.Error("config not marked stale after TTL")
	}
}
