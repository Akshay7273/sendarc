package main

import (
	"testing"
)

func TestICEClientFlagGroupsMultipleSTUN(t *testing.T) {
	servers, err := iceServers([]string{
		"stun:stun1.example.com:3478",
		"stun:stun2.example.com:3478",
	})
	if err != nil {
		t.Fatalf("iceServers: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("len = %d, want 1 folded server", len(servers))
	}
	if len(servers[0].URLs) != 2 {
		t.Fatalf("urls = %d, want 2", len(servers[0].URLs))
	}
}

func TestICEClientEmptyUsesDefault(t *testing.T) {
	servers, err := iceServers(nil)
	if err != nil {
		t.Fatalf("iceServers: %v", err)
	}
	if servers != nil {
		t.Fatalf("servers = %v, want nil (package default)", servers)
	}
}

func TestICEClientRejectsMalformedURL(t *testing.T) {
	if _, err := iceServers([]string{"stun:stun.example.com"}); err == nil {
		t.Fatal("expected error for host-only STUN URL")
	}
}
