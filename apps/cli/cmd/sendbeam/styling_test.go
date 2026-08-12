package main

import (
	"strings"
	"testing"
)

func TestFrameAlignsAllLines(t *testing.T) {
	got := frame("SendBeam invite", "4-brave-otter", "link: https://example.com/#4-brave-otter")
	lines := strings.Split(got, "\n")
	widths := make([]int, len(lines))
	for i, line := range lines {
		widths[i] = visibleLen(line)
	}
	for i := 1; i < len(widths); i++ {
		if widths[i] != widths[0] {
			t.Fatalf("line %d width = %d, want %d\n%s", i, widths[i], widths[0], got)
		}
	}
	if !strings.HasPrefix(lines[0], "\u250c\u2500 SendBeam invite ") {
		t.Fatalf("top border missing title: %q", lines[0])
	}
	if !strings.HasSuffix(lines[len(lines)-1], "\u2518") {
		t.Fatalf("bottom border missing corner: %q", lines[len(lines)-1])
	}
}

func TestFrameAccountsForAnsiWidth(t *testing.T) {
	s := &style{on: true}
	styled := s.cyan("4-brave-otter")
	got := frame("SendBeam invite", styled)
	lines := strings.Split(got, "\n")
	for i, line := range lines {
		if visibleLen(line) != visibleLen(lines[0]) {
			t.Fatalf("line %d width = %d, want %d (styled content breaks alignment):\n%s",
				i, visibleLen(line), visibleLen(lines[0]), got)
		}
	}
}

func TestVisibleLenStripsAnsi(t *testing.T) {
	plain := "abc123"
	styled := "\x1b[36m" + plain + "\x1b[0m"
	if visibleLen(styled) != len(plain) {
		t.Fatalf("visibleLen(%q) = %d, want %d", styled, visibleLen(styled), len(plain))
	}
}
