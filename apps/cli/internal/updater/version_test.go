package updater

import (
	"testing"
)

func TestParseChannel(t *testing.T) {
	tests := []struct {
		input       string
		expected    Channel
		shouldError bool
	}{
		{"stable", ChannelStable, false},
		{"STABLE", ChannelStable, false},
		{"", ChannelStable, false},
		{"beta", ChannelBeta, false},
		{"BETA", ChannelBeta, false},
		{"dev", ChannelDev, false},
		{"nightly", "", true},
		{"alpha", "", true},
	}

	for _, tt := range tests {
		got, err := ParseChannel(tt.input)
		if (err != nil) != tt.shouldError {
			t.Errorf("ParseChannel(%q) error = %v, shouldError %v", tt.input, err, tt.shouldError)
			continue
		}
		if got != tt.expected {
			t.Errorf("ParseChannel(%q) = %v, expected %v", tt.input, got, tt.expected)
		}
	}
}

func TestChannelProperties(t *testing.T) {
	if ChannelStable.AllowsPrerelease() {
		t.Error("ChannelStable must not allow prereleases")
	}
	if !ChannelBeta.AllowsPrerelease() {
		t.Error("ChannelBeta must allow prereleases")
	}
	if !ChannelDev.IsDev() {
		t.Error("ChannelDev must be dev")
	}
	if ChannelStable.IsDev() {
		t.Error("ChannelStable must not be dev")
	}
}

func TestVersionParsingAndComparison(t *testing.T) {
	tests := []struct {
		name     string
		v1       string
		v2       string
		expected int // -1 (v1 < v2), 0 (v1 == v2), 1 (v1 > v2)
	}{
		{"equal basic", "1.4.0", "1.4.0", 0},
		{"equal with v prefix", "v1.4.0", "1.4.0", 0},
		{"patch upgrade", "1.4.1", "1.4.0", 1},
		{"minor upgrade", "1.5.0", "1.4.9", 1},
		{"major upgrade", "2.0.0", "1.99.99", 1},
		{"stable vs beta", "1.4.0", "1.4.0-beta.1", 1},
		{"beta1 vs beta2", "1.4.0-beta.1", "1.4.0-beta.2", -1},
		{"beta vs rc", "1.4.0-beta.2", "1.4.0-rc.1", -1},
		{"rc vs release", "1.4.0-rc.1", "1.4.0", -1},
		{"dev vs release", "dev", "1.4.0", -1},
		{"release vs dev", "1.0.0", "dev", 1},
		{"dev vs dev", "dev", "dev", 0},
		{"ignore build metadata", "1.4.0+build1", "1.4.0+build2", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ver1, err := ParseVersion(tt.v1)
			if err != nil {
				t.Fatalf("ParseVersion(%q) failed: %v", tt.v1, err)
			}
			ver2, err := ParseVersion(tt.v2)
			if err != nil {
				t.Fatalf("ParseVersion(%q) failed: %v", tt.v2, err)
			}

			cmp := ver1.Compare(ver2)
			if cmp != tt.expected {
				t.Errorf("Compare(%q, %q) = %d, expected %d", tt.v1, tt.v2, cmp, tt.expected)
			}

			if tt.expected > 0 && !ver1.IsGreaterThan(ver2) {
				t.Errorf("IsGreaterThan(%q, %q) = false, expected true", tt.v1, tt.v2)
			}
		})
	}
}

func TestVersionChannelCompatibility(t *testing.T) {
	stableVer, _ := ParseVersion("1.4.0")
	betaVer, _ := ParseVersion("1.4.0-beta.1")
	devVer, _ := ParseVersion("dev")

	// Stable channel: accepts stable only
	if !stableVer.CompatibleWithChannel(ChannelStable) {
		t.Error("stableVer must be compatible with ChannelStable")
	}
	if betaVer.CompatibleWithChannel(ChannelStable) {
		t.Error("betaVer must NOT be compatible with ChannelStable")
	}
	if devVer.CompatibleWithChannel(ChannelStable) {
		t.Error("devVer must NOT be compatible with ChannelStable")
	}

	// Beta channel: accepts both stable and beta
	if !stableVer.CompatibleWithChannel(ChannelBeta) {
		t.Error("stableVer must be compatible with ChannelBeta")
	}
	if !betaVer.CompatibleWithChannel(ChannelBeta) {
		t.Error("betaVer must be compatible with ChannelBeta")
	}
	if devVer.CompatibleWithChannel(ChannelBeta) {
		t.Error("devVer must NOT be compatible with ChannelBeta")
	}

	// Dev channel: accepts dev
	if !devVer.CompatibleWithChannel(ChannelDev) {
		t.Error("devVer must be compatible with ChannelDev")
	}
}
