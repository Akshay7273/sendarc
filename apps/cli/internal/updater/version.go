package updater

import (
	"fmt"
	"strconv"
	"strings"
)

// Version represents a parsed semantic version.
type Version struct {
	Raw        string
	Major      int
	Minor      int
	Patch      int
	Prerelease string
	Build      string
	IsDev      bool
}

// ParseVersion parses a semantic version string (e.g. "1.4.0", "v1.4.0-beta.1", "dev").
func ParseVersion(s string) (Version, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" || trimmed == "dev" || strings.HasPrefix(trimmed, "0.0.0~dev") {
		return Version{Raw: trimmed, IsDev: true}, nil
	}

	clean := strings.TrimPrefix(trimmed, "v")

	// Split off build metadata first (+build)
	build := ""
	if idx := strings.IndexByte(clean, '+'); idx != -1 {
		build = clean[idx+1:]
		clean = clean[:idx]
	}

	// Split off prerelease metadata (-beta.1)
	prerelease := ""
	if idx := strings.IndexByte(clean, '-'); idx != -1 {
		prerelease = clean[idx+1:]
		clean = clean[:idx]
	}

	parts := strings.Split(clean, ".")
	if len(parts) < 1 || len(parts) > 3 {
		return Version{}, fmt.Errorf("invalid semver format %q: expected 1-3 numeric components", s)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil || major < 0 {
		return Version{}, fmt.Errorf("invalid major version in %q", s)
	}

	minor := 0
	if len(parts) > 1 {
		minor, err = strconv.Atoi(parts[1])
		if err != nil || minor < 0 {
			return Version{}, fmt.Errorf("invalid minor version in %q", s)
		}
	}

	patch := 0
	if len(parts) > 2 {
		patch, err = strconv.Atoi(parts[2])
		if err != nil || patch < 0 {
			return Version{}, fmt.Errorf("invalid patch version in %q", s)
		}
	}

	return Version{
		Raw:        trimmed,
		Major:      major,
		Minor:      minor,
		Patch:      patch,
		Prerelease: prerelease,
		Build:      build,
		IsDev:      false,
	}, nil
}

// String returns the normalized version string.
func (v Version) String() string {
	if v.IsDev {
		if v.Raw != "" {
			return v.Raw
		}
		return "dev"
	}
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Prerelease != "" {
		s += "-" + v.Prerelease
	}
	if v.Build != "" {
		s += "+" + v.Build
	}
	return s
}

// IsPrerelease returns true if this version contains a prerelease tag.
func (v Version) IsPrerelease() bool {
	return !v.IsDev && v.Prerelease != ""
}

// CompatibleWithChannel checks if this version is eligible for installation under channel c.
func (v Version) CompatibleWithChannel(c Channel) bool {
	if v.IsDev {
		return c == ChannelDev
	}
	if v.IsPrerelease() {
		return c.AllowsPrerelease()
	}
	return true
}

// Compare returns:
//
//	-1 if v < other
//	 0 if v == other
//	 1 if v > other
func (v Version) Compare(other Version) int {
	if v.IsDev && other.IsDev {
		return 0
	}
	if v.IsDev {
		return -1 // dev is treated as older than any tagged release for update candidate evaluation
	}
	if other.IsDev {
		return 1
	}

	if v.Major != other.Major {
		if v.Major > other.Major {
			return 1
		}
		return -1
	}
	if v.Minor != other.Minor {
		if v.Minor > other.Minor {
			return 1
		}
		return -1
	}
	if v.Patch != other.Patch {
		if v.Patch > other.Patch {
			return 1
		}
		return -1
	}

	// When major, minor, patch are equal:
	// A normal version has higher precedence than a pre-release version.
	if v.Prerelease == "" && other.Prerelease != "" {
		return 1
	}
	if v.Prerelease != "" && other.Prerelease == "" {
		return -1
	}
	if v.Prerelease == other.Prerelease {
		return 0
	}

	return comparePrereleases(v.Prerelease, other.Prerelease)
}

// comparePrereleases compares two non-empty prerelease strings according to SemVer 2.0.0.
func comparePrereleases(p1, p2 string) int {
	parts1 := strings.Split(p1, ".")
	parts2 := strings.Split(p2, ".")

	minLen := len(parts1)
	if len(parts2) < minLen {
		minLen = len(parts2)
	}

	for i := 0; i < minLen; i++ {
		seg1 := parts1[i]
		seg2 := parts2[i]

		num1, err1 := strconv.Atoi(seg1)
		num2, err2 := strconv.Atoi(seg2)

		switch {
		case err1 == nil && err2 == nil:
			if num1 != num2 {
				if num1 > num2 {
					return 1
				}
				return -1
			}
		case err1 == nil && err2 != nil:
			// Numeric identifiers always have lower precedence than non-numeric identifiers
			return -1
		case err1 != nil && err2 == nil:
			return 1
		default:
			// Compare lexical ASCII
			if seg1 != seg2 {
				if seg1 > seg2 {
					return 1
				}
				return -1
			}
		}
	}

	// If all shared parts are equal, the longer prerelease has higher precedence
	if len(parts1) > len(parts2) {
		return 1
	}
	if len(parts1) < len(parts2) {
		return -1
	}
	return 0
}

// IsGreaterThan returns true if v > other.
func (v Version) IsGreaterThan(other Version) bool {
	return v.Compare(other) > 0
}
