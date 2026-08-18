package updater

import (
	"fmt"
	"strings"
)

// Channel represents an update distribution channel.
type Channel string

const (
	// ChannelStable tracks official, fully-tested releases only (vX.Y.Z).
	// Stable never silently accepts or checks prerelease / beta versions.
	ChannelStable Channel = "stable"

	// ChannelBeta tracks candidate releases and prerelease builds (vX.Y.Z-beta.N, vX.Y.Z-rc.N)
	// in addition to stable versions.
	ChannelBeta Channel = "beta"

	// ChannelDev represents local or untagged development builds.
	ChannelDev Channel = "dev"
)

// ParseChannel normalizes and validates a channel name.
func ParseChannel(s string) (Channel, error) {
	norm := strings.ToLower(strings.TrimSpace(s))
	switch Channel(norm) {
	case ChannelStable, "":
		return ChannelStable, nil
	case ChannelBeta:
		return ChannelBeta, nil
	case ChannelDev:
		return ChannelDev, nil
	default:
		return "", fmt.Errorf("unknown update channel %q: must be %q or %q", s, ChannelStable, ChannelBeta)
	}
}

// AllowsPrerelease returns true if this channel accepts prerelease versions.
func (c Channel) AllowsPrerelease() bool {
	return c == ChannelBeta || c == ChannelDev
}

// IsDev returns true if this is the development channel.
func (c Channel) IsDev() bool {
	return c == ChannelDev
}

// String returns the string representation of the channel.
func (c Channel) String() string {
	if c == "" {
		return string(ChannelStable)
	}
	return string(c)
}
