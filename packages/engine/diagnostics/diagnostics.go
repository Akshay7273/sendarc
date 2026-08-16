// Package diagnostics builds sanitized connection diagnostics for SendBeam with no
// secrets or personally-identifying leaks. It is the Go counterpart of the browser's
// apps/web/src/lib/transfer/diagnostics.ts: both clients emit the same logical shape
// (see ADR 0003 / V12-PR06) so a failing client or the `sendbeam diagnose` command can
// surface a small, safe snapshot of path/ICE/timing/failure state.
//
// Sanitization guarantees: a snapshot never contains invite words/codes, full IP
// addresses, filenames, SDP, ICE credentials, or payload metadata. Candidate types are
// kept ("host"/"srflx"/"prflx"/"relay") because they are diagnostic and not sensitive;
// the addresses themselves are dropped.
package diagnostics

import (
	"encoding/json"
	"regexp"

	"github.com/sendbeam/wire"
)

// PathKind identifies the byte path a diagnostic refers to.
type PathKind string

const (
	// PathDirect is the direct WebRTC path (host/srflx/prflx candidates).
	PathDirect PathKind = "direct"
	// PathDirectTURN is the direct WebRTC path whose selected candidate is a TURN relay.
	PathDirectTURN PathKind = "direct-turn"
	// PathRelay is the encrypted WebSocket relay fallback.
	PathRelay PathKind = "relay"
)

// PathState mirrors the supervisor's lifecycle for the path snapshot.
type PathState string

// Lifecycle state values carried in a sanitized PathDiag.
const (
	StateCandidate PathState = "candidate"
	StateWarming   PathState = "warming"
	StateReady     PathState = "ready"
	StateActive    PathState = "active"
	StateDegraded  PathState = "degraded"
	StateFailed    PathState = "failed"
	StateClosed    PathState = "closed"
)

// PathDiag is one path's sanitized state at snapshot time.
type PathDiag struct {
	// State is the lifecycle state of the path.
	State PathState `json:"state"`
	// Kind is the path kind.
	Kind PathKind `json:"kind"`
	// SetupMS is the time to open this path, in ms (0 if never opened).
	SetupMS int64 `json:"setupMs"`
	// ICEStates is the ordered ICE connection-state history for a direct path ("" for relay).
	ICEStates []string `json:"iceStates,omitempty"`
	// SelectedPairType is the selected candidate pair type ("host"/"srflx"/"prflx"/"relay");
	// "" if none or the path is not direct.
	SelectedPairType string `json:"selectedPairType,omitempty"`
}

// FailureEvent is one sanitized failure observed during the exchange.
type FailureEvent struct {
	// Code is the stable wire error class (ADR 0002).
	Code wire.ErrorCode `json:"code"`
	// AtMS is the time since session start, in ms.
	AtMS int64 `json:"atMs"`
	// Path is the sanitized path kind the failure occurred on, if known.
	Path PathKind `json:"path,omitempty"`
	// Message is a short sanitized human message. It is scrubbed of IPs/filenames/secrets.
	Message string `json:"message"`
}

// Snapshot is a sanitized connection diagnostics report.
type Snapshot struct {
	// App is "cli" or "web".
	App string `json:"app"`
	// Role is "offerer" or "joiner".
	Role string `json:"role,omitempty"`
	// SetupMS is pairing+connection time, in ms (0 until connected).
	SetupMS int64 `json:"setupMs"`
	// TransferMS is the time bytes moved, in ms.
	TransferMS int64 `json:"transferMs,omitempty"`
	// TotalMS is wall time from session start to snapshot, in ms.
	TotalMS int64 `json:"totalMs,omitempty"`
	// SelectedPath is the sanitized final path kind; "" if none yet.
	SelectedPath PathKind `json:"selectedPath,omitempty"`
	// SelectedPairType is the sanitized selected candidate type for the final path.
	SelectedPairType string `json:"selectedPairType,omitempty"`
	// Paths is the ordered set of candidate paths that were registered.
	Paths []PathDiag `json:"paths,omitempty"`
	// Failures is the ordered set of failures observed.
	Failures []FailureEvent `json:"failures,omitempty"`
	// ICEServersConfigured counts the ICE servers the client was configured with (raw
	// details are never exposed; the count and TURN presence are non-sensitive).
	ICEServersConfigured int `json:"iceServersConfigured,omitempty"`
	// TURNConfigured reports whether a TURN server was configured (never its details).
	TURNConfigured bool `json:"turnConfigured,omitempty"`
}

// JSON returns the snapshot as compact, stable JSON.
func (s *Snapshot) JSON() []byte {
	b, err := json.Marshal(s)
	if err != nil {
		return []byte(`{"error":"diagnostics: marshal failed"}`)
	}
	return b
}

// Sanitize applies the shared redaction rules to a string, returning a version with full
// IP addresses, credentials, invite codes, and filenames/paths removed. Used for any free
// text (e.g. failure messages) before it enters a Snapshot or a failure message.
func Sanitize(s string) string {
	s = ipAddrRe.ReplaceAllString(s, "<ip>")
	s = credRe.ReplaceAllString(s, "${1}=<redacted>")
	s = codeRe.ReplaceAllString(s, "<code>")
	s = pathRe.ReplaceAllString(s, "<path>")
	return s
}

var (
	// ipAddrRe matches a full IPv4 or IPv6 address, optionally with a port, followed by a
	// word boundary so a trailing ":" in an unbracketed IPv6 is still caught.
	ipAddrRe = regexp.MustCompile(`(?:\b(?:\d{1,3}\.){3}\d{1,3}\b|\[[0-9a-fA-F:]+\]|\b(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F]{0,4}\b)(?:[-:]\d{1,5})?`)
	// credRe matches "label=value" or "label: value" or "label value" for credential-like
	// keys and replaces only the value (group 1 is the key, group 2 the value).
	credRe = regexp.MustCompile(`(?i)\b(credential|token|secret|password|passwd|key|username)\s*[=:]\s*(\S+)|(?i)\b(credential|token|secret|password|passwd|key|username)\s+(\S+)`)
	// codeRe strips the invite-code shape (room-dash-two-words) from free text.
	codeRe = regexp.MustCompile(`\b\d+-[a-z]+(?:-[a-z]+)+\b`)
	// pathRe strips absolute and drive-relative filesystem paths that may embed filenames.
	pathRe = regexp.MustCompile(`(?i)\b(?:/[a-zA-Z0-9_.\-]+)+|(?:[a-z]:\\)[\\a-zA-Z0-9_.\-]+`)
)
