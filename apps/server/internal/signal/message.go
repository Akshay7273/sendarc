// Package signal implements the SendArc rendezvous server: a blind WebSocket
// forwarder and pairer. It allocates room numbers, links exactly two sockets per
// room, and relays the peers' SPAKE2 handshake and encrypted capability frames
// without inspecting them. It never sees the word code, any key, or any plaintext —
// only room numbers and connection metadata.
package signal

import (
	"encoding/json"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// Wire message types. Control types are handled by the server; the
// forwardable types are relayed peer-to-peer as opaque bytes.
const (
	typeCreate        = "create"
	typeCreated       = "created"
	typeJoin          = "join"
	typePeerJoined    = "peer-joined"
	typePake          = "pake"
	typeConfirm       = "confirm"
	typeCaps          = "caps"
	typeSDP           = "sdp"
	typeICE           = "ice"
	typeRelayOpen     = "relay_open"
	typeRelayRequired = "relay_required"
	typeRelayReady    = "relay_ready"
	typeRelayCredit   = "relay_credit"
	typeCredit        = "credit"
	typeBye           = "bye"
	typeError         = "error"
)

// Role labels echoed to peers on pairing. These are routing labels only; their
// cryptographic meaning lives in packages/wire (wire.Role) and must stay in sync
// with it — the offerer created the room, the joiner joined it.
const (
	roleOfferer = "offerer"
	roleJoiner  = "joiner"
)

// forwardable is the set of peer→peer types the server relays without inspection.
// SDP and ICE bodies are forwarded without being parsed.
var forwardable = map[string]bool{
	typePake:    true,
	typeConfirm: true,
	typeCaps:    true,
	typeSDP:     true,
	typeICE:     true,
}

// Error codes carried in an error message's "code" field.
const (
	errBadMessage    = "bad_message"
	errUnknownRoom   = "unknown_room"
	errRoomFull      = "room_full"
	errNotPaired     = "not_paired"
	errRateLimited   = "rate_limited"
	errProtocol      = "protocol"
	errRelayNotReady = "relay_not_ready"
	errRelayCredit   = "relay_credit"
	errRelayLimit    = "relay_limit"
)

// clientMsg is the envelope the server parses from a client. Only type and room are
// read; the payloads of forwardable messages are relayed as raw bytes and never
// decoded here, which is what keeps the server blind to handshake contents.
type clientMsg struct {
	Type  string `json:"type"`
	Room  *int   `json:"room,omitempty"`
	Bytes int64  `json:"bytes,omitempty"`
}

type relayMsg struct {
	Type  string `json:"type"`
	Bytes int64  `json:"bytes,omitempty"`
}

// createdMsg tells the offerer which room number the server allocated.
type createdMsg struct {
	Type string `json:"type"`
	Room int    `json:"room"`
}

// peerJoinedMsg notifies a socket that its room is now paired, with its own role.
type peerJoinedMsg struct {
	Type string `json:"type"`
	Role string `json:"role"`
}

// byeMsg tears a session down.
type byeMsg struct {
	Type   string `json:"type"`
	Reason string `json:"reason,omitempty"`
}

// errorMsg reports a protocol or limit error to a single socket.
type errorMsg struct {
	Type string `json:"type"`
	Code string `json:"code"`
	Msg  string `json:"msg,omitempty"`
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		// The server-built messages above are all trivially marshalable; a failure
		// here is a programming error, not a runtime condition.
		panic("signal: marshal server message: " + err.Error())
	}
	return b
}

func createdFrame(room int) []byte {
	return mustJSON(createdMsg{Type: typeCreated, Room: room})
}

func peerJoinedFrame(role string) []byte {
	return mustJSON(peerJoinedMsg{Type: typePeerJoined, Role: role})
}

func byeFrame(reason string) []byte {
	return mustJSON(byeMsg{Type: typeBye, Reason: reason})
}

func errorFrame(code, msg string) []byte {
	return mustJSON(errorMsg{Type: typeError, Code: code, Msg: msg})
}

func relayFrame(typ string) []byte { return mustJSON(relayMsg{Type: typ}) }

func creditFrame(bytes int64) []byte {
	return mustJSON(relayMsg{Type: typeCredit, Bytes: bytes})
}

// Config controls the signaling server's limits and origin policy.
type Config struct {
	// AllowedOrigins is the WSS origin allowlist for browser clients. An empty list
	// permits only same-origin browser connections. Native clients (CLI) send no
	// Origin header and are always allowed.
	AllowedOrigins []string

	// IdleTimeout closes a socket that sends nothing for this long, and bounds how
	// long an unpaired room lingers before the reaper frees it.
	IdleTimeout time.Duration

	// MaxMessageBytes caps a single inbound WebSocket message; larger frames close
	// the connection. Handshake and caps frames are small, so this stays modest.
	MaxMessageBytes int64

	// MsgBurst / MsgPerSec are the per-connection message-rate token bucket.
	MsgBurst  int
	MsgPerSec float64

	// ConnBurst / ConnPerSec are the per-IP connection-rate token bucket applied at
	// upgrade time.
	ConnBurst  int
	ConnPerSec float64

	// Relay limits bound every layer of the opaque binary data path.
	MaxRelayFrameBytes   int64
	RelayWindowBytes     int64
	RelayQueueBytes      int64
	RelayBurstBytes      int64
	RelayBytesPerSec     int64
	RelayMaxSessionBytes int64
}

// DefaultConfig returns conservative rendezvous and opaque relay limits. Relay ceilings are high
// enough for ordinary transfers while keeping memory, bandwidth, and lifetime bytes explicit.
func DefaultConfig() Config {
	return Config{
		IdleTimeout:          2 * time.Minute,
		MaxMessageBytes:      64 * 1024,
		MsgBurst:             32,
		MsgPerSec:            16,
		ConnBurst:            16,
		ConnPerSec:           8,
		MaxRelayFrameBytes:   128 * 1024,
		RelayWindowBytes:     1 * 1024 * 1024,
		RelayQueueBytes:      2 * 1024 * 1024,
		RelayBurstBytes:      8 * 1024 * 1024,
		RelayBytesPerSec:     32 * 1024 * 1024,
		RelayMaxSessionBytes: 16 * 1024 * 1024 * 1024,
	}
}

// ConfigFromEnv layers SENDARC_* overrides onto DefaultConfig.
func ConfigFromEnv() Config {
	cfg := DefaultConfig()
	if v := os.Getenv("SENDARC_ALLOWED_ORIGINS"); v != "" {
		for _, o := range strings.Split(v, ",") {
			if o = strings.TrimSpace(o); o != "" {
				cfg.AllowedOrigins = append(cfg.AllowedOrigins, o)
			}
		}
	}
	if d, ok := envDuration("SENDARC_SIGNAL_IDLE_TIMEOUT"); ok {
		cfg.IdleTimeout = d
	}
	if n, ok := envInt("SENDARC_SIGNAL_MAX_MESSAGE_BYTES"); ok {
		cfg.MaxMessageBytes = int64(n)
	}
	if n, ok := envInt64("SENDARC_RELAY_MAX_FRAME_BYTES"); ok {
		cfg.MaxRelayFrameBytes = n
	}
	if n, ok := envInt64("SENDARC_RELAY_WINDOW_BYTES"); ok {
		cfg.RelayWindowBytes = n
	}
	if n, ok := envInt64("SENDARC_RELAY_QUEUE_BYTES"); ok {
		cfg.RelayQueueBytes = n
	}
	if n, ok := envInt64("SENDARC_RELAY_BURST_BYTES"); ok {
		cfg.RelayBurstBytes = n
	}
	if n, ok := envInt64("SENDARC_RELAY_BYTES_PER_SEC"); ok {
		cfg.RelayBytesPerSec = n
	}
	if n, ok := envInt64("SENDARC_RELAY_MAX_SESSION_BYTES"); ok {
		cfg.RelayMaxSessionBytes = n
	}
	return cfg
}

func envDuration(key string) (time.Duration, bool) {
	v := os.Getenv(key)
	if v == "" {
		return 0, false
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, false
	}
	return d, true
}

func envInt(key string) (int, bool) {
	v := os.Getenv(key)
	if v == "" {
		return 0, false
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

func envInt64(key string) (int64, bool) {
	v := os.Getenv(key)
	if v == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

// slog helper so callers can pass a nil logger.
func orDiscard(l *slog.Logger) *slog.Logger {
	if l != nil {
		return l
	}
	return slog.New(slog.NewTextHandler(discard{}, nil))
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
