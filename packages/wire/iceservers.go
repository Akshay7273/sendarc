package wire

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ICEEntry describes one STUN/TURN server used to gather ICE candidates for the direct
// path. It is the Go counterpart of the browser's RTCIceServer and the JSON shape the
// signaling server publishes in /config.json, so the CLI and the browser select candidates
// against the same logical set.
type ICEEntry struct {
	// URLs lists one or more STUN/TURN URLs that refer to the same server/credentials.
	URLs []string `json:"urls"`
	// Username is used with TURN credential types; empty for plain STUN.
	Username string `json:"username,omitempty"`
	// Credential is the shared secret or OAuth access token for TURN; never empty for TURN.
	Credential string `json:"credential,omitempty"`
	// CredentialType is "password" (default) or "oauth".
	CredentialType string `json:"credentialType,omitempty"`
}

// ParseICEServers validates one ICE server URL list and folds them into ICEEntry values,
// grouping consecutive URL strings by the presence of credentials. It rejects malformed or
// unsafe URLs (unknown scheme, empty host, missing or non-numeric port) and keeps
// credential-bearing TURN endpoints distinct from credential-less STUN servers so different
// credentials are never merged. STUN URLs must not carry credentials.
func ParseICEServers(urls []string) ([]ICEEntry, error) {
	entries := make([]ICEEntry, 0, len(urls))
	for _, raw := range urls {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		entry, err := ParseICEServer(raw)
		if err != nil {
			return nil, err
		}
		if n := len(entries); n > 0 && sameCreds(entries[n-1], entry) {
			entries[n-1].URLs = append(entries[n-1].URLs, entry.URLs...)
		} else {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

// ParseICEServer parses and validates a single ICE URL into an ICEEntry. ICE URLs may use
// either the authority form (stun://host:port) or the common opaque form (stun:host:port);
// both are accepted and validated.
func ParseICEServer(raw string) (ICEEntry, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return ICEEntry{}, fmt.Errorf("ice: malformed URL %q: %w", raw, err)
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "stun", "stuns":
		if err := validateHostPort(raw); err != nil {
			return ICEEntry{}, fmt.Errorf("ice: %q: %w", raw, err)
		}
		return ICEEntry{URLs: []string{raw}}, nil
	case "turn", "turns":
		host, port, _, err := splitICE(raw)
		if err != nil {
			return ICEEntry{}, fmt.Errorf("ice: %q: %w", raw, err)
		}
		_ = host
		_ = port
		username, credential, uerr := iceUserInfo(raw)
		if uerr != nil {
			return ICEEntry{}, fmt.Errorf("ice: %q: %w", raw, uerr)
		}
		return ICEEntry{URLs: []string{raw}, Username: username, Credential: credential}, nil
	default:
		return ICEEntry{}, fmt.Errorf("ice: unsupported scheme %q in %q (want stun/stuns/turn/turns)", u.Scheme, raw)
	}
}

// validateHostPort checks that an ICE URL carries a host and a numeric port. It accepts both
// the opaque and authority forms.
func validateHostPort(raw string) error {
	_, _, _, err := splitICE(raw)
	return err
}

// splitICE returns the host, port, scheme, and error for an ICE URL in either form.
func splitICE(raw string) (host, port, scheme string, err error) {
	u, perr := url.Parse(raw)
	if perr != nil {
		return "", "", "", perr
	}
	scheme = strings.ToLower(u.Scheme)
	rest := u.Opaque
	if rest == "" {
		rest = u.Host
	}
	// The opaque form can carry user:cred@host:port; the userinfo is not part of host:port.
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[at+1:]
	}
	host, port, err = net.SplitHostPort(rest)
	if err != nil {
		return "", "", "", fmt.Errorf("missing or invalid host:port: %w", err)
	}
	if host == "" {
		return "", "", "", fmt.Errorf("empty host")
	}
	if port == "" {
		return "", "", "", fmt.Errorf("missing port")
	}
	if p, cerr := strconv.Atoi(port); cerr != nil || p < 1 || p > 65535 {
		return "", "", "", fmt.Errorf("invalid port %q", port)
	}
	return host, port, scheme, nil
}

// iceUserInfo extracts the username:credential pair from a TURN URL's opaque or authority
// user info, if present.
func iceUserInfo(raw string) (username, credential string, err error) {
	u, perr := url.Parse(raw)
	if perr != nil {
		return "", "", perr
	}
	if u.User != nil && u.User.Username() != "" {
		username = u.User.Username()
		credential, _ = u.User.Password()
		return username, credential, nil
	}
	// Opaque form: user:cred@host:port appears inside the opaque part.
	rest := u.Opaque
	if rest == "" {
		return "", "", nil
	}
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		credPart := rest[:at]
		if i := strings.Index(credPart, ":"); i >= 0 {
			username = credPart[:i]
			credential = credPart[i+1:]
		} else {
			username = credPart
		}
	}
	return username, credential, nil
}

func sameCreds(a, b ICEEntry) bool {
	sameScheme := len(a.URLs) > 0 && len(b.URLs) > 0 && schemeOf(a.URLs[0]) == schemeOf(b.URLs[0])
	return sameScheme && a.Username == b.Username && a.Credential == b.Credential
}

func schemeOf(raw string) string {
	if i := strings.Index(raw, ":"); i >= 0 {
		return strings.ToLower(raw[:i])
	}
	return ""
}
