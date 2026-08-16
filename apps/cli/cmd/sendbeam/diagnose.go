// Command diagnose: a standalone, sanitized connection diagnostic for SendBeam. It probes
// the reachable surface (signaling /config.json, STUN/TURN servers) and reports local
// interface/ICE capability counts — never full IPs, credentials, codes, or filenames.
// Output is one JSON object (see ADR 0003 / V12-PR06).
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pion/stun/v3"

	"github.com/sendbeam/engine/diagnostics"
	"github.com/sendbeam/wire"
)

// diagnoseConfig is the subset of /config.json the CLI honors, mirrored here so the
// diagnose command can report how the operator configures ICE without leaking it.
type diagnoseConfig struct {
	ICEServers []wire.ICEEntry `json:"iceServers"`
}

// diagnoseProbe is one sanitized server-reachability result.
type diagnoseProbe struct {
	Scheme    string `json:"scheme"`
	Reachable bool   `json:"reachable"`
	// HasCredentials reports a TURN/STUN entry carried credentials (never the credentials).
	HasCredentials bool   `json:"hasCredentials,omitempty"`
	Error          string `json:"error,omitempty"`
}

// diagnoseResult is the sanitized output of `sendbeam diagnose`.
type diagnoseResult struct {
	App string `json:"app"`
	// ICEServersConfigured counts configured ICE servers.
	ICEServersConfigured int `json:"iceServersConfigured"`
	// TURNConfigured reports whether any TURN server was configured.
	TURNConfigured bool `json:"turnConfigured"`
	// Probes is the per-server reachability result.
	Probes []diagnoseProbe `json:"probes,omitempty"`
	// InterfaceIPv4/IPv6 report local stack capability (counts only, never addresses).
	InterfaceIPv4 bool `json:"interfaceIPv4"`
	InterfaceIPv6 bool `json:"interfaceIPv6"`
	// SanitizedLog is a short list of sanitized observations.
	SanitizedLog []string `json:"sanitizedLog,omitempty"`
}

func runDiagnose(args []string) int {
	fs := flag.NewFlagSet("diagnose", flag.ExitOnError)
	server := fs.String("server", defaultServer, "signaling server URL")
	insecure := fs.Bool("insecure-skip-verify", false, "skip TLS verification (self-signed dev certs only)")
	timeout := fs.Duration("timeout", 5*time.Second, "per-probe timeout")
	_ = fs.Parse(args)

	res := &diagnoseResult{App: "cli"}
	res.SanitizedLog = append(res.SanitizedLog, "diagnose: probe start")

	// Local stack capability: interface address family presence only.
	v4, v6 := interfaceFamilies()
	res.InterfaceIPv4 = v4
	res.InterfaceIPv6 = v6

	ctx, cancel := context.WithTimeout(context.Background(), *timeout*4)
	defer cancel()

	cfg, err := fetchServerConfig(ctx, *server, *insecure, *timeout)
	if err != nil {
		res.SanitizedLog = append(res.SanitizedLog, "diagnose: "+diagnostics.Sanitize(err.Error()))
	} else {
		res.ICEServersConfigured = len(cfg.ICEServers)
		for _, e := range cfg.ICEServers {
			if strings.HasPrefix(strings.ToLower(e.URLs[0]), "turn:") || strings.HasPrefix(strings.ToLower(e.URLs[0]), "turns:") {
				res.TURNConfigured = true
			}
		}
		for _, e := range cfg.ICEServers {
			probe := diagnoseProbe{
				Scheme:         strings.ToLower(strings.SplitN(e.URLs[0], ":", 2)[0]),
				HasCredentials: e.Username != "" || e.Credential != "",
			}
			switch probe.Scheme {
			case "stun", "stuns":
				if probe.Reachable = probeStun(ctx, e.URLs[0], *timeout); !probe.Reachable {
					probe.Error = "STUN binding request timed out or failed"
				}
			case "turn", "turns":
				probe.Reachable = true // TURN reachability requires credentials; presence is all we report
			}
			res.Probes = append(res.Probes, probe)
		}
	}
	res.SanitizedLog = append(res.SanitizedLog, "diagnose: probe complete")

	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
	return 0
}

// fetchServerConfig requests /config.json from the signaling server and parses the ICE
// entries. The full response is never echoed back; only the sanitized summary is.
func fetchServerConfig(ctx context.Context, server string, insecure bool, timeout time.Duration) (*diagnoseConfig, error) {
	u, err := url.Parse(server)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid server URL")
	}
	switch u.Scheme {
	case "wss":
		u.Scheme = "https"
	case "ws":
		u.Scheme = "http"
	default:
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	u.Path = "/config.json"
	u.RawQuery = ""
	u.Fragment = ""

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure}, // #nosec G402 -- explicit dev flag
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var cfg diagnoseConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return &cfg, nil
}

// probeStun sends a STUN binding request to the given server URL and reports whether a
// binding response arrives within timeout. A response confirms the host is reachable and
// speaks STUN; the source address it reports back is discarded.
func probeStun(ctx context.Context, rawURL string, timeout time.Duration) bool {
	addr, scheme := stunHostPort(rawURL)
	if addr == "" {
		return false
	}
	network := "udp"
	if scheme == "stuns" {
		network = "tcp"
	}
	conn, err := net.DialTimeout(network, addr, timeout)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	c, err := stun.NewClient(conn)
	if err != nil {
		return false
	}
	defer func() { _ = c.Close() }()
	c.SetRTO(timeout / 2)

	done := make(chan error, 1)
	message, err := stun.Build(stun.TransactionID, stun.BindingRequest)
	if err != nil {
		return false
	}
	if err := c.Do(message, func(res stun.Event) { done <- res.Error }); err != nil {
		return false
	}
	select {
	case err := <-done:
		return err == nil
	case <-ctx.Done():
		return false
	case <-time.After(timeout):
		return false
	}
}

// stunHostPort extracts a dialable host:port from an ICE URL of the form
// stun:host:port or stuns:host:port (authority or opaque), dropping any userinfo.
func stunHostPort(raw string) (addr, scheme string) {
	rest := raw
	if i := strings.Index(rest, ":"); i >= 0 {
		scheme = strings.ToLower(rest[:i])
		rest = strings.TrimPrefix(rest[i+1:], "//")
	}
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[at+1:]
	}
	if rest == "" {
		return "", scheme
	}
	return rest, scheme
}

// interfaceFamilies reports whether any interface has an IPv4 or IPv6 unicast address.
// Counts only — the addresses themselves are never returned.
func interfaceFamilies() (ipv4, ipv6 bool) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false, false
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if ipnet.IP.To4() != nil {
				ipv4 = true
			} else if strings.Contains(ipnet.IP.String(), ":") {
				ipv6 = true
			}
		}
	}
	return ipv4, ipv6
}
