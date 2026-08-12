package main

import (
	"strings"

	"github.com/pion/webrtc/v4"
	"github.com/sendbeam/wire"
)

// iceServerList is a repeatable flag value: each --ice-server occurrence appends one URL.
type iceServerList []string

func (l *iceServerList) String() string { return strings.Join(*l, ",") }

func (l *iceServerList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

// iceServers converts the parsed --ice-server URLs into pion ICE server config, validating
// each URL up front. An empty list maps to nil so the package default STUN server applies.
// It supports multiple STUN (and future TURN) URLs from the same logical config.
func iceServers(urls []string) ([]webrtc.ICEServer, error) {
	if len(urls) == 0 {
		return nil, nil
	}
	entries, err := wire.ParseICEServers(urls)
	if err != nil {
		return nil, err
	}
	servers := make([]webrtc.ICEServer, 0, len(entries))
	for _, e := range entries {
		s := webrtc.ICEServer{URLs: e.URLs}
		if e.Username != "" {
			s.Username = e.Username
			s.Credential = e.Credential
			if e.CredentialType == "oauth" {
				s.CredentialType = webrtc.ICECredentialTypeOauth
			}
		}
		servers = append(servers, s)
	}
	return servers, nil
}
