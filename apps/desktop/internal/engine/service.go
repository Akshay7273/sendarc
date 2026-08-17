// Package engine exposes the SendBeam engine to the desktop frontend through
// Wails services. WebRTC, crypto, file I/O, durability, and trust logic stay
// in the Go engine (packages/engine); these services are only a thin
// presentation seam, exactly as the CLI consumes the engine through its
// public API.
package engine

import (
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/sendbeam/engine/rendezvous"
)

// Injected at build time via -ldflags
var (
	// ProductVersion is the desktop product release version (e.g. "1.4.0" or "dev").
	ProductVersion = "dev"

	// GitCommit is the commit SHA (e.g. "1e937f5e07eaf6d74882018c7ce7a42856e22841" or "unknown").
	GitCommit = "unknown"
)

// Service is the Wails service the desktop shell binds to the frontend.
type Service struct{}

// NewService returns a Service.
func NewService() *Service { return &Service{} }

// Info describes the engine build the shell is running against.
type Info struct {
	ProductVersion string `json:"productVersion"`
	Commit         string `json:"commit"`
	GoVersion      string `json:"goVersion"`
	EngineVer      string `json:"engineVer"`
	Platform       string `json:"platform"`
}

// Info returns build info for the shared engine module and application build,
// proving the shell links packages/engine rather than a copy.
func (s *Service) Info() Info {
	ver := strings.TrimSpace(ProductVersion)
	if ver == "" {
		ver = "dev"
	}
	ver = strings.TrimPrefix(ver, "v")

	commit := strings.TrimSpace(GitCommit)
	if commit == "" || commit == "unknown" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			for _, setting := range bi.Settings {
				if setting.Key == "vcs.revision" && setting.Value != "" {
					commit = setting.Value
					break
				}
			}
		}
	}
	if commit == "" {
		commit = "unknown"
	}
	if len(commit) > 12 {
		commit = commit[:12]
	}

	info := Info{
		ProductVersion: ver,
		Commit:         commit,
		GoVersion:      runtime.Version(),
		Platform:       runtime.GOOS + "/" + runtime.GOARCH,
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range bi.Deps {
			if dep.Path == "github.com/sendbeam/engine" {
				info.EngineVer = dep.Version
			}
		}
	}
	return info
}

// Caps returns the engine's default capability set, mirroring what a real
// send/receive session would negotiate.
func (s *Service) Caps() rendezvous.Caps {
	return rendezvous.DefaultCaps()
}
