// Package engine exposes the SendBeam engine to the desktop frontend through
// Wails services. WebRTC, crypto, file I/O, durability, and trust logic stay
// in the Go engine (packages/engine); these services are only a thin
// presentation seam, exactly as the CLI consumes the engine through its
// public API.
package engine

import (
	"runtime"
	"runtime/debug"

	"github.com/sendbeam/engine/rendezvous"
)

// Service is the Wails service the desktop shell binds to the frontend.
type Service struct{}

// NewService returns a Service.
func NewService() *Service { return &Service{} }

// Info describes the engine build the shell is running against.
type Info struct {
	GoVersion string `json:"goVersion"`
	EngineVer string `json:"engineVer"`
	Platform  string `json:"platform"`
}

// Info returns build info for the shared engine module, proving the shell
// links packages/engine rather than a copy.
func (s *Service) Info() Info {
	info := Info{GoVersion: runtime.Version()}
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
