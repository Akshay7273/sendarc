package main

import (
	"fmt"
	"io"
	"runtime/debug"
	"strings"
)

var (
	// Version is the product build version (e.g. "1.4.0" or "dev").
	// Injected at build time via -ldflags "-X main.Version=...".
	Version = "dev"

	// GitCommit is the commit SHA (e.g. "1e937f5e07eaf6d74882018c7ce7a42856e22841" or "unknown").
	// Injected at build time via -ldflags "-X main.GitCommit=...".
	GitCommit = "unknown"
)

// buildVersionString formats the product version and short commit SHA into a
// stable, compact string suitable for scripting and CLI output:
//
//	sendbeam dev (1e937f5e07ea)
//	sendbeam 1.4.0 (abcdef123456)
//	sendbeam dev (unknown)
func buildVersionString(v, c string) string {
	ver := strings.TrimSpace(v)
	if ver == "" {
		ver = "dev"
	}
	ver = strings.TrimPrefix(ver, "v")

	commit := strings.TrimSpace(c)
	if commit == "" || commit == "unknown" {
		// Fallback to runtime/debug VCS info if available
		if bi, ok := debug.ReadBuildInfo(); ok {
			for _, s := range bi.Settings {
				if s.Key == "vcs.revision" && s.Value != "" {
					commit = s.Value
					break
				}
			}
		}
	}
	if commit == "" {
		commit = "unknown"
	}

	shortCommit := commit
	if len(shortCommit) > 12 {
		shortCommit = shortCommit[:12]
	}

	return fmt.Sprintf("sendbeam %s (%s)", ver, shortCommit)
}

func printVersion(w io.Writer) {
	_, _ = fmt.Fprintln(w, buildVersionString(Version, GitCommit))
}
