// Command desktop is the SendBeam desktop shell. It runs the shared Go engine
// (packages/engine) behind Wails v3 services and a system-WebView frontend; all
// WebRTC, crypto, file I/O, durability, and trust logic stays in the engine.
//
// Build modes:
//
//	# Desktop (native window; needs platform WebView deps)
//	go build -o sendbeam-desktop .
//
//	# Server (headless HTTP; no GUI deps, used by CI and tests)
//	go build -tags server -o sendbeam-desktop-server .
package main

import (
	"embed"
	"log"

	"github.com/wailsapp/wails/v3/pkg/application"

	"github.com/sendbeam/desktop/internal/engine"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := application.New(application.Options{
		Name:        "SendBeam Desktop",
		Description: "Secure, end-to-end-encrypted, peer-to-peer file transfer",
		Services: []application.Service{
			application.NewService(engine.NewService()),
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
		// Server mode (go build -tags server) serves the same app over HTTP —
		// used by CI and headless smoke tests, with no GUI dependencies.
		Server: application.ServerOptions{
			Host: "localhost",
			Port: 18123,
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: true,
		},
	})

	app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:     "SendBeam Desktop",
		Width:     960,
		Height:    640,
		MinWidth:  720,
		MinHeight: 480,
		URL:       "/",
	})

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
