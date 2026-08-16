// Command desktop is the SendBeam desktop app. It runs the shared Go engine
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
	"github.com/wailsapp/wails/v3/pkg/events"

	"github.com/sendbeam/desktop/internal/engine"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	transferSvc := engine.NewTransferService(
		// Emit every transfer snapshot to the frontend.
		func(name string, data any) {
			application.Get().Event.Emit(name, data)
		},
		// Real signaling server (same wsclient the CLI uses → browser/CLI interop).
		nil,
	)

	app := application.New(application.Options{
		Name:        "SendBeam Desktop",
		Description: "Secure, end-to-end-encrypted, peer-to-peer file transfer",
		Services: []application.Service{
			application.NewService(engine.NewService()),
			application.NewService(transferSvc),
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

	win := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:     "SendBeam Desktop",
		Width:     1040,
		Height:    720,
		MinWidth:  760,
		MinHeight: 520,
		URL:       "/",
		// Drag-and-drop files onto the window; the frontend's drop targets
		// carry data-file-drop-target and the runtime posts the dropped paths
		// to the FilesDropped window event below.
		EnableFileDrop: true,
	})

	// Forward OS file drops to a new send. Dropped paths are absolute; the
	// engine's source expansion handles files and folders identically. The
	// drop event lets the frontend adopt the new transfer id and show the
	// invite as soon as the engine allocates the room.
	win.OnWindowEvent(events.Common.WindowFilesDropped, func(e *application.WindowEvent) {
		paths := e.Context().DroppedFiles()
		if len(paths) == 0 {
			return
		}
		h, err := transferSvc.Drop(paths)
		if err != nil {
			application.Get().Event.Emit(engine.TransferEventName, map[string]any{
				"kind":  "error",
				"error": err.Error(),
			})
			return
		}
		application.Get().Event.Emit(engine.TransferEventName, map[string]any{
			"kind":  "drop",
			"id":    h.ID,
			"files": paths,
		})
	})

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
