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
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"

	"github.com/sendbeam/desktop/internal/config"
	"github.com/sendbeam/desktop/internal/engine"
	"github.com/sendbeam/desktop/internal/lifecycle"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	// Single-instance lock: ensure only one authoritative desktop process runs
	// to prevent racing on transfer journals, config, or destinations.
	lockPath := filepath.Join(os.TempDir(), "sendbeam.lock")
	if configDir, err := os.UserConfigDir(); err == nil {
		lockPath = filepath.Join(configDir, config.AppDirName, "sendbeam.lock")
	}
	lock, err := lifecycle.AcquireSingleInstanceLock(lockPath)
	if err != nil {
		if errors.Is(err, lifecycle.ErrAnotherInstanceRunning) {
			fmt.Fprintln(os.Stderr, "SendBeam Desktop: another instance is already running.")
			os.Exit(0)
		}
		// Fail closed on lock acquisition errors rather than running unprotected
		fmt.Fprintf(os.Stderr, "SendBeam Desktop: single-instance lock failed: %v\n", err)
		os.Exit(1)
	}
	if lock != nil {
		defer func() { _ = lock.Release() }()
	}

	transferSvc := engine.NewTransferService(
		// Emit every transfer snapshot to the frontend.
		func(name string, data any) {
			if app := application.Get(); app != nil && app.Event != nil {
				app.Event.Emit(name, data)
			}
		},
		// Real signaling server (same wsclient the CLI uses → browser/CLI interop).
		nil,
	)
	transferSvc.SetNotifier(lifecycle.DefaultNotifier())

	cfg, _ := transferSvc.GetConfig()

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
			ApplicationShouldTerminateAfterLastWindowClosed: false,
		},
	})

	winOpts := application.WebviewWindowOptions{
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
	}
	if cfg.StartMinimized {
		winOpts.StartState = application.WindowStateMinimised
	}

	win := app.Window.NewWithOptions(winOpts)

	// System Tray: provides an authoritative reopen and quit mechanism so close-to-tray
	// or start-minimized never creates an unreachable or un-restorable application.
	systemTray := app.SystemTray.New()
	trayMenu := app.NewMenu()
	trayMenu.Add("Show SendBeam").OnClick(func(_ *application.Context) {
		win.Show()
		win.Focus()
	})
	trayMenu.Add("Quit SendBeam").OnClick(func(_ *application.Context) {
		_ = transferSvc.Shutdown(3 * time.Second)
		app.Quit()
	})
	systemTray.SetMenu(trayMenu)
	systemTray.OnClick(func() {
		win.Show()
		win.Focus()
	})

	// macOS dock reopen hook
	app.Event.OnApplicationEvent(events.Mac.ApplicationShouldHandleReopen, func(_ *application.ApplicationEvent) {
		win.Show()
		win.Focus()
	})

	// Close-to-tray handling: hides window into tray rather than destroying active transfers
	if cfg.CloseToTray {
		win.OnWindowEvent(events.Common.WindowClosing, func(e *application.WindowEvent) {
			if cfg.CloseToTray {
				win.Hide()
				e.Cancel()
			}
		})
	}

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
			if a := application.Get(); a != nil && a.Event != nil {
				a.Event.Emit(engine.TransferEventName, map[string]any{
					"kind":  "error",
					"error": err.Error(),
				})
			}
			return
		}
		if a := application.Get(); a != nil && a.Event != nil {
			a.Event.Emit(engine.TransferEventName, map[string]any{
				"kind":  "drop",
				"id":    h.ID,
				"files": paths,
			})
		}
	})

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}

	// Bounded graceful teardown upon exit: cancel active transfers cleanly
	_ = transferSvc.Shutdown(3 * time.Second)
}
