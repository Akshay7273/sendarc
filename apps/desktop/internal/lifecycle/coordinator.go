// Package lifecycle provides platform integration for desktop durability, single-instance
// locking, native notifications, file reveal, and power/window lifecycle coordination.
package lifecycle

import (
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Shutdownable defines a component that can be gracefully shut down with a timeout.
type Shutdownable interface {
	Shutdown(timeout time.Duration) error
}

// LifecycleEventEmitter is the sink for emitting desktop-wide lifecycle updates.
type LifecycleEventEmitter func(kind, phase string)

// Coordinator coordinates application window hooks, power sleep/wake events,
// tray reachability policies, and bounded idempotent teardown.
type Coordinator struct {
	mu           sync.Mutex
	closeToTray  bool
	isTrayUsable bool
	shutdownOnce sync.Once
	shutdownErr  error
	service      Shutdownable
	emitter      LifecycleEventEmitter
	sleepCount   int
	wakeCount    int
}

// NewCoordinator creates a new lifecycle coordinator.
func NewCoordinator(closeToTray bool, svc Shutdownable, emitter LifecycleEventEmitter) *Coordinator {
	return NewCoordinatorWithPlatform(closeToTray, runtime.GOOS, os.Getenv, svc, emitter)
}

// NewCoordinatorWithPlatform creates a coordinator with explicit platform and env parameters for unit testing.
func NewCoordinatorWithPlatform(closeToTray bool, goos string, env func(string) string, svc Shutdownable, emitter LifecycleEventEmitter) *Coordinator {
	trayUsable := IsTraySupportedOnPlatform(goos, env)
	return &Coordinator{
		closeToTray:  closeToTray,
		isTrayUsable: trayUsable,
		service:      svc,
		emitter:      emitter,
	}
}

// IsTraySupportedOnPlatform evaluates whether system tray reachability can be reliably trusted.
// macOS and Windows provide universal system tray and notification area facilities.
// Linux desktop environments vary widely; hide-to-tray is enabled only where reliable tray host
// facilities are standard (e.g. KDE, XFCE, Cinnamon, MATE, LXQt), degrading safely to normal
// window-close behavior on GNOME or environments without confirmed tray host support.
func IsTraySupportedOnPlatform(goos string, env func(string) string) bool {
	if env == nil {
		env = os.Getenv
	}
	switch goos {
	case "darwin", "windows":
		return true
	case "linux":
		desktop := strings.ToUpper(env("XDG_CURRENT_DESKTOP"))
		if strings.Contains(desktop, "KDE") ||
			strings.Contains(desktop, "XFCE") ||
			strings.Contains(desktop, "CINNAMON") ||
			strings.Contains(desktop, "MATE") ||
			strings.Contains(desktop, "LXQT") ||
			strings.Contains(desktop, "UNITY") ||
			strings.Contains(desktop, "DEEPIN") {
			return true
		}
		if env("KDE_FULL_SESSION") != "" {
			return true
		}
		// GNOME standard session without extensions or unknown desktop sessions degrade conservatively
		// to false so close-to-tray does not create an unreachable/unrecoverable background process.
		return false
	default:
		return false
	}
}

// SetCloseToTray updates the user-configured CloseToTray preference.
func (c *Coordinator) SetCloseToTray(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeToTray = enabled
}

// IsTrayUsable reports whether the current platform supports reachable system tray interaction.
func (c *Coordinator) IsTrayUsable() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isTrayUsable
}

// ShouldHideOnClose reports whether window close events should hide to tray rather than exiting.
// It requires both that CloseToTray is enabled AND that tray interaction is known usable.
func (c *Coordinator) ShouldHideOnClose() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeToTray && c.isTrayUsable
}

// OnSystemWillSleep handles the Wails events.Common.SystemWillSleep notification.
// It preserves in-flight durability state, ensures no false completion is emitted,
// and notifies telemetry/UI.
func (c *Coordinator) OnSystemWillSleep() {
	c.mu.Lock()
	c.sleepCount++
	emitter := c.emitter
	c.mu.Unlock()

	if emitter != nil {
		emitter("lifecycle", "sleep")
	}
}

// OnSystemDidWake handles the Wails events.Common.SystemDidWake notification.
// It triggers UI telemetry refresh while relying on the engine's adaptive transport
// reconnect supervisor for WebRTC/signaling recovery without creating duplicate sessions.
func (c *Coordinator) OnSystemDidWake() {
	c.mu.Lock()
	c.wakeCount++
	emitter := c.emitter
	c.mu.Unlock()

	if emitter != nil {
		emitter("lifecycle", "wake")
	}
}

// SleepWakeCounts returns the total sleep and wake events handled.
func (c *Coordinator) SleepWakeCounts() (sleeps, wakes int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sleepCount, c.wakeCount
}

// Shutdown performs bounded, idempotent application teardown.
func (c *Coordinator) Shutdown(timeout time.Duration) error {
	c.shutdownOnce.Do(func() {
		if c.service != nil {
			c.shutdownErr = c.service.Shutdown(timeout)
		}
	})
	return c.shutdownErr
}
