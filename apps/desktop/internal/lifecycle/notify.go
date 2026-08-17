// Package lifecycle manages desktop lifecycle events, single-instance locking,
// notifications, and OS integration.
package lifecycle

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

// NotificationEvent represents an emitted native notification.
type NotificationEvent struct {
	Kind    string // "success" | "failure"
	Title   string
	Message string
	Path    string
}

// Notifier is the interface for emitting native desktop notifications.
// Notifications MUST ONLY be emitted after verified transfer completion or failure.
type Notifier interface {
	NotifySuccess(title, message, path string)
	NotifyFailure(title, message string)
	IsAvailable() bool
	BackendName() string
}

// SilentNotifier is a no-op notifier for headless server mode or when notifications are disabled.
type SilentNotifier struct{}

// NotifySuccess is a no-op for SilentNotifier.
func (s *SilentNotifier) NotifySuccess(_, _, _ string) {}

// NotifyFailure is a no-op for SilentNotifier.
func (s *SilentNotifier) NotifyFailure(_, _ string) {}

// IsAvailable reports false for SilentNotifier.
func (s *SilentNotifier) IsAvailable() bool { return false }

// BackendName returns "silent".
func (s *SilentNotifier) BackendName() string { return "silent" }

// TestNotifier records notifications in memory for assertions.
type TestNotifier struct {
	mu     sync.Mutex
	events []NotificationEvent
}

// NewTestNotifier creates a TestNotifier.
func NewTestNotifier() *TestNotifier {
	return &TestNotifier{}
}

// NotifySuccess records a success notification event.
func (t *TestNotifier) NotifySuccess(title, message, path string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.events = append(t.events, NotificationEvent{
		Kind:    "success",
		Title:   title,
		Message: message,
		Path:    path,
	})
}

// NotifyFailure records a failure notification event.
func (t *TestNotifier) NotifyFailure(title, message string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.events = append(t.events, NotificationEvent{
		Kind:    "failure",
		Title:   title,
		Message: message,
	})
}

// IsAvailable reports true for TestNotifier.
func (t *TestNotifier) IsAvailable() bool { return true }

// BackendName returns "test".
func (t *TestNotifier) BackendName() string { return "test" }

// Events returns a copy of all recorded events.
func (t *TestNotifier) Events() []NotificationEvent {
	t.mu.Lock()
	defer t.mu.Unlock()
	cpy := make([]NotificationEvent, len(t.events))
	copy(cpy, t.events)
	return cpy
}

// Reset clears the recorded events.
func (t *TestNotifier) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.events = t.events[:0]
}

// DarwinNotifier emits macOS UserNotifications via osascript.
type DarwinNotifier struct{}

// NotifySuccess displays a macOS notification for completed transfers.
func (d *DarwinNotifier) NotifySuccess(title, message, _ string) {
	script := fmt.Sprintf(`display notification %q with title %q`, message, title)
	cmd := exec.Command("osascript", "-e", script)
	_ = cmd.Start()
}

// NotifyFailure displays a macOS notification for transfer failures.
func (d *DarwinNotifier) NotifyFailure(title, message string) {
	script := fmt.Sprintf(`display notification %q with title %q`, message, title)
	cmd := exec.Command("osascript", "-e", script)
	_ = cmd.Start()
}

// IsAvailable reports true on Darwin when osascript is in PATH.
func (d *DarwinNotifier) IsAvailable() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	_, err := exec.LookPath("osascript")
	return err == nil
}

// BackendName returns "darwin-osascript".
func (d *DarwinNotifier) BackendName() string { return "darwin-osascript" }

// WindowsNotifier emits Windows desktop notifications via PowerShell toast.
type WindowsNotifier struct{}

// NotifySuccess displays a Windows toast notification for completed transfers.
func (w *WindowsNotifier) NotifySuccess(title, message, _ string) {
	script := fmt.Sprintf(`[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null; $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); $text = $template.GetElementsByTagName('text'); $text[0].AppendChild($template.CreateTextNode('%s')) > $null; $text[1].AppendChild($template.CreateTextNode('%s')) > $null; $toast = [Windows.UI.Notifications.ToastNotification]::new($template); [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('SendBeam').Show($toast)`, escapePowerShell(title), escapePowerShell(message))
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	_ = cmd.Start()
}

// NotifyFailure displays a Windows toast notification for transfer failures.
func (w *WindowsNotifier) NotifyFailure(title, message string) {
	script := fmt.Sprintf(`[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null; $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); $text = $template.GetElementsByTagName('text'); $text[0].AppendChild($template.CreateTextNode('%s')) > $null; $text[1].AppendChild($template.CreateTextNode('%s')) > $null; $toast = [Windows.UI.Notifications.ToastNotificationManager]::new($template); [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('SendBeam').Show($toast)`, escapePowerShell(title), escapePowerShell(message))
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	_ = cmd.Start()
}

// IsAvailable reports true on Windows.
func (w *WindowsNotifier) IsAvailable() bool {
	return runtime.GOOS == "windows"
}

// BackendName returns "windows-powershell".
func (w *WindowsNotifier) BackendName() string { return "windows-powershell" }

func escapePowerShell(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// LinuxNotifier emits FreeDesktop desktop notifications using notify-send.
type LinuxNotifier struct{}

// NotifySuccess displays a Linux notification for completed transfers.
func (l *LinuxNotifier) NotifySuccess(title, message, _ string) {
	cmd := exec.Command("notify-send", "-a", "SendBeam", "-i", "document-save", title, message)
	_ = cmd.Start()
}

// NotifyFailure displays a Linux notification for transfer failures.
func (l *LinuxNotifier) NotifyFailure(title, message string) {
	cmd := exec.Command("notify-send", "-a", "SendBeam", "-u", "critical", "-i", "dialog-error", title, message)
	_ = cmd.Start()
}

// IsAvailable reports true on Linux when notify-send is in PATH.
func (l *LinuxNotifier) IsAvailable() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	_, err := exec.LookPath("notify-send")
	return err == nil
}

// BackendName returns "linux-notify-send".
func (l *LinuxNotifier) BackendName() string { return "linux-notify-send" }

// DefaultNotifier returns the native notifier appropriate for the platform.
// If the platform notification facility is unavailable, it returns a SilentNotifier.
func DefaultNotifier() Notifier {
	switch runtime.GOOS {
	case "darwin":
		dn := &DarwinNotifier{}
		if dn.IsAvailable() {
			return dn
		}
	case "windows":
		wn := &WindowsNotifier{}
		if wn.IsAvailable() {
			return wn
		}
	case "linux":
		ln := &LinuxNotifier{}
		if ln.IsAvailable() {
			return ln
		}
	}
	return &SilentNotifier{}
}
