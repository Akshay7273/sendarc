package lifecycle

import (
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
}

// SilentNotifier is a no-op notifier for headless server mode or when notifications are disabled.
type SilentNotifier struct{}

func (s *SilentNotifier) NotifySuccess(title, message, path string) {}
func (s *SilentNotifier) NotifyFailure(title, message string)       {}

// TestNotifier records notifications in memory for assertions.
type TestNotifier struct {
	mu     sync.Mutex
	events []NotificationEvent
}

// NewTestNotifier creates a TestNotifier.
func NewTestNotifier() *TestNotifier {
	return &TestNotifier{}
}

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

func (t *TestNotifier) NotifyFailure(title, message string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.events = append(t.events, NotificationEvent{
		Kind:    "failure",
		Title:   title,
		Message: message,
	})
}

// Events returns a copy of all recorded events.
func (t *TestNotifier) Events() []NotificationEvent {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]NotificationEvent, len(t.events))
	copy(out, t.events)
	return out
}

// Reset clears the recorded events.
func (t *TestNotifier) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.events = nil
}
