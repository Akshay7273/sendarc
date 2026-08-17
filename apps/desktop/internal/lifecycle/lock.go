// Package lifecycle manages desktop lifecycle events, single-instance locking,
// notifications, and OS integration.
package lifecycle

import (
	"errors"
	"os"
)

var (
	// ErrAnotherInstanceRunning is returned when another SendBeam Desktop process
	// holds the single-instance lock.
	ErrAnotherInstanceRunning = errors.New("another SendBeam Desktop instance is already running")
)

// SingleInstanceLock represents an active single-instance lock file.
type SingleInstanceLock struct {
	file *os.File
	path string
}

// Path returns the path of the lock file.
func (l *SingleInstanceLock) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}
