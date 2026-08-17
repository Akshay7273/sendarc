//go:build !windows

package lifecycle

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// AcquireSingleInstanceLock attempts to acquire an exclusive non-blocking lock on path.
// If another process holds the lock, it returns ErrAnotherInstanceRunning.
func AcquireSingleInstanceLock(path string) (*SingleInstanceLock, error) {
	if path == "" {
		return nil, errors.New("lock path cannot be empty")
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create lock dir: %w", err)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}

	// Try non-blocking exclusive flock
	err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) || err == syscall.Errno(0x23) {
			return nil, ErrAnotherInstanceRunning
		}
		return nil, fmt.Errorf("acquire file lock: %w", err)
	}

	// Write PID into lock file for diagnostics
	_ = file.Truncate(0)
	_, _ = file.Seek(0, 0)
	_, _ = fmt.Fprintf(file, "%d\n", os.Getpid())
	_ = file.Sync()

	return &SingleInstanceLock{
		file: file,
		path: path,
	}, nil
}

// Release releases the lock, closes the file, and removes the lock file.
func (l *SingleInstanceLock) Release() error {
	if l == nil || l.file == nil {
		return nil
	}

	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	_ = l.file.Close()
	_ = os.Remove(l.path)
	l.file = nil
	return nil
}
