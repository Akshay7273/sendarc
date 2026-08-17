//go:build windows

package lifecycle

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const (
	// ERROR_SHARING_VIOLATION is the Win32 error code 32 (0x20).
	errorSharingViolation = syscall.Errno(32)
)

// AcquireSingleInstanceLock on Windows opens the file with exclusive access (no sharing),
// preventing another instance from opening or acquiring it.
func AcquireSingleInstanceLock(path string) (*SingleInstanceLock, error) {
	if path == "" {
		return nil, errors.New("lock path cannot be empty")
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create lock dir: %w", err)
	}

	path16, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}

	// Create/open file with exclusive access (dwShareMode = 0 -> no sharing)
	h, err := syscall.CreateFile(
		path16,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		0, // exclusive: no share read or write
		nil,
		syscall.OPEN_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		if errors.Is(err, errorSharingViolation) || errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
			return nil, ErrAnotherInstanceRunning
		}
		return nil, fmt.Errorf("open exclusive lock file: %w", err)
	}

	file := os.NewFile(uintptr(h), path)
	_ = file.Truncate(0)
	_, _ = file.Seek(0, 0)
	_, _ = fmt.Fprintf(file, "%d\n", os.Getpid())
	_ = file.Sync()

	return &SingleInstanceLock{
		file: file,
		path: path,
	}, nil
}

// Release releases the lock and closes the file handle.
func (l *SingleInstanceLock) Release() error {
	if l == nil || l.file == nil {
		return nil
	}

	_ = l.file.Close()
	_ = os.Remove(l.path)
	l.file = nil
	return nil
}
