package lifecycle

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	// ErrPathNotFound is returned when the path to reveal does not exist.
	ErrPathNotFound = errors.New("path does not exist on disk")
	// ErrPathOutsideRoot is returned when the path is not within the authorized directory root.
	ErrPathOutsideRoot = errors.New("path is outside authorized destination directory")
	// ErrInvalidPath is returned when a path contains invalid characters or traversal.
	ErrInvalidPath = errors.New("invalid path")
)

// FileLauncher runs the platform-specific file manager command.
type FileLauncher func(targetPath string) error

// DefaultLauncher executes the native OS file manager to reveal targetPath.
func DefaultLauncher(targetPath string) error {
	switch runtime.GOOS {
	case "darwin":
		cmd := exec.Command("/usr/bin/open", "-R", targetPath)
		return cmd.Start()
	case "windows":
		cmd := exec.Command("explorer.exe", "/select,"+targetPath)
		return cmd.Start()
	default:
		// Linux / BSD: Try org.freedesktop.FileManager1 via dbus if available,
		// otherwise open the containing folder with xdg-open.
		parent := filepath.Dir(targetPath)
		cmd := exec.Command("xdg-open", parent)
		return cmd.Start()
	}
}

// RevealManager validates paths and opens the native file manager.
type RevealManager struct {
	launcher FileLauncher
}

// NewRevealManager creates a RevealManager with the given launcher (or DefaultLauncher if nil).
func NewRevealManager(launcher FileLauncher) *RevealManager {
	if launcher == nil {
		launcher = DefaultLauncher
	}
	return &RevealManager{launcher: launcher}
}

// ValidatePath validates that targetPath is a safe, canonical path that exists on disk.
// If allowedRoots are provided, targetPath must be inside (or equal to) at least one allowed root.
func ValidatePath(targetPath string, allowedRoots ...string) (string, error) {
	if targetPath == "" {
		return "", fmt.Errorf("%w: path is empty", ErrInvalidPath)
	}

	// Reject null bytes and control characters
	for _, r := range targetPath {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("%w: path contains control characters", ErrInvalidPath)
		}
	}

	absPath, err := filepath.Abs(filepath.Clean(targetPath))
	if err != nil {
		return "", fmt.Errorf("%w: resolve absolute path: %v", ErrInvalidPath, err)
	}

	// Verify file or directory actually exists on disk
	fi, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("%w: %s", ErrPathNotFound, absPath)
		}
		return "", fmt.Errorf("stat path %s: %w", absPath, err)
	}
	_ = fi

	// If allowed roots are provided, ensure absPath is within one of them
	if len(allowedRoots) > 0 {
		authorized := false
		for _, root := range allowedRoots {
			if root == "" {
				continue
			}
			absRoot, err := filepath.Abs(filepath.Clean(root))
			if err != nil {
				continue
			}
			rel, err := filepath.Rel(absRoot, absPath)
			if err == nil && !strings.HasPrefix(rel, "..") && rel != ".." {
				authorized = true
				break
			}
		}
		if !authorized {
			return "", fmt.Errorf("%w: %s is not within allowed destination roots %v", ErrPathOutsideRoot, absPath, allowedRoots)
		}
	}

	return absPath, nil
}

// Reveal validates targetPath and reveals it in the native file manager.
func (r *RevealManager) Reveal(targetPath string, allowedRoots ...string) error {
	validated, err := ValidatePath(targetPath, allowedRoots...)
	if err != nil {
		return err
	}
	return r.launcher(validated)
}
