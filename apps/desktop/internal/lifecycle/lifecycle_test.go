package lifecycle

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSingleInstanceLock(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "sendbeam.lock")

	// 1. First acquisition succeeds
	lock1, err := AcquireSingleInstanceLock(lockPath)
	if err != nil {
		t.Fatalf("first AcquireSingleInstanceLock failed: %v", err)
	}
	if lock1 == nil {
		t.Fatalf("lock1 is nil")
	}
	defer func() { _ = lock1.Release() }()

	// 2. Second concurrent acquisition on same lock file must fail with ErrAnotherInstanceRunning
	lock2, err := AcquireSingleInstanceLock(lockPath)
	if err == nil || !errors.Is(err, ErrAnotherInstanceRunning) {
		if lock2 != nil {
			_ = lock2.Release()
		}
		t.Fatalf("second AcquireSingleInstanceLock returned err = %v, want ErrAnotherInstanceRunning", err)
	}

	// 3. Release first lock
	if err := lock1.Release(); err != nil {
		t.Fatalf("Release lock1 failed: %v", err)
	}

	// 4. Third acquisition now succeeds
	lock3, err := AcquireSingleInstanceLock(lockPath)
	if err != nil {
		t.Fatalf("third AcquireSingleInstanceLock after release failed: %v", err)
	}
	if lock3 == nil {
		t.Fatalf("lock3 is nil")
	}
	_ = lock3.Release()
}

func TestRevealPathValidation(t *testing.T) {
	dir := t.TempDir()
	file1 := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(file1, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	otherDir := t.TempDir()
	otherFile := filepath.Join(otherDir, "outside.txt")
	if err := os.WriteFile(otherFile, []byte("outside"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	tests := []struct {
		name         string
		targetPath   string
		allowedRoots []string
		wantErr      error
	}{
		{
			name:         "empty path",
			targetPath:   "",
			allowedRoots: []string{dir},
			wantErr:      ErrInvalidPath,
		},
		{
			name:         "control characters",
			targetPath:   dir + "/\x00evil.txt",
			allowedRoots: []string{dir},
			wantErr:      ErrInvalidPath,
		},
		{
			name:         "non-existent file",
			targetPath:   filepath.Join(dir, "missing.txt"),
			allowedRoots: []string{dir},
			wantErr:      ErrPathNotFound,
		},
		{
			name:         "file outside allowed root",
			targetPath:   otherFile,
			allowedRoots: []string{dir},
			wantErr:      ErrPathOutsideRoot,
		},
		{
			name:         "valid file inside allowed root",
			targetPath:   file1,
			allowedRoots: []string{dir},
			wantErr:      nil,
		},
		{
			name:         "valid directory without root restrictions",
			targetPath:   dir,
			allowedRoots: nil,
			wantErr:      nil,
		},
		{
			name:         "traversal attempting escape",
			targetPath:   filepath.Join(dir, "..", filepath.Base(otherDir), "outside.txt"),
			allowedRoots: []string{dir},
			wantErr:      ErrPathOutsideRoot,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidatePath(tt.targetPath, tt.allowedRoots...)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("ValidatePath unexpected error: %v", err)
				}
			} else {
				if err == nil || !errors.Is(err, tt.wantErr) {
					t.Fatalf("ValidatePath error = %v, want %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestRevealManager(t *testing.T) {
	dir := t.TempDir()
	file1 := filepath.Join(dir, "data.bin")
	if err := os.WriteFile(file1, []byte("data"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	var launchedPath string
	mgr := NewRevealManager(func(target string) error {
		launchedPath = target
		return nil
	})

	if err := mgr.Reveal(file1, dir); err != nil {
		t.Fatalf("Reveal failed: %v", err)
	}
	if launchedPath != file1 {
		t.Errorf("launchedPath = %q, want %q", launchedPath, file1)
	}

	// Reveal invalid path fails without calling launcher
	launchedPath = ""
	if err := mgr.Reveal(filepath.Join(dir, "nonexistent.bin"), dir); err == nil {
		t.Fatalf("Reveal nonexistent expected error, got nil")
	}
	if launchedPath != "" {
		t.Errorf("launcher was called on invalid path")
	}
}

func TestTestNotifier(t *testing.T) {
	notifier := NewTestNotifier()

	notifier.NotifySuccess("Transfer Complete", "file.txt received (100 KiB)", "/tmp/file.txt")
	notifier.NotifyFailure("Transfer Failed", "network error")

	events := notifier.Events()
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	if events[0].Kind != "success" || events[0].Title != "Transfer Complete" || events[0].Path != "/tmp/file.txt" {
		t.Errorf("event[0] = %+v, want success event", events[0])
	}
	if events[1].Kind != "failure" || events[1].Title != "Transfer Failed" || !strings.Contains(events[1].Message, "network error") {
		t.Errorf("event[1] = %+v, want failure event", events[1])
	}

	notifier.Reset()
	if len(notifier.Events()) != 0 {
		t.Errorf("Events after reset not empty: %v", notifier.Events())
	}
}
