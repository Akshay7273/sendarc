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

func TestSingleInstanceLockInvalidPath(t *testing.T) {
	// Empty path
	_, err := AcquireSingleInstanceLock("")
	if err == nil {
		t.Fatalf("AcquireSingleInstanceLock with empty path expected error, got nil")
	}
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

	// Legitimate dotfile inside dir
	dotFile := filepath.Join(dir, "..legit.txt")
	if err := os.WriteFile(dotFile, []byte("dotcontent"), 0o600); err != nil {
		t.Fatalf("write dotfile: %v", err)
	}

	// Symlink inside dir pointing to file in otherDir
	symlinkToOutside := filepath.Join(dir, "symlink_outside.txt")
	_ = os.Symlink(otherFile, symlinkToOutside)

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
			name:         "legitimate dotfile starting with .. inside allowed root",
			targetPath:   dotFile,
			allowedRoots: []string{dir},
			wantErr:      nil,
		},
		{
			name:         "symlink inside root pointing outside root is rejected",
			targetPath:   symlinkToOutside,
			allowedRoots: []string{dir},
			wantErr:      ErrPathOutsideRoot,
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
	realFile1, _ := filepath.EvalSymlinks(file1)
	if launchedPath != realFile1 && launchedPath != file1 {
		t.Errorf("launchedPath = %q, want %q or %q", launchedPath, realFile1, file1)
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

func TestNotifiers(t *testing.T) {
	// TestNotifier
	testNotif := NewTestNotifier()
	if !testNotif.IsAvailable() {
		t.Errorf("TestNotifier.IsAvailable() = false, want true")
	}
	if testNotif.BackendName() != "test" {
		t.Errorf("TestNotifier.BackendName() = %q, want test", testNotif.BackendName())
	}

	testNotif.NotifySuccess("Transfer Complete", "file.txt received (100 KiB)", "/tmp/file.txt")
	testNotif.NotifyFailure("Transfer Failed", "network error")

	events := testNotif.Events()
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	if events[0].Kind != "success" || events[0].Title != "Transfer Complete" || events[0].Path != "/tmp/file.txt" {
		t.Errorf("event[0] = %+v, want success event", events[0])
	}
	if events[1].Kind != "failure" || events[1].Title != "Transfer Failed" || !strings.Contains(events[1].Message, "network error") {
		t.Errorf("event[1] = %+v, want failure event", events[1])
	}

	testNotif.Reset()
	if len(testNotif.Events()) != 0 {
		t.Errorf("Events after reset not empty: %v", testNotif.Events())
	}

	// SilentNotifier
	silent := &SilentNotifier{}
	if silent.IsAvailable() {
		t.Errorf("SilentNotifier.IsAvailable() = true, want false")
	}
	if silent.BackendName() != "silent" {
		t.Errorf("SilentNotifier.BackendName() = %q, want silent", silent.BackendName())
	}
	silent.NotifySuccess("Title", "Msg", "path")
	silent.NotifyFailure("Title", "Msg")

	// DefaultNotifier
	defNotif := DefaultNotifier()
	if defNotif == nil {
		t.Fatalf("DefaultNotifier() returned nil")
	}
	if defNotif.BackendName() == "" {
		t.Errorf("DefaultNotifier.BackendName() is empty")
	}
}
