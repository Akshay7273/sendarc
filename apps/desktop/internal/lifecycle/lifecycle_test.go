package lifecycle

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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
		t.Fatalf("first AcquireSingleInstanceLock returned nil lock")
	}

	// 2. Second acquisition on same path fails with ErrAnotherInstanceRunning
	lock2, err := AcquireSingleInstanceLock(lockPath)
	if err == nil || !errors.Is(err, ErrAnotherInstanceRunning) {
		t.Fatalf("second AcquireSingleInstanceLock error = %v, want ErrAnotherInstanceRunning", err)
	}
	if lock2 != nil {
		t.Fatalf("second AcquireSingleInstanceLock returned non-nil lock")
	}

	// 3. Release first lock
	if err := lock1.Release(); err != nil {
		t.Fatalf("Release failed: %v", err)
	}

	// 4. Acquisition succeeds again after release
	lock3, err := AcquireSingleInstanceLock(lockPath)
	if err != nil {
		t.Fatalf("AcquireSingleInstanceLock after release failed: %v", err)
	}
	if lock3 == nil {
		t.Fatalf("AcquireSingleInstanceLock after release returned nil lock")
	}
	_ = lock3.Release()
}

func TestValidatePathConfinement(t *testing.T) {
	dir := t.TempDir()

	// Setup authorized root
	root := filepath.Join(dir, "downloads")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}

	// Setup external directory (unauthorized)
	external := filepath.Join(dir, "external")
	if err := os.MkdirAll(external, 0o755); err != nil {
		t.Fatal(err)
	}

	// Valid target inside root
	validFile := filepath.Join(root, "valid.txt")
	if err := os.WriteFile(validFile, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Valid hidden / dotfile inside root
	dotFile := filepath.Join(root, ".hidden_data")
	if err := os.WriteFile(dotFile, []byte("hidden"), 0o600); err != nil {
		t.Fatal(err)
	}

	// File outside authorized root
	externalFile := filepath.Join(external, "secret.txt")
	if err := os.WriteFile(externalFile, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Symlink inside root pointing outside
	symlinkEscape := filepath.Join(root, "escape_link.txt")
	_ = os.Symlink(externalFile, symlinkEscape)

	tests := []struct {
		name    string
		target  string
		roots   []string
		wantErr error
	}{
		{
			name:    "valid file within root",
			target:  validFile,
			roots:   []string{root},
			wantErr: nil,
		},
		{
			name:    "valid hidden dotfile within root",
			target:  dotFile,
			roots:   []string{root},
			wantErr: nil,
		},
		{
			name:    "file outside authorized roots",
			target:  externalFile,
			roots:   []string{root},
			wantErr: ErrPathOutsideRoot,
		},
		{
			name:    "symlink escaping root boundary",
			target:  symlinkEscape,
			roots:   []string{root},
			wantErr: ErrPathOutsideRoot,
		},
		{
			name:    "nonexistent file",
			target:  filepath.Join(root, "nonexistent.bin"),
			roots:   []string{root},
			wantErr: ErrPathNotFound,
		},
		{
			name:    "empty target",
			target:  "",
			roots:   []string{root},
			wantErr: ErrInvalidPath,
		},
		{
			name:    "no authorized roots",
			target:  validFile,
			roots:   nil,
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidatePath(tt.target, tt.roots...)
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

	// Platform Notifiers
	darwinNotif := &DarwinNotifier{}
	if runtime.GOOS != "darwin" && darwinNotif.IsAvailable() {
		t.Errorf("DarwinNotifier.IsAvailable() must be false on non-darwin")
	}
	if darwinNotif.BackendName() != "darwin-osascript" {
		t.Errorf("DarwinNotifier.BackendName() = %q, want darwin-osascript", darwinNotif.BackendName())
	}

	winNotif := &WindowsNotifier{}
	if runtime.GOOS != "windows" && winNotif.IsAvailable() {
		t.Errorf("WindowsNotifier.IsAvailable() must be false on non-windows")
	}
	if winNotif.BackendName() != "windows-powershell" {
		t.Errorf("WindowsNotifier.BackendName() = %q, want windows-powershell", winNotif.BackendName())
	}

	linuxNotif := &LinuxNotifier{}
	if runtime.GOOS != "linux" && linuxNotif.IsAvailable() {
		t.Errorf("LinuxNotifier.IsAvailable() must be false on non-linux")
	}
	if linuxNotif.BackendName() != "linux-notify-send" {
		t.Errorf("LinuxNotifier.BackendName() = %q, want linux-notify-send", linuxNotif.BackendName())
	}
}

func TestIsTraySupportedOnPlatform(t *testing.T) {
	tests := []struct {
		name string
		goos string
		env  map[string]string
		want bool
	}{
		{
			name: "macOS is always supported",
			goos: "darwin",
			want: true,
		},
		{
			name: "windows is always supported",
			goos: "windows",
			want: true,
		},
		{
			name: "linux KDE desktop",
			goos: "linux",
			env:  map[string]string{"XDG_CURRENT_DESKTOP": "KDE"},
			want: true,
		},
		{
			name: "linux XFCE desktop",
			goos: "linux",
			env:  map[string]string{"XDG_CURRENT_DESKTOP": "XFCE"},
			want: true,
		},
		{
			name: "linux MATE desktop",
			goos: "linux",
			env:  map[string]string{"XDG_CURRENT_DESKTOP": "MATE"},
			want: true,
		},
		{
			name: "linux GNOME standard desktop degrades safely",
			goos: "linux",
			env:  map[string]string{"XDG_CURRENT_DESKTOP": "GNOME"},
			want: false,
		},
		{
			name: "linux unknown desktop degrades safely",
			goos: "linux",
			env:  map[string]string{"XDG_CURRENT_DESKTOP": "custom-wm"},
			want: false,
		},
		{
			name: "unsupported OS",
			goos: "freebsd",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envFn := func(k string) string {
				if tt.env != nil {
					return tt.env[k]
				}
				return ""
			}
			got := IsTraySupportedOnPlatform(tt.goos, envFn)
			if got != tt.want {
				t.Errorf("IsTraySupportedOnPlatform(%q) = %v, want %v", tt.goos, got, tt.want)
			}
		})
	}
}

func TestLifecycleCoordinatorCloseToTrayPolicy(t *testing.T) {
	// Darwin with CloseToTray = true
	coordDarwin := NewCoordinatorWithPlatform(true, "darwin", nil, nil, nil)
	if !coordDarwin.ShouldHideOnClose() {
		t.Errorf("Darwin with CloseToTray=true should hide on close")
	}

	// Darwin with CloseToTray = false
	coordDarwin.SetCloseToTray(false)
	if coordDarwin.ShouldHideOnClose() {
		t.Errorf("Darwin with CloseToTray=false should not hide on close")
	}

	// Linux GNOME (tray unsupported) with CloseToTray = true -> degrades to false
	coordGnome := NewCoordinatorWithPlatform(true, "linux", func(k string) string {
		if k == "XDG_CURRENT_DESKTOP" {
			return "GNOME"
		}
		return ""
	}, nil, nil)
	if coordGnome.ShouldHideOnClose() {
		t.Errorf("Linux GNOME should degrade ShouldHideOnClose to false")
	}
	if coordGnome.IsTrayUsable() {
		t.Errorf("Linux GNOME IsTrayUsable() = true, want false")
	}

	// Linux KDE (tray supported) with CloseToTray = true -> hides
	coordKDE := NewCoordinatorWithPlatform(true, "linux", func(k string) string {
		if k == "XDG_CURRENT_DESKTOP" {
			return "KDE"
		}
		return ""
	}, nil, nil)
	if !coordKDE.ShouldHideOnClose() {
		t.Errorf("Linux KDE ShouldHideOnClose() = false, want true")
	}
}

type mockShutdownable struct {
	shutdownCalls int32
}

func (m *mockShutdownable) Shutdown(_ time.Duration) error {
	atomic.AddInt32(&m.shutdownCalls, 1)
	return nil
}

func TestLifecycleCoordinatorSleepWakeAndShutdown(t *testing.T) {
	var emittedEvents []string
	emitter := func(kind, phase string) {
		emittedEvents = append(emittedEvents, kind+":"+phase)
	}

	mockSvc := &mockShutdownable{}
	coord := NewCoordinatorWithPlatform(true, "windows", nil, mockSvc, emitter)

	// 1. Sleep event
	coord.OnSystemWillSleep()
	sleeps, wakes := coord.SleepWakeCounts()
	if sleeps != 1 || wakes != 0 {
		t.Errorf("SleepWakeCounts after sleep: %d, %d; want 1, 0", sleeps, wakes)
	}

	// 2. Wake event
	coord.OnSystemDidWake()
	sleeps, wakes = coord.SleepWakeCounts()
	if sleeps != 1 || wakes != 1 {
		t.Errorf("SleepWakeCounts after wake: %d, %d; want 1, 1", sleeps, wakes)
	}

	if len(emittedEvents) != 2 || emittedEvents[0] != "lifecycle:sleep" || emittedEvents[1] != "lifecycle:wake" {
		t.Errorf("emittedEvents = %v, want [lifecycle:sleep lifecycle:wake]", emittedEvents)
	}

	// 3. Idempotent shutdown
	if err := coord.Shutdown(time.Second); err != nil {
		t.Fatalf("first Shutdown failed: %v", err)
	}
	if err := coord.Shutdown(time.Second); err != nil {
		t.Fatalf("second Shutdown failed: %v", err)
	}

	calls := atomic.LoadInt32(&mockSvc.shutdownCalls)
	if calls != 1 {
		t.Errorf("Shutdown was called %d times, want exactly 1 (idempotent)", calls)
	}
}
