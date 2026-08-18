package updater

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUpdater_CheckAndApply(t *testing.T) {
	tempDir := t.TempDir()
	targetBinary := filepath.Join(tempDir, "sendbeam")

	oldBinary := []byte("sendbeam-v1.3.0")
	if err := os.WriteFile(targetBinary, oldBinary, 0755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	newBinary := []byte("sendbeam-v1.4.0-updated")
	tarData := createTestTarGz(t, "sendbeam", newBinary)
	tarHash := sha256Hex(tarData)

	archiveName := "sendbeam-cli-linux-amd64.tar.gz"

	// Mock server
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/Akshay7273/sendbeam/releases":
			releases := []map[string]any{
				{
					"tag_name":     "v1.4.0",
					"prerelease":   false,
					"published_at": time.Now().Format(time.RFC3339),
					"body":         "v1.4.0 release notes",
					"assets": []map[string]any{
						{
							"name":                 archiveName,
							"size":                 len(tarData),
							"browser_download_url": srv.URL + "/download/" + archiveName,
						},
						{
							"name":                 "SHA256SUMS.txt",
							"size":                 100,
							"browser_download_url": srv.URL + "/download/SHA256SUMS.txt",
						},
					},
				},
				{
					"tag_name":     "v1.5.0-beta.1",
					"prerelease":   true,
					"published_at": time.Now().Format(time.RFC3339),
					"body":         "v1.5.0 beta notes",
					"assets": []map[string]any{
						{
							"name":                 archiveName,
							"size":                 len(tarData),
							"browser_download_url": srv.URL + "/download/" + archiveName,
						},
					},
				},
			}
			_ = json.NewEncoder(w).Encode(releases)
		case "/download/SHA256SUMS.txt":
			manifest := fmt.Sprintf("%s  %s\n", tarHash, archiveName)
			_, _ = w.Write([]byte(manifest))
		case "/download/" + archiveName:
			_, _ = w.Write(tarData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// Test 1: Stable channel from v1.3.0 -> finds v1.4.0 (and ignores v1.5.0-beta.1)
	u, err := New(
		"1.3.0",
		"Akshay7273/sendbeam",
		WithBaseURL(srv.URL),
		WithChannel(ChannelStable),
		WithTargetPlatform("linux", "amd64"),
		WithExecutablePath(targetBinary),
		WithHTTPClient(srv.Client()),
	)
	if err != nil {
		t.Fatalf("New updater: %v", err)
	}

	check, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}

	if !check.UpdateAvailable {
		t.Fatalf("expected update to be available, message: %s", check.Message)
	}
	if check.LatestVersion.String() != "1.4.0" {
		t.Fatalf("expected latest version 1.4.0 on stable channel, got %s", check.LatestVersion)
	}
	if check.TargetAsset == nil || check.TargetAsset.SHA256 != tarHash {
		t.Fatalf("target asset sha256 mismatch: got %v, expected %s", check.TargetAsset, tarHash)
	}

	// Apply update
	if err := u.Apply(context.Background(), check); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	// Verify file on disk was updated
	updated, err := os.ReadFile(targetBinary)
	if err != nil {
		t.Fatalf("ReadFile after apply: %v", err)
	}
	if !bytes.Equal(updated, newBinary) {
		t.Fatalf("binary on disk not updated: got %q", string(updated))
	}

	// Test 2: Checking when already on 1.4.0 on stable channel -> no update
	uCurrent, _ := New(
		"1.4.0",
		"Akshay7273/sendbeam",
		WithBaseURL(srv.URL),
		WithChannel(ChannelStable),
		WithTargetPlatform("linux", "amd64"),
		WithExecutablePath(targetBinary),
		WithHTTPClient(srv.Client()),
	)
	checkCurrent, err := uCurrent.Check(context.Background())
	if err != nil {
		t.Fatalf("Check on current version failed: %v", err)
	}
	if checkCurrent.UpdateAvailable {
		t.Fatalf("expected no update on current version, got updateAvailable=true")
	}

	// Test 3: Checking on Beta channel from 1.4.0 -> finds 1.5.0-beta.1
	uBeta, _ := New(
		"1.4.0",
		"Akshay7273/sendbeam",
		WithBaseURL(srv.URL),
		WithChannel(ChannelBeta),
		WithTargetPlatform("linux", "amd64"),
		WithExecutablePath(targetBinary),
		WithHTTPClient(srv.Client()),
	)
	checkBeta, err := uBeta.Check(context.Background())
	if err != nil {
		t.Fatalf("Check on beta failed: %v", err)
	}
	if !checkBeta.UpdateAvailable {
		t.Fatalf("expected beta update available, got false (%s)", checkBeta.Message)
	}
	if checkBeta.LatestVersion.String() != "1.5.0-beta.1" {
		t.Fatalf("expected beta version 1.5.0-beta.1, got %s", checkBeta.LatestVersion)
	}
}

func TestUpdater_DevVersion(t *testing.T) {
	u, err := New("dev", "Akshay7273/sendbeam")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	check, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check on dev version failed: %v", err)
	}
	if check.UpdateAvailable {
		t.Fatal("dev version should not report automatic update available")
	}
}
