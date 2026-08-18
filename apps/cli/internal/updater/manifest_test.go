package updater

import (
	"strings"
	"testing"
)

func TestParseChecksums(t *testing.T) {
	manifest := `# Official SHA256 checksums
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  sendbeam-cli-linux-amd64.tar.gz
a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e *sendbeam-cli-windows-amd64.zip

# Comment line
c71d0310f3f63811d9a4691c624271c6151b90c372707158298f4c4e7c69f695  sendbeam-cli-darwin-arm64.tar.gz
`

	checksums, err := ParseChecksums(strings.NewReader(manifest))
	if err != nil {
		t.Fatalf("ParseChecksums failed: %v", err)
	}

	if len(checksums) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(checksums))
	}

	if checksums["sendbeam-cli-linux-amd64.tar.gz"] != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("mismatched hash for linux: %s", checksums["sendbeam-cli-linux-amd64.tar.gz"])
	}

	if checksums["sendbeam-cli-windows-amd64.zip"] != "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e" {
		t.Errorf("mismatched hash for windows: %s", checksums["sendbeam-cli-windows-amd64.zip"])
	}
}

func TestParseChecksumsInvalid(t *testing.T) {
	badManifest := `not-a-valid-sha256  sendbeam-cli-linux-amd64.tar.gz`
	_, err := ParseChecksums(strings.NewReader(badManifest))
	if err == nil {
		t.Error("expected error for invalid sha256 length, got nil")
	}
}

func TestTargetNames(t *testing.T) {
	if got := TargetCLIArchiveName("linux", "amd64"); got != "sendbeam-cli-linux-amd64.tar.gz" {
		t.Errorf("unexpected linux archive name %q", got)
	}
	if got := TargetCLIArchiveName("windows", "amd64"); got != "sendbeam-cli-windows-amd64.zip" {
		t.Errorf("unexpected windows archive name %q", got)
	}
	if got := TargetCLIBinaryName("linux"); got != "sendbeam" {
		t.Errorf("unexpected linux binary name %q", got)
	}
	if got := TargetCLIBinaryName("windows"); got != "sendbeam.exe" {
		t.Errorf("unexpected windows binary name %q", got)
	}
}
