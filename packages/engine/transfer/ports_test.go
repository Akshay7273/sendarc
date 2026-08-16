package transfer

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOSFileSourceMetaAndStream(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "greeting.txt")
	// Larger than sourceChunkBytes so Stream must loop and reassemble across reads.
	content := bytes.Repeat([]byte("sendbeam-"), 20000) // 160000 bytes
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	src, err := NewOSFileSource(path)
	if err != nil {
		t.Fatalf("NewOSFileSource: %v", err)
	}

	meta := src.Meta()
	if meta.Name != "greeting.txt" {
		t.Errorf("Name = %q, want greeting.txt", meta.Name)
	}
	if meta.Size != int64(len(content)) {
		t.Errorf("Size = %d, want %d", meta.Size, len(content))
	}
	if meta.Mime == "" {
		t.Error("Mime is empty; want a resolved or fallback type")
	}
	if meta.LastModified <= 0 {
		t.Errorf("LastModified = %d, want a positive epoch-millis value", meta.LastModified)
	}

	// Stream must be repeatable: the sender reads once for the whole-file digest and again
	// for the block stream, both from the start.
	for pass := 1; pass <= 2; pass++ {
		var got bytes.Buffer
		if err := src.Stream(func(chunk []byte) error {
			got.Write(chunk)
			return nil
		}); err != nil {
			t.Fatalf("pass %d Stream: %v", pass, err)
		}
		if !bytes.Equal(got.Bytes(), content) {
			t.Fatalf("pass %d streamed %d bytes, want %d identical", pass, got.Len(), len(content))
		}
	}
}

func TestOSFileSourceStreamPropagatesError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.bin")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0xab}, 200000), 0o644); err != nil {
		t.Fatal(err)
	}
	src, err := NewOSFileSource(path)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("consumer stop")
	err = src.Stream(func([]byte) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("Stream error = %v, want the consumer's error propagated", err)
	}
}

func TestNewOSFileSourceRejectsMissingAndDir(t *testing.T) {
	if _, err := NewOSFileSource(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("expected an error for a missing file")
	}
	if _, err := NewOSFileSource(t.TempDir()); err == nil {
		t.Error("expected an error for a directory")
	}
}

func TestNewOSFileSourcesExpandsFolderDeterministically(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "album")
	if err := os.MkdirAll(filepath.Join(root, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"z.txt": "z", "nested/a.txt": "alpha", "empty": ""} {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sources, total, err := NewOSFileSources([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	wantNames := []string{"album/empty", "album/nested/a.txt", "album/z.txt"}
	if len(sources) != len(wantNames) || total != 6 {
		t.Fatalf("sources=%d total=%d", len(sources), total)
	}
	for i, source := range sources {
		if source.Meta().Name != wantNames[i] {
			t.Errorf("source %d name=%q want=%q", i, source.Meta().Name, wantNames[i])
		}
	}
}

func TestNewOSFileSourcesRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, _, err := NewOSFileSources([]string{link}); err == nil {
		t.Fatal("symlink source accepted")
	}
}
