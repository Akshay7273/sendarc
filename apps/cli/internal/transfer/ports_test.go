package transfer

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sendarc/wire"
)

func TestOSFileSourceMetaAndStream(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "greeting.txt")
	// Larger than sourceChunkBytes so Stream must loop and reassemble across reads.
	content := bytes.Repeat([]byte("sendarc-"), 20000) // 160000 bytes
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

func TestOSFileSinkWritesAndCommits(t *testing.T) {
	dir := t.TempDir()
	sink, err := NewOSFileSink(dir, "out.bin")
	if err != nil {
		t.Fatalf("NewOSFileSink: %v", err)
	}
	if want := filepath.Join(dir, "out.bin"); sink.Path() != want {
		t.Errorf("Path = %q, want %q", sink.Path(), want)
	}
	// WriteAt semantics: the second block lands at its offset regardless of order.
	if err := sink.Write(5, []byte("world")); err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(0, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Errorf("second Close = %v, want nil (idempotent)", err)
	}
	got, err := os.ReadFile(sink.Path())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "helloworld" {
		t.Errorf("file = %q, want helloworld", got)
	}
}

func TestOSFileSinkWriteAfterCloseFails(t *testing.T) {
	sink, err := NewOSFileSink(t.TempDir(), "out.bin")
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(0, []byte("late")); !errors.Is(err, errSinkClosed) {
		t.Fatalf("Write after Close = %v, want errSinkClosed", err)
	}
}

func TestOSFileSinkAbortRemovesPartial(t *testing.T) {
	sink, err := NewOSFileSink(t.TempDir(), "out.bin")
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(0, []byte("partial")); err != nil {
		t.Fatal(err)
	}
	if err := sink.Abort("digest mismatch"); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if _, err := os.Stat(sink.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("partial file still present after Abort: stat err = %v", err)
	}
	if err := sink.Abort("again"); err != nil {
		t.Errorf("second Abort = %v, want nil (idempotent)", err)
	}
}

func TestSanitizeName(t *testing.T) {
	cases := map[string]string{
		"report.pdf":       "report.pdf",
		"a/b/c.txt":        "c.txt",
		`dir\sub\win.dat`:  "win.dat",
		"../../etc/passwd": "passwd",
		"  spaced.bin  ":   "spaced.bin",
		"":                 "download",
		".":                "download",
		"..":               "download",
		"/":                "download",
		`trailing\`:        "download",
	}
	for in, want := range cases {
		if got := sanitizeName(in); got != want {
			t.Errorf("sanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewOSFileSinkContainsTraversalName(t *testing.T) {
	dir := t.TempDir()
	sink, err := NewOSFileSink(dir, "../escape.txt")
	if err != nil {
		t.Fatalf("NewOSFileSink: %v", err)
	}
	defer func() { _ = sink.Abort("cleanup") }()
	if got, want := sink.Path(), filepath.Join(dir, "escape.txt"); got != want {
		t.Errorf("traversal name escaped dir: Path = %q, want %q", got, want)
	}
}

func TestDeferredSinkBeforeAttach(t *testing.T) {
	d := &deferredSink{}

	// A write before the manifest is a protocol error surfaced as a sink failure.
	err := d.Write(0, []byte("early"))
	var te *wire.TransferError
	if !errors.As(err, &te) || te.Reason != wire.FailSinkError {
		t.Fatalf("Write before attach = %v, want a FailSinkError TransferError", err)
	}
	// Close and Abort are no-ops until a real sink is attached.
	if err := d.Close(); err != nil {
		t.Errorf("Close before attach = %v, want nil", err)
	}
	if err := d.Abort("x"); err != nil {
		t.Errorf("Abort before attach = %v, want nil", err)
	}
}

func TestDeferredSinkDelegatesAfterAttach(t *testing.T) {
	d := &deferredSink{}
	inner, err := NewOSFileSink(t.TempDir(), "out.bin")
	if err != nil {
		t.Fatal(err)
	}
	d.attach(inner)
	if err := d.Write(0, []byte("data")); err != nil {
		t.Fatalf("Write after attach: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(inner.Path())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "data" {
		t.Errorf("delegated file = %q, want data", got)
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

func destinationManifest(names ...string) wire.Manifest {
	files := make([]wire.FileEntry, len(names))
	for i, name := range names {
		files[i] = wire.FileEntry{Idx: i, Name: name, Size: 1, BlockSize: 1, Blocks: 1}
	}
	return *wire.NewManifest(files, int64(len(files)))
}

func TestOSDestinationWritesNestedTreeWithoutOverwrite(t *testing.T) {
	root := t.TempDir()
	destination, err := NewOSDestination(root)
	if err != nil {
		t.Fatal(err)
	}
	manifest := destinationManifest("folder/a.txt", "b.txt")
	if err := destination.Prepare(manifest); err != nil {
		t.Fatal(err)
	}
	for _, file := range manifest.Files {
		sink, openErr := destination.Open(file)
		if openErr != nil {
			t.Fatal(openErr)
		}
		if err := sink.Write(0, []byte{byte('a' + file.Idx)}); err != nil {
			t.Fatal(err)
		}
		if err := sink.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := destination.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(root, "folder", "a.txt")); err != nil || string(got) != "a" {
		t.Fatalf("nested file=%q err=%v", got, err)
	}

	existing := filepath.Join(root, "existing.txt")
	if err := os.WriteFile(existing, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	second, err := NewOSDestination(root)
	if err != nil {
		t.Fatal(err)
	}
	file := destinationManifest("existing.txt").Files[0]
	if _, err := second.Open(file); err == nil {
		t.Fatal("existing destination was overwritten")
	}
	got, _ := os.ReadFile(existing)
	if string(got) != "keep" {
		t.Fatalf("existing content changed to %q", got)
	}
}

func TestOSDestinationAbortRemovesCompletedTreeAndRejectsSymlinkComponent(t *testing.T) {
	root := t.TempDir()
	destination, err := NewOSDestination(root)
	if err != nil {
		t.Fatal(err)
	}
	file := destinationManifest("folder/a.txt").Files[0]
	sink, err := destination.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(0, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if err := destination.Abort("later file failed"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "folder", "a.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed partial output survived abort: %v", err)
	}

	outside := t.TempDir()
	link := filepath.Join(root, "linked")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	third, err := NewOSDestination(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := third.Open(destinationManifest("linked/escape.txt").Files[0]); err == nil {
		t.Fatal("symlink destination component accepted")
	}
}
