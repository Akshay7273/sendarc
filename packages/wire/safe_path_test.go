package wire

import (
	"strings"
	"testing"
)

func TestNormalizeTransferPath(t *testing.T) {
	got, err := NormalizeTransferPath(`photos\2026\arc.jpg`)
	if err != nil || got != "photos/2026/arc.jpg" {
		t.Fatalf("NormalizeTransferPath = %q, %v", got, err)
	}
	bad := []string{
		"", "/etc/passwd", `\server\share`, `C:\secret.txt`, "../secret", "safe/../../secret",
		"./file", "folder//file", "folder/", "nul", "COM1.txt", "folder/aux.json",
		"trailing. ", "bad\x00name", "bad:name", strings.Repeat("é", 128),
		strings.Repeat("a/", MaxTransferPathDepth) + "a",
	}
	for _, path := range bad {
		if normalized, err := NormalizeTransferPath(path); err == nil {
			t.Errorf("NormalizeTransferPath(%q) = %q, want error", path, normalized)
		}
	}
}

func TestValidateManifest(t *testing.T) {
	entry := func(idx int, name string, size int64) FileEntry {
		blocks := int((size + 7) / 8)
		return FileEntry{Idx: idx, Name: name, Size: size, BlockSize: 8, Blocks: blocks}
	}
	valid, err := ValidateManifest(*NewManifest([]FileEntry{
		entry(0, `a\b.bin`, 9), entry(1, "empty", 0),
	}, 9))
	if err != nil || valid.Files[0].Name != "a/b.bin" {
		t.Fatalf("ValidateManifest = %#v, %v", valid, err)
	}
	bad := []Manifest{
		*NewManifest(nil, 0),
		*NewManifest([]FileEntry{entry(1, "a", 9)}, 9),
		*NewManifest([]FileEntry{entry(0, "a", 9), entry(1, "A", 9)}, 18),
		*NewManifest([]FileEntry{entry(0, "../a", 9)}, 9),
		*NewManifest([]FileEntry{func() FileEntry { f := entry(0, "a", 9); f.Blocks = 99; return f }()}, 9),
		*NewManifest([]FileEntry{entry(0, "a", 9)}, 8),
		*NewManifest([]FileEntry{func() FileEntry { f := entry(0, "big.bin", 1<<30); f.BlockSize = 1 << 30; f.Blocks = 1; return f }()}, 1<<30),
	}
	for i, manifest := range bad {
		if _, err := ValidateManifest(manifest); err == nil {
			t.Errorf("bad manifest %d accepted", i)
		}
	}
}

func FuzzNormalizeTransferPath(f *testing.F) {
	for _, seed := range []string{"safe/file.txt", "../escape", `C:\escape`, "nul", "猫/写真.jpg"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		path, err := NormalizeTransferPath(input)
		if err != nil {
			return
		}
		if path == "" || strings.Contains(path, `\`) || strings.HasPrefix(path, "/") {
			t.Fatalf("unsafe normalized path %q from %q", path, input)
		}
		for _, part := range strings.Split(path, "/") {
			if part == "" || part == "." || part == ".." {
				t.Fatalf("unsafe segment in %q from %q", path, input)
			}
		}
	})
}
