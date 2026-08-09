package transfer

import (
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"os"
	"path/filepath"
	"sort"

	"github.com/sendarc/wire"
)

// sourceChunkBytes is the streaming granularity when reading a file from disk. It mirrors the
// browser blobFileSource's 64 KiB slice; the sender re-chunks into frames regardless, so this
// only bounds how much is read per syscall.
const sourceChunkBytes = 64 * 1024

// OSFileSource is a [wire.FileSource] backed by a regular file on disk. Stream opens the file
// fresh on each call, so the sender's two passes — the whole-file digest, then the block
// stream — each read from the start, satisfying the "safe to call more than once" contract the
// engine relies on. It is the CLI counterpart of apps/web/src/lib/transfer/file-source.ts.
type OSFileSource struct {
	path string
	meta wire.FileMeta
}

// NewOSFileSource stats path and prepares a repeatable streaming source. It errors if the path
// is missing or is a directory.
func NewOSFileSource(path string) (*OSFileSource, error) {
	return newOSFileSource(path, filepath.Base(path))
}

func newOSFileSource(path, transferName string) (*OSFileSource, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("transfer: %s is a directory, not a file", path)
	}
	mimeType := mime.TypeByExtension(filepath.Ext(path))
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	return &OSFileSource{
		path: path,
		meta: wire.FileMeta{
			Name:         filepath.ToSlash(transferName),
			Size:         info.Size(),
			Mime:         mimeType,
			LastModified: info.ModTime().UnixMilli(),
		},
	}, nil
}

// NewOSFileSources expands regular files and folders into a deterministic ordered transfer set.
// Folder entries retain the selected folder's base name as their safe relative-path prefix.
func NewOSFileSources(paths []string) ([]wire.FileSource, int64, error) {
	if len(paths) == 0 {
		return nil, 0, errors.New("transfer: at least one file or folder is required")
	}
	type candidate struct{ path, name string }
	var candidates []candidate
	for _, input := range paths {
		info, err := os.Lstat(input)
		if err != nil {
			return nil, 0, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, 0, fmt.Errorf("transfer: symbolic links are not supported: %s", input)
		}
		if !info.IsDir() {
			if !info.Mode().IsRegular() {
				return nil, 0, fmt.Errorf("transfer: %s is not a regular file", input)
			}
			candidates = append(candidates, candidate{input, filepath.Base(input)})
			continue
		}
		root := filepath.Clean(input)
		prefix := filepath.Base(root)
		err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if path == root {
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("transfer: symbolic links are not supported: %s", path)
			}
			if entry.IsDir() {
				return nil
			}
			if !entry.Type().IsRegular() {
				return fmt.Errorf("transfer: %s is not a regular file", path)
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			candidates = append(candidates, candidate{path, filepath.Join(prefix, rel)})
			return nil
		})
		if err != nil {
			return nil, 0, err
		}
	}
	if len(candidates) == 0 {
		return nil, 0, errors.New("transfer: selected folders contain no regular files")
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].name < candidates[j].name })
	sources := make([]wire.FileSource, len(candidates))
	var total int64
	for i, candidate := range candidates {
		source, err := newOSFileSource(candidate.path, candidate.name)
		if err != nil {
			return nil, 0, err
		}
		if _, err := wire.NormalizeTransferPath(source.meta.Name); err != nil {
			return nil, 0, fmt.Errorf("transfer: unsafe source path %q: %w", source.meta.Name, err)
		}
		if source.meta.Size > math.MaxInt64-total {
			return nil, 0, errors.New("transfer: total size overflow")
		}
		total += source.meta.Size
		sources[i] = source
	}
	return sources, total, nil
}

// Meta returns the file's manifest metadata, captured at construction.
func (s *OSFileSource) Meta() wire.FileMeta { return s.meta }

// Stream reads the file from the beginning, handing successive chunks to fn. Each chunk is only
// valid for the duration of the call — the engine copies what it retains. Opening per call keeps
// Stream repeatable and avoids holding a descriptor open between the sender's two passes.
func (s *OSFileSource) Stream(fn func(chunk []byte) error) error {
	f, err := os.Open(s.path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, sourceChunkBytes)
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			if err := fn(buf[:n]); err != nil {
				return err
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}
