package transfer

import (
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"

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
			Name:         filepath.Base(path),
			Size:         info.Size(),
			Mime:         mimeType,
			LastModified: info.ModTime().UnixMilli(),
		},
	}, nil
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
