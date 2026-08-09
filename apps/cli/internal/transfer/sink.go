package transfer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/sendarc/wire"
)

// errSinkClosed is returned when a block is written after the sink has been closed or aborted.
// The engine never does this, so it only guards against a misuse or a late concurrent abort.
var errSinkClosed = errors.New("transfer: write after sink closed")

// OSFileSink is a [wire.Sink] that writes verified, in-order blocks to a file on disk. The
// receiver hands it a block only after that block's SHA-256 checks out, so a committed file is
// exactly the sender's bytes; a failed transfer aborts and removes the partial file rather than
// leave truncated output behind. It is the CLI counterpart of the browser sink.
type OSFileSink struct {
	path string

	mu     sync.Mutex
	f      *os.File
	closed bool
}

// NewOSFileSink creates (truncating) the destination file named after the manifest inside dir.
// name is reduced to its base component so a hostile manifest name cannot escape dir (see
// [sanitizeName]); the resolved path is available via Path.
func NewOSFileSink(dir, name string) (*OSFileSink, error) {
	path := filepath.Join(dir, sanitizeName(name))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, err
	}
	return &OSFileSink{path: path, f: f}, nil
}

// OSDestination owns a safe relative file tree for one transfer and removes the complete tree of
// files it created if any later file fails. Existing files are never overwritten.
type OSDestination struct {
	mu     sync.Mutex
	root   string
	sinks  []*OSFileSink
	files  []string
	dirs   []string
	paths  map[int]string
	closed bool
}

// NewOSDestination prepares a filesystem-rooted multi-file destination.
func NewOSDestination(root string) (*OSDestination, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		return nil, err
	}
	return &OSDestination{root: abs, paths: make(map[int]string)}, nil
}

// Prepare validates the already-canonical manifest before any output is created.
func (d *OSDestination) Prepare(manifest wire.Manifest) error {
	_, err := wire.ValidateManifest(manifest)
	return err
}

// Open creates one manifest path without following symlinked child directories.
func (d *OSDestination) Open(file wire.FileEntry) (wire.Sink, error) {
	name, err := wire.NormalizeTransferPath(file.Name)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, errSinkClosed
	}
	parts := strings.Split(name, "/")
	parent := d.root
	for _, part := range parts[:len(parts)-1] {
		parent = filepath.Join(parent, part)
		info, statErr := os.Lstat(parent)
		if errors.Is(statErr, os.ErrNotExist) {
			if err := os.Mkdir(parent, 0o755); err != nil {
				return nil, err
			}
			d.dirs = append(d.dirs, parent)
			continue
		}
		if statErr != nil {
			return nil, statErr
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fmt.Errorf("transfer: destination component is not a safe directory: %s", parent)
		}
	}
	path := filepath.Join(parent, parts[len(parts)-1])
	rel, err := filepath.Rel(d.root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, errors.New("transfer: destination path escaped its root")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	sink := &OSFileSink{path: path, f: f}
	d.sinks = append(d.sinks, sink)
	d.files = append(d.files, path)
	d.paths[file.Idx] = path
	return sink, nil
}

// Close commits the destination. Individual files have already been flushed and closed.
func (d *OSDestination) Close() error {
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()
	return nil
}

// Abort closes active files and removes every file and empty directory created by this transfer.
func (d *OSDestination) Abort(reason string) error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	sinks := append([]*OSFileSink(nil), d.sinks...)
	files := append([]string(nil), d.files...)
	dirs := append([]string(nil), d.dirs...)
	d.mu.Unlock()
	for _, sink := range sinks {
		_ = sink.Abort(reason)
	}
	for _, path := range files {
		_ = os.Remove(path)
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		_ = os.Remove(dirs[i])
	}
	return nil
}

// Path returns the output path assigned to one manifest index.
func (d *OSDestination) Path(fileIdx int) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.paths[fileIdx]
}

// Path is the destination path the sink writes to.
func (s *OSFileSink) Path() string { return s.path }

// Write places bytes at offset. Blocks arrive in order, but WriteAt keeps the sink correct for
// whatever offset the engine chooses.
func (s *OSFileSink) Write(offset int64, bytes []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errSinkClosed
	}
	_, err := s.f.WriteAt(bytes, offset)
	return err
}

// Close flushes and closes the file, committing the received bytes. It is idempotent.
func (s *OSFileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.f.Close()
}

// Abort discards a partial transfer: it closes the descriptor and removes the file so no
// truncated output survives. It is idempotent and best-effort on the removal. The reason is
// unused here — the sink simply discards; the peer already learned it via fail.
func (s *OSFileSink) Abort(_ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	_ = s.f.Close()
	return os.Remove(s.path)
}

// deferredSink lets the receiver be constructed before its destination file exists: the real
// sink is attached from OnManifest, once the file name is known. It mirrors the browser
// DeferredSink — a write before attach is a programming error, since the engine always delivers
// the manifest before the first block.
type deferredSink struct {
	mu    sync.Mutex
	inner wire.Sink
}

func (d *deferredSink) attach(inner wire.Sink) {
	d.mu.Lock()
	d.inner = inner
	d.mu.Unlock()
}

func (d *deferredSink) get() wire.Sink {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.inner
}

func (d *deferredSink) Write(offset int64, bytes []byte) error {
	inner := d.get()
	if inner == nil {
		return wire.NewTransferError(wire.FailSinkError, "sink written before manifest")
	}
	return inner.Write(offset, bytes)
}

func (d *deferredSink) Close() error {
	inner := d.get()
	if inner == nil {
		return nil
	}
	return inner.Close()
}

func (d *deferredSink) Abort(reason string) error {
	inner := d.get()
	if inner == nil {
		return nil
	}
	return inner.Abort(reason)
}

// sanitizeName reduces a manifest-supplied file name to a safe base name for the local
// filesystem: it strips any directory component (either separator style, so a name authored on
// Windows cannot smuggle a path through a backslash on a POSIX host) and rejects the empty and
// dot names, falling back to "download". It matches the browser sink's sanitize().
func sanitizeName(name string) string {
	name = strings.TrimSpace(name)
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." {
		return "download"
	}
	return name
}
