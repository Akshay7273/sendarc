package transfer

import (
	"errors"
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
