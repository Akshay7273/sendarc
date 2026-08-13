package wire

import (
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"errors"
	"hash"
)

// IO ports for the transfer engine. The Sender/Receiver depend only on
// these primitives, so the same core runs over an in-memory pipe in tests and over the real
// pion DataChannel in the CLI. Concrete OS-backed implementations (file source, file sink)
// live in apps/cli; this file defines the contracts plus in-memory helpers. It is the Go twin
// of packages/protocol/src/transfer-ports.ts.

// FileMeta is the minimal file metadata carried in the manifest.
type FileMeta struct {
	Name         string
	Size         int64
	Mime         string
	LastModified int64
}

// FileSource is a streamable file. Stream yields the bytes in order and MUST be safe to call
// more than once: the sender reads once to compute the whole-file digest, then again to emit
// blocks. Each chunk is a view valid only for the duration of the callback — copy to retain.
type FileSource interface {
	Meta() FileMeta
	Stream(fn func(chunk []byte) error) error
}

// Sink is a destination for verified, in-order block writes (design §7). offset is the byte
// offset within the file. A non-nil error from any method aborts the transfer.
type Sink interface {
	Write(offset int64, bytes []byte) error
	Close() error
	Abort(reason string) error
}

// Destination owns every per-file Sink in one transfer so a terminal failure can discard the
// complete partial output rather than leaving already-verified files behind.
type Destination interface {
	Prepare(manifest Manifest) error
	Open(file FileEntry) (Sink, error)
	Close() error
	Abort(reason string) error
}

type singleSinkDestination struct {
	sink   Sink
	opened bool
}

// SingleSinkDestination adapts the original one-file Sink contract for compatibility.
func SingleSinkDestination(sink Sink) Destination { return &singleSinkDestination{sink: sink} }

func (d *singleSinkDestination) Prepare(manifest Manifest) error {
	if len(manifest.Files) != 1 {
		return errors.New("single sink cannot receive multiple files")
	}
	return nil
}

func (d *singleSinkDestination) Open(FileEntry) (Sink, error) {
	if d.opened {
		return nil, errors.New("single sink opened more than once")
	}
	d.opened = true
	return d.sink, nil
}

func (d *singleSinkDestination) Close() error { return nil }

func (d *singleSinkDestination) Abort(reason string) error { return d.sink.Abort(reason) }

// Digest is a streaming whole-file hasher producing a sha256sum-identical hex string. The
// sender computes it in a first pass so the file is never buffered whole; a fresh Digest is
// requested per transfer so implementations may be stateful. It is the Go twin of the TS
// Digest port.
type Digest interface {
	Update(bytes []byte)
	HexDigest() string
}

// DigestState is an optional Digest capability (V13-PR05): the digest's internal state can
// be serialized to bytes that a compatible Digest can restore, so a durable receiver can
// resume hashing from a checkpoint instead of re-hashing the persisted prefix. The bytes
// are opaque to the wire layer — they are meaningful only to the implementation that
// produced them and are version-tagged by the host when persisted.
type DigestState interface {
	// MarshalState returns a serialized snapshot of the digest's internal state covering
	// exactly the bytes fed so far. The digest remains usable afterwards.
	MarshalState() ([]byte, error)
}

// DigestStateSink is an optional Sink capability (V13-PR05): the sink can carry serialized
// digest state into its next durable checkpoint. The receiver calls SetDigestState with the
// state covering exactly the blocks the following Write/Close will checkpoint, so the
// storage layer can persist committedBlocks and the matching digest checkpoint atomically
// in one journal update. The state is an optimization only; a sink that rejects it (or a
// digest without state support) simply journals a checkpoint without digest state and the
// resume re-hashes.
type DigestStateSink interface {
	// SetDigestState remembers serialized digest state for the blocks the next Write or
	// Close commits. A nil state clears it (the next checkpoint carries no digest state).
	SetDigestState(state []byte) error
}

// sha256Digest is the default Digest, backed by the standard library.
type sha256Digest struct{ h hash.Hash }

// NewSHA256Digest returns a streaming SHA-256 Digest — the CLI's default whole-file hasher.
func NewSHA256Digest() Digest { return &sha256Digest{h: sha256.New()} }

func (d *sha256Digest) Update(b []byte) { d.h.Write(b) }

func (d *sha256Digest) HexDigest() string { return hex.EncodeToString(d.h.Sum(nil)) }

// MarshalState serializes the digest state through the standard library's documented
// encoding.BinaryMarshaler (a fixed 108-byte state for SHA-256). The digest remains usable
// afterwards, exactly like Sum.
func (d *sha256Digest) MarshalState() ([]byte, error) {
	if m, ok := d.h.(encoding.BinaryMarshaler); ok {
		return m.MarshalBinary()
	}
	return nil, errors.New("sha256 digest does not support state marshaling on this platform")
}

// RestoreSHA256Digest rebuilds a SHA-256 Digest from a serialized state produced by
// MarshalState, using the standard library's documented encoding.BinaryUnmarshaler, which
// fails closed on an invalid state identifier or size. State from another implementation
// (or another format) is rejected — never guessed.
func RestoreSHA256Digest(state []byte) (Digest, error) {
	h := sha256.New()
	if err := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
		return nil, err
	}
	return &sha256Digest{h: h}, nil
}

// FailReason is the machine-readable tag for a transfer failure, sent on the wire in a fail
// message. The set mirrors the TypeScript Fail['reason'] union exactly.
type FailReason string

// TransferState is the user-visible live state shared by sender and receiver controls.
type TransferState string

const (
	// TransferRunning means new data frames may be produced.
	TransferRunning TransferState = "running"
	// TransferPaused means new data frames are halted while buffered transport bytes drain.
	TransferPaused TransferState = "paused"
	// TransferCanceled means one peer terminated the transfer.
	TransferCanceled TransferState = "canceled"
)

// Transfer sizing defaults, mirroring packages/protocol/src/constants.ts. They are the
// negotiation starting point; a caps exchange may lower them within the header field widths.
const (
	// DefaultBlockBytes is the logical block size — the unit of ack, retry, and resume.
	DefaultBlockBytes = 1024 * 1024
	// DefaultFrameBytes is the default DataChannel/relay payload size.
	DefaultFrameBytes = 16 * 1024
	// DefaultInflightBlocks bounds how many unacknowledged blocks the sender retains,
	// capping receiver pressure and retry memory regardless of sink speed.
	DefaultInflightBlocks = 8
	// MaxManifestBlockBytes is the hard ceiling on any single block allocation the
	// receiver will make from a manifest. It exists purely to bound untrusted input:
	// honest senders use DefaultBlockBytes, but a malicious peer that completed the
	// handshake could otherwise claim a multi-gigabyte block and OOM the receiver
	// before a payload byte arrives.
	MaxManifestBlockBytes = 16 * 1024 * 1024
)

const (
	// FailDigestMismatch means the whole-file digest did not match the sender's Complete.
	FailDigestMismatch FailReason = "digest_mismatch"
	// FailIntegrity means a per-block hash did not match: a block was corrupted or forged.
	FailIntegrity FailReason = "integrity"
	// FailSinkError means the destination sink failed to write, close, or commit.
	FailSinkError FailReason = "sink_error"
	// FailCanceled means a peer canceled the transfer.
	FailCanceled FailReason = "canceled"
	// FailQuota means the destination ran out of space or quota.
	FailQuota FailReason = "quota"
	// FailRetryExhausted means a missing block remained unacknowledged after bounded retries.
	FailRetryExhausted FailReason = "retry_exhausted"
)

// TransferError carries one of the protocol's fail reasons. The reason is always prefixed
// onto the message so it survives in Error() (logs, matchers) even when a detail is given,
// matching the TypeScript TransferError.
type TransferError struct {
	Reason  FailReason
	Message string
}

// NewTransferError builds a TransferError; an empty message yields the bare reason.
func NewTransferError(reason FailReason, message string) *TransferError {
	return &TransferError{Reason: reason, Message: message}
}

func (e *TransferError) Error() string {
	if e.Message != "" {
		return string(e.Reason) + ": " + e.Message
	}
	return string(e.Reason)
}

// errWriteAfterClose is returned by MemorySink when written to after close or abort.
var errWriteAfterClose = errors.New("write after close/abort")

// MemorySink is an in-memory Sink that reassembles writes into one buffer. For tests and the
// loopback; it copies each write so callers may reuse their buffers.
type MemorySink struct {
	chunks  []memChunk
	closed  bool
	aborted bool
	reason  string
}

type memChunk struct {
	offset int64
	bytes  []byte
}

// Write records bytes at offset. It fails once the sink is closed or aborted.
func (s *MemorySink) Write(offset int64, bytes []byte) error {
	if s.closed || s.aborted {
		return errWriteAfterClose
	}
	s.chunks = append(s.chunks, memChunk{offset: offset, bytes: append([]byte(nil), bytes...)})
	return nil
}

// Close marks the sink complete.
func (s *MemorySink) Close() error {
	s.closed = true
	return nil
}

// Abort records a reason and stops accepting writes; an empty reason defaults to "aborted".
func (s *MemorySink) Abort(reason string) error {
	s.aborted = true
	if reason == "" {
		reason = "aborted"
	}
	s.reason = reason
	return nil
}

// IsClosed reports whether Close has been called.
func (s *MemorySink) IsClosed() bool { return s.closed }

// AbortReason returns the reason passed to Abort, or "" if the sink was not aborted.
func (s *MemorySink) AbortReason() string { return s.reason }

// Bytes returns the assembled buffer; its size is the highest written offset plus length.
func (s *MemorySink) Bytes() []byte {
	var size int64
	for _, c := range s.chunks {
		if end := c.offset + int64(len(c.bytes)); end > size {
			size = end
		}
	}
	out := make([]byte, size)
	for _, c := range s.chunks {
		copy(out[c.offset:], c.bytes)
	}
	return out
}

// defaultSourceChunk is the streaming granularity of BytesSource when none is given (64 KiB).
const defaultSourceChunk = 64 * 1024

// BytesSource builds an in-memory FileSource over data, yielding chunk-sized pieces. A chunk
// size of zero or less selects the 64 KiB default.
func BytesSource(data []byte, meta FileMeta, chunk int) FileSource {
	if chunk <= 0 {
		chunk = defaultSourceChunk
	}
	return &bytesSource{data: data, meta: meta, chunk: chunk}
}

type bytesSource struct {
	data  []byte
	meta  FileMeta
	chunk int
}

func (b *bytesSource) Meta() FileMeta { return b.meta }

func (b *bytesSource) Stream(fn func(chunk []byte) error) error {
	for i := 0; i < len(b.data); i += b.chunk {
		end := i + b.chunk
		if end > len(b.data) {
			end = len(b.data)
		}
		if err := fn(b.data[i:end]); err != nil {
			return err
		}
	}
	return nil
}
