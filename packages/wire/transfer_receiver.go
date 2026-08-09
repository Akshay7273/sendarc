package wire

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

// Receiver is the receiving half of the transfer engine (design §5, §6). Frames arrive over an
// ordered, reliable channel, so blocks assemble one at a time, in order. For each block the
// receiver verifies its SHA-256 (from block_hash) BEFORE writing to the sink, feeds the verified
// bytes into the whole-file streaming digest, then signals block_recv (the in-flight window). On
// complete it compares the recomputed digest to the sender's and replies done, or
// fail{digest_mismatch}. A GCM open failure or any hash mismatch yields fail{integrity} and an
// abort — never a silent retry (design §5.5). It is the Go twin of
// packages/protocol/src/transfer-receiver.ts.
//
// Handle is called from the transport read loop and MUST be called serially — the ordered
// DataChannel satisfies this, and each frame consumes the next receive counter. Wait blocks a
// separate goroutine until the transfer settles.

// ReceiveResult is the outcome of a successful receive: the manifest entry and the verified
// whole-file digest (hex).
type ReceiveResult struct {
	File   FileEntry
	Digest string
}

// ReceiverOptions configures a Receiver.
type ReceiverOptions struct {
	Send             func(frame []byte) error
	SendDir          DirectionalKey
	RecvDir          DirectionalKey
	SendCounterStart uint64
	RecvCounterStart uint64
	CreateDigest     func() Digest // nil selects a streaming SHA-256 digest
	Sink             Sink
	OnProgress       func(receivedBytes int64)
	// OnManifest is called once when the manifest decodes, before any block is written — it lets
	// the host open a destination named after the file without the engine knowing about it. A
	// non-nil error aborts the transfer.
	OnManifest func(file FileEntry) error
}

// Receiver drives one file receive. Construct it with NewReceiver.
type Receiver struct {
	o      ReceiverOptions
	digest Digest

	// Counters and assembly state are touched only by Handle's (serial) goroutine.
	sendCounter uint64
	recvCounter uint64
	file        *FileEntry
	curBlock    int
	blockBuf    []byte
	blockLen    int
	received    int

	mu      sync.Mutex
	done    chan struct{}
	settled bool
	result  ReceiveResult
	err     error
}

// NewReceiver builds a Receiver, defaulting to a streaming SHA-256 digest when none is given.
func NewReceiver(opts ReceiverOptions) *Receiver {
	if opts.CreateDigest == nil {
		opts.CreateDigest = NewSHA256Digest
	}
	return &Receiver{
		o:           opts,
		digest:      opts.CreateDigest(),
		sendCounter: opts.SendCounterStart,
		recvCounter: opts.RecvCounterStart,
		done:        make(chan struct{}),
	}
}

// Wait blocks until the transfer settles, returning the result on done or the error on fail.
// Canceling ctx aborts the receive with FailCanceled in bounded time, so a dropped peer never
// parks Wait forever.
func (r *Receiver) Wait(ctx context.Context) (ReceiveResult, error) {
	select {
	case <-r.done:
	case <-ctx.Done():
		// abortWith is idempotent and closes r.done; if the receive already settled it is a
		// no-op and the <-r.done below returns immediately with the real result.
		r.abortWith(NewTransferError(FailCanceled, ctx.Err().Error()))
		<-r.done
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.result, r.err
}

// Handle feeds one inbound frame from the sender (manifest / block_data / block_hash / complete).
// Any error aborts the transfer with the appropriate fail reason (integrity unless the error
// already carries one).
func (r *Receiver) Handle(frame []byte) {
	if err := r.process(frame); err != nil {
		var te *TransferError
		if !errors.As(err, &te) {
			te = NewTransferError(FailIntegrity, err.Error())
		}
		r.abortWith(te)
	}
}

// --- internal ---------------------------------------------------------------

func (r *Receiver) process(frame []byte) error {
	if r.isSettled() {
		return nil
	}
	ctr := r.recvCounter
	r.recvCounter++
	opened, err := Open(r.o.RecvDir, ctr, frame) // open failure → integrity abort
	if err != nil {
		return NewTransferError(FailIntegrity, err.Error())
	}
	switch opened.Header.Type {
	case FrameManifest:
		return r.applyManifest(opened.Plaintext)
	case FrameBlockData:
		return r.onBlockData(opened.Header.BlockIdx, opened.Header.FrameOff, opened.Plaintext)
	case FrameBlockHash:
		return r.onBlockHash(opened.Plaintext)
	case FrameComplete:
		return r.onComplete(opened.Plaintext)
	default:
		return NewTransferError(FailIntegrity,
			fmt.Sprintf("unexpected receiver-inbound type %d", opened.Header.Type))
	}
}

func (r *Receiver) applyManifest(payload []byte) error {
	msg, err := DecodeControl(payload)
	if err != nil {
		return NewTransferError(FailIntegrity, err.Error())
	}
	m, ok := msg.(*Manifest)
	if !ok {
		return NewTransferError(FailIntegrity, "expected manifest")
	}
	if len(m.Files) == 0 {
		return NewTransferError(FailIntegrity, "manifest has no files")
	}
	f := m.Files[0]
	r.file = &f
	if r.o.OnManifest != nil {
		return r.o.OnManifest(f)
	}
	return nil
}

func (r *Receiver) onBlockData(blockIdx uint32, frameOff uint32, payload []byte) error {
	if r.file == nil {
		return NewTransferError(FailIntegrity, "block_data before manifest")
	}
	if int(blockIdx) != r.curBlock {
		return NewTransferError(FailIntegrity, fmt.Sprintf("out-of-order block %d", blockIdx))
	}
	if frameOff == 0 {
		// The final block is short: cap its buffer at the file's remaining bytes.
		r.blockLen = r.file.BlockSize
		if rem := r.file.Size - int64(blockIdx)*int64(r.file.BlockSize); int64(r.blockLen) > rem {
			r.blockLen = int(rem)
		}
		r.blockBuf = make([]byte, r.blockLen)
		r.received = 0
	}
	copy(r.blockBuf[frameOff:], payload)
	r.received += len(payload)
	return nil
}

func (r *Receiver) onBlockHash(payload []byte) error {
	if r.file == nil || r.blockBuf == nil {
		return NewTransferError(FailIntegrity, "block_hash without a block")
	}
	msg, err := DecodeControl(payload)
	if err != nil {
		return NewTransferError(FailIntegrity, err.Error())
	}
	bh, ok := msg.(*BlockHash)
	if !ok {
		return NewTransferError(FailIntegrity, "expected block_hash")
	}
	if r.received != r.blockLen {
		return NewTransferError(FailIntegrity, "short block")
	}
	sum := sha256.Sum256(r.blockBuf)
	if hex.EncodeToString(sum[:]) != bh.SHA256 {
		return NewTransferError(FailIntegrity, fmt.Sprintf("block %d hash mismatch", bh.BlockIdx))
	}

	// Verified: write, fold into the whole-file digest, then open the window one more block. A
	// sink error propagates as-is, so a sink returning a TransferError keeps its reason.
	offset := int64(r.curBlock) * int64(r.file.BlockSize)
	if err := r.o.Sink.Write(offset, r.blockBuf); err != nil {
		return err
	}
	r.digest.Update(r.blockBuf)
	if r.o.OnProgress != nil {
		r.o.OnProgress(offset + int64(r.blockLen))
	}
	if err := r.sendControl(NewBlockRecv(0, r.curBlock)); err != nil {
		return err
	}
	r.curBlock++
	r.blockBuf = nil
	return nil
}

func (r *Receiver) onComplete(payload []byte) error {
	if r.file == nil {
		return NewTransferError(FailIntegrity, "complete before manifest")
	}
	msg, err := DecodeControl(payload)
	if err != nil {
		return NewTransferError(FailIntegrity, err.Error())
	}
	c, ok := msg.(*Complete)
	if !ok {
		return NewTransferError(FailIntegrity, "expected complete")
	}
	got := r.digest.HexDigest()
	if got != c.FileDigest {
		return NewTransferError(FailDigestMismatch, "whole-file digest mismatch")
	}
	if err := r.o.Sink.Close(); err != nil {
		return err
	}
	if err := r.sendControl(NewDone()); err != nil {
		return err
	}
	r.settle(ReceiveResult{File: *r.file, Digest: got})
	return nil
}

// abortWith settles the transfer as failed and, best-effort, tells the peer and the sink. Only
// the first abort (or a prior settle) takes effect.
func (r *Receiver) abortWith(err *TransferError) {
	r.mu.Lock()
	if r.settled {
		r.mu.Unlock()
		return
	}
	r.settled = true
	r.err = err
	r.mu.Unlock()

	_ = r.sendControl(NewFail(err.Reason)) // best-effort — the channel may already be gone
	_ = r.o.Sink.Abort(string(err.Reason)) // best-effort
	close(r.done)
}

// settle records a successful finish; only the first settle (or a prior abort) takes effect.
func (r *Receiver) settle(res ReceiveResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.settled {
		return
	}
	r.settled = true
	r.result = res
	close(r.done)
}

func (r *Receiver) isSettled() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.settled
}

// sendControl seals and sends a control message under the next send counter.
func (r *Receiver) sendControl(msg ControlMsg) error {
	payload, err := EncodeControl(msg)
	if err != nil {
		return err
	}
	frame, err := Seal(r.o.SendDir, r.sendCounter, FrameHeaderInput{
		Version: FrameVersion, Type: msg.FrameType(),
	}, payload)
	if err != nil {
		return err
	}
	r.sendCounter++
	return r.o.Send(frame)
}
