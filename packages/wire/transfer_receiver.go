package wire

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Receiver verifies and commits blocks before acknowledging them. A valid block that arrives
// ahead of the next required index exposes a gap: it is not committed, and the missing block is
// requested. Duplicate retransmissions are reverified and acknowledged without a second write.

// ReceiveResult is the successful manifest entry and canonical whole-file digest.
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
	CreateDigest     func() Digest
	Sink             Sink
	// OnProgress reports bytes only after verify-and-sink.
	OnProgress    func(acknowledgedBytes int64)
	OnStateChange func(TransferState)
	OnManifest    func(file FileEntry) error
}

// Receiver drives one file receive. Handle calls must remain ordered.
type Receiver struct {
	o      ReceiverOptions
	digest Digest

	sendMu      sync.Mutex
	sendCounter uint64

	// Assembly state belongs to the serial Handle path.
	recvCounter     uint64
	file            *FileEntry
	nextBlock       int
	assembling      int
	blockBuf        []byte
	blockReceived   int
	seenAhead       map[int]bool
	nackOutstanding int

	mu      sync.Mutex
	done    chan struct{}
	settled bool
	paused  bool
	result  ReceiveResult
	err     error
}

// NewReceiver builds a Receiver.
func NewReceiver(opts ReceiverOptions) *Receiver {
	if opts.CreateDigest == nil {
		opts.CreateDigest = NewSHA256Digest
	}
	return &Receiver{
		o:               opts,
		digest:          opts.CreateDigest(),
		sendCounter:     opts.SendCounterStart,
		recvCounter:     opts.RecvCounterStart,
		assembling:      -1,
		seenAhead:       make(map[int]bool),
		nackOutstanding: -1,
		done:            make(chan struct{}),
	}
}

// Wait blocks until completion or cancellation.
func (r *Receiver) Wait(ctx context.Context) (ReceiveResult, error) {
	select {
	case <-r.done:
	case <-ctx.Done():
		r.cancelFromContext(ctx.Err())
		<-r.done
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.result, r.err
}

// Handle consumes one encrypted sender frame. Any malformed or unauthenticated frame aborts.
func (r *Receiver) Handle(frame []byte) {
	if err := r.process(frame); err != nil {
		var te *TransferError
		if !errors.As(err, &te) {
			te = NewTransferError(FailIntegrity, err.Error())
		}
		r.abortWith(te, true)
	}
}

// Pause asks the sender to stop producing data frames.
func (r *Receiver) Pause() error {
	if !r.setPaused(true) {
		return nil
	}
	return r.sendControl(NewControl(ControlPause))
}

// Resume asks the sender to continue.
func (r *Receiver) Resume() error {
	if !r.setPaused(false) {
		return nil
	}
	return r.sendControl(NewControl(ControlResume))
}

// Cancel notifies the sender and terminates the receive.
func (r *Receiver) Cancel(reason string) error {
	r.mu.Lock()
	settled := r.settled
	r.mu.Unlock()
	if settled {
		return nil
	}
	if r.o.OnStateChange != nil {
		r.o.OnStateChange(TransferCanceled)
	}
	err := r.sendControl(NewControl(ControlCancel))
	r.abortWith(NewTransferError(FailCanceled, reason), false)
	return err
}

func (r *Receiver) process(frame []byte) error {
	if r.isSettled() {
		return nil
	}
	ctr := r.recvCounter
	r.recvCounter++
	opened, err := Open(r.o.RecvDir, ctr, frame)
	if err != nil {
		return NewTransferError(FailIntegrity, err.Error())
	}
	switch opened.Header.Type {
	case FrameManifest:
		return r.applyManifest(opened.Plaintext)
	case FrameBlockData:
		return r.onBlockData(opened.Header.FileIdx, opened.Header.BlockIdx,
			opened.Header.FrameOff, opened.Plaintext)
	case FrameBlockHash:
		return r.onBlockHash(opened.Plaintext)
	case FrameControl:
		return r.onControl(opened.Plaintext)
	case FrameComplete:
		return r.onComplete(opened.Plaintext)
	case FrameFail:
		return r.onPeerFail(opened.Plaintext)
	default:
		return NewTransferError(FailIntegrity,
			fmt.Sprintf("unexpected receiver-inbound type %d", opened.Header.Type))
	}
}

func (r *Receiver) applyManifest(payload []byte) error {
	if r.file != nil {
		return NewTransferError(FailIntegrity, "duplicate manifest")
	}
	msg, err := DecodeControl(payload)
	if err != nil {
		return NewTransferError(FailIntegrity, err.Error())
	}
	m, ok := msg.(*Manifest)
	if !ok {
		return NewTransferError(FailIntegrity, "expected manifest")
	}
	if len(m.Files) != 1 {
		return NewTransferError(FailIntegrity, "single-file manifest required")
	}
	f := m.Files[0]
	wantBlocks := 0
	if f.Size > 0 && f.BlockSize > 0 {
		wantBlocks = int((f.Size + int64(f.BlockSize) - 1) / int64(f.BlockSize))
	}
	if f.Idx != 0 || f.Size < 0 || f.BlockSize <= 0 || f.Blocks != wantBlocks {
		return NewTransferError(FailIntegrity, "invalid manifest geometry")
	}
	r.file = &f
	if r.o.OnManifest != nil {
		if err := r.o.OnManifest(f); err != nil {
			return asTransferError(err, FailSinkError)
		}
	}
	return nil
}

func (r *Receiver) onBlockData(fileIdx uint16, blockIdx uint32, frameOff uint32, payload []byte) error {
	if r.file == nil {
		return NewTransferError(FailIntegrity, "block_data before manifest")
	}
	idx := int(blockIdx)
	if fileIdx != 0 || idx < 0 || idx >= r.file.Blocks {
		return NewTransferError(FailIntegrity, fmt.Sprintf("block_data outside manifest: %d", idx))
	}
	if frameOff == 0 {
		if r.blockBuf != nil {
			return NewTransferError(FailIntegrity, "new block before block_hash")
		}
		blockLen := r.file.BlockSize
		if rem := r.file.Size - int64(idx)*int64(r.file.BlockSize); int64(blockLen) > rem {
			blockLen = int(rem)
		}
		r.assembling = idx
		r.blockBuf = make([]byte, blockLen)
		r.blockReceived = 0
	}
	if r.blockBuf == nil || r.assembling != idx {
		return NewTransferError(FailIntegrity, fmt.Sprintf("unexpected block fragment %d", idx))
	}
	off := int(frameOff)
	if off != r.blockReceived || off+len(payload) > len(r.blockBuf) {
		return NewTransferError(FailIntegrity, fmt.Sprintf("invalid frame offset in block %d", idx))
	}
	copy(r.blockBuf[off:], payload)
	r.blockReceived += len(payload)
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
	if bh.FileIdx != 0 || bh.BlockIdx != r.assembling {
		return NewTransferError(FailIntegrity, "block_hash does not match assembled block")
	}
	if r.blockReceived != len(r.blockBuf) {
		return NewTransferError(FailIntegrity, "short block")
	}
	sum := sha256.Sum256(r.blockBuf)
	if hex.EncodeToString(sum[:]) != bh.SHA256 {
		return NewTransferError(FailIntegrity, fmt.Sprintf("block %d hash mismatch", bh.BlockIdx))
	}

	block := r.blockBuf
	r.blockBuf = nil
	r.blockReceived = 0
	r.assembling = -1

	if bh.BlockIdx < r.nextBlock {
		return r.sendControl(NewAck(0, bh.BlockIdx))
	}
	if bh.BlockIdx > r.nextBlock {
		if len(r.seenAhead) < DefaultInflightBlocks {
			r.seenAhead[bh.BlockIdx] = true
		}
		return r.requestMissing()
	}

	offset := int64(r.nextBlock) * int64(r.file.BlockSize)
	if err := r.o.Sink.Write(offset, block); err != nil {
		return asTransferError(err, FailSinkError)
	}
	r.digest.Update(block)
	r.nextBlock++
	r.nackOutstanding = -1
	if r.o.OnProgress != nil {
		r.o.OnProgress(offset + int64(len(block)))
	}
	if err := r.sendControl(NewAck(0, bh.BlockIdx)); err != nil {
		return err
	}
	if r.seenAhead[r.nextBlock] {
		delete(r.seenAhead, r.nextBlock)
		return r.requestMissing()
	}
	return nil
}

func (r *Receiver) requestMissing() error {
	if r.nackOutstanding == r.nextBlock {
		return nil
	}
	r.nackOutstanding = r.nextBlock
	return r.sendControl(NewNack(0, r.nextBlock, NackMissing))
}

func (r *Receiver) onControl(payload []byte) error {
	msg, err := DecodeControl(payload)
	if err != nil {
		return NewTransferError(FailIntegrity, err.Error())
	}
	control, ok := msg.(*Control)
	if !ok {
		return NewTransferError(FailIntegrity, "expected control")
	}
	switch control.Op {
	case ControlPause:
		r.setPaused(true)
	case ControlResume:
		r.setPaused(false)
	case ControlCancel:
		if r.o.OnStateChange != nil {
			r.o.OnStateChange(TransferCanceled)
		}
		r.abortWith(NewTransferError(FailCanceled, "peer canceled the transfer"), false)
	}
	return nil
}

func (r *Receiver) onPeerFail(payload []byte) error {
	msg, err := DecodeControl(payload)
	if err != nil {
		return NewTransferError(FailIntegrity, err.Error())
	}
	fail, ok := msg.(*Fail)
	if !ok {
		return NewTransferError(FailIntegrity, "expected fail")
	}
	r.abortWith(NewTransferError(fail.Reason, "sender failed: "+string(fail.Reason)), false)
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
	complete, ok := msg.(*Complete)
	if !ok {
		return NewTransferError(FailIntegrity, "expected complete")
	}
	if r.nextBlock != r.file.Blocks {
		return r.requestMissing()
	}
	got := r.digest.HexDigest()
	if complete.FileDigest != r.file.FileDigest || got != complete.FileDigest {
		return NewTransferError(FailDigestMismatch, "whole-file digest mismatch")
	}
	if err := r.o.Sink.Close(); err != nil {
		return asTransferError(err, FailSinkError)
	}
	if err := r.sendControl(NewDone()); err != nil {
		return err
	}
	r.settle(ReceiveResult{File: *r.file, Digest: got})
	return nil
}

func (r *Receiver) setPaused(paused bool) bool {
	r.mu.Lock()
	if r.settled || r.paused == paused {
		r.mu.Unlock()
		return false
	}
	r.paused = paused
	r.mu.Unlock()
	if r.o.OnStateChange != nil {
		if paused {
			r.o.OnStateChange(TransferPaused)
		} else {
			r.o.OnStateChange(TransferRunning)
		}
	}
	return true
}

func (r *Receiver) abortWith(err *TransferError, notifyPeer bool) {
	r.mu.Lock()
	if r.settled {
		r.mu.Unlock()
		return
	}
	r.settled = true
	r.err = err
	r.mu.Unlock()
	if notifyPeer {
		_ = r.sendControl(NewFail(err.Reason))
	}
	_ = r.o.Sink.Abort(string(err.Reason))
	close(r.done)
}

func (r *Receiver) cancelFromContext(cause error) {
	sent := make(chan struct{})
	go func() {
		_ = r.sendControl(NewControl(ControlCancel))
		close(sent)
	}()
	select {
	case <-sent:
	case <-time.After(250 * time.Millisecond):
	}
	r.abortWith(NewTransferError(FailCanceled, cause.Error()), false)
}

func (r *Receiver) settle(result ReceiveResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.settled {
		return
	}
	r.settled = true
	r.result = result
	close(r.done)
}

func (r *Receiver) isSettled() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.settled
}

func (r *Receiver) sendControl(msg ControlMsg) error {
	payload, err := EncodeControl(msg)
	if err != nil {
		return err
	}
	r.sendMu.Lock()
	defer r.sendMu.Unlock()
	frame, err := Seal(r.o.SendDir, r.sendCounter,
		FrameHeaderInput{Version: FrameVersion, Type: msg.FrameType()}, payload)
	if err != nil {
		return err
	}
	r.sendCounter++
	return r.o.Send(frame)
}

func asTransferError(err error, fallback FailReason) *TransferError {
	var transferErr *TransferError
	if errors.As(err, &transferErr) {
		return transferErr
	}
	return NewTransferError(fallback, err.Error())
}
