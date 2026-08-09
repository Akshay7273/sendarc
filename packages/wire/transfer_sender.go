package wire

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

// Sender is the sending half of the transport-agnostic transfer engine (design §5). It
// streams a file without ever buffering it whole:
//
//	Pass 1  read the file once → whole-file streaming digest → manifest (with fileDigest).
//	Pass 2  re-chunk into block_data frames; at each block boundary send block_hash.
//	Finish  send complete{fileDigest}; return when the receiver replies done.
//
// Outbound frames are AES-GCM sealed with a per-direction counter that continues from the
// handshake and is never reset. The sender never runs more than Window blocks ahead of the
// receiver's block_recv signal, bounding the outbound queue. It is the Go twin of
// packages/protocol/src/transfer-sender.ts.
//
// Run executes on the caller's goroutine; Handle is called from the transport's read loop as
// inbound frames (block_recv / done / fail) arrive. Shared state is guarded by a mutex and a
// condition variable: window-gating in Run waits on the receiver's acks delivered by Handle.

// FrameFlagLastInBlock is the header flag marking a frame as the last of its block.
const FrameFlagLastInBlock uint8 = 0x01

// SenderOptions configures a Sender. Zero-valued sizing fields select the protocol defaults.
type SenderOptions struct {
	File             FileSource
	Send             func(frame []byte) error
	SendDir          DirectionalKey
	RecvDir          DirectionalKey
	SendCounterStart uint64
	RecvCounterStart uint64
	CreateDigest     func() Digest // nil selects a streaming SHA-256 digest
	BlockSize        int           // 0 selects DefaultBlockBytes
	FrameSize        int           // 0 selects DefaultFrameBytes
	Window           int           // 0 selects DefaultInflightBlocks
	OnProgress       func(sentBytes int64)
}

// Sender drives one file send. Construct it with NewSender.
type Sender struct {
	o         SenderOptions
	blockSize int
	frameSize int
	window    int

	sendCounter uint64 // touched only by Run's goroutine
	sent        int64  // touched only by Run's goroutine

	mu            sync.Mutex
	cond          *sync.Cond
	recvCounter   uint64
	lastRecvBlock int
	settled       bool
	err           error // non-nil once a fail has been observed
}

// errSenderSettled breaks out of the pass-2 stream when the transfer settles mid-flight; it
// never escapes Run, which converts it into the stored fail (or nil on an early done).
var errSenderSettled = errors.New("sender settled")

// NewSender builds a Sender, applying protocol defaults for any zero-valued sizing option.
func NewSender(opts SenderOptions) *Sender {
	if opts.BlockSize <= 0 {
		opts.BlockSize = DefaultBlockBytes
	}
	if opts.FrameSize <= 0 {
		opts.FrameSize = DefaultFrameBytes
	}
	if opts.Window <= 0 {
		opts.Window = DefaultInflightBlocks
	}
	if opts.CreateDigest == nil {
		opts.CreateDigest = NewSHA256Digest
	}
	s := &Sender{
		o:             opts,
		blockSize:     opts.BlockSize,
		frameSize:     opts.FrameSize,
		window:        opts.Window,
		sendCounter:   opts.SendCounterStart,
		recvCounter:   opts.RecvCounterStart,
		lastRecvBlock: -1,
	}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// Run drives the whole send. It returns the canonical whole-file digest (hex) once the
// receiver confirms done, or an error on fail or an IO failure. The digest is the same value
// carried in the manifest and complete, so a host can report it without recomputing.
func (s *Sender) Run() (string, error) {
	meta := s.o.File.Meta()

	// Pass 1: whole-file digest, streamed so the file is never held.
	digest := s.o.CreateDigest()
	if err := s.o.File.Stream(func(chunk []byte) error {
		digest.Update(chunk)
		return nil
	}); err != nil {
		return "", err
	}
	fileDigest := digest.HexDigest()

	blocks := 0
	if meta.Size > 0 {
		blocks = int((meta.Size + int64(s.blockSize) - 1) / int64(s.blockSize)) // ceil
	}
	if err := s.sendControl(NewManifest([]FileEntry{{
		Idx: 0, Name: meta.Name, Size: meta.Size, Mime: meta.Mime,
		LastModified: meta.LastModified, BlockSize: s.blockSize, Blocks: blocks,
		FileDigest: fileDigest,
	}}, meta.Size)); err != nil {
		return "", err
	}

	// Pass 2: block data + per-block hash, gated to the in-flight window.
	var blockParts []byte
	streamErr := ReChunk(StreamFunc(s.o.File.Stream), s.blockSize, s.frameSize, func(p FramePiece) error {
		s.gate(p.BlockIdx)
		if s.isSettled() {
			return errSenderSettled // aborted by an inbound fail (or early done)
		}
		flags := uint8(0)
		if p.LastInBlock {
			flags = FrameFlagLastInBlock
		}
		if err := s.sendFrame(FrameHeaderInput{
			Version:  FrameVersion,
			Type:     FrameBlockData,
			Flags:    flags,
			FileIdx:  0,
			BlockIdx: uint32(p.BlockIdx),
			FrameOff: uint32(p.FrameOff),
		}, p.Payload); err != nil {
			return err
		}
		s.sent += int64(len(p.Payload))
		if s.o.OnProgress != nil {
			s.o.OnProgress(s.sent)
		}
		blockParts = append(blockParts, p.Payload...)
		if p.LastInBlock {
			sum := sha256.Sum256(blockParts)
			blockParts = blockParts[:0]
			if err := s.sendControl(NewBlockHash(0, p.BlockIdx, hex.EncodeToString(sum[:]))); err != nil {
				return err
			}
		}
		return nil
	})
	if streamErr != nil {
		if errors.Is(streamErr, errSenderSettled) {
			// Settled mid-stream: propagate the fail, or return the digest on an early done.
			return fileDigest, s.waitDone()
		}
		return "", streamErr
	}

	if err := s.sendControl(NewComplete(fileDigest)); err != nil {
		return "", err
	}
	if err := s.waitDone(); err != nil {
		return "", err
	}
	return fileDigest, nil
}

// Handle feeds one inbound frame from the receiver (block_recv / done / fail). It must be
// called serially — the ordered DataChannel read loop satisfies this — because each frame
// consumes the next receive counter.
func (s *Sender) Handle(frame []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.settled {
		return
	}
	ctr := s.recvCounter
	s.recvCounter++
	opened, err := Open(s.o.RecvDir, ctr, frame)
	if err != nil {
		s.failLocked(err)
		return
	}
	msg, err := DecodeControl(opened.Plaintext)
	if err != nil {
		s.failLocked(err)
		return
	}
	switch m := msg.(type) {
	case *BlockRecv:
		if m.BlockIdx > s.lastRecvBlock {
			s.lastRecvBlock = m.BlockIdx
		}
		s.cond.Broadcast()
	case *Done:
		s.settleLocked()
	case *Fail:
		s.failLocked(NewTransferError(m.Reason, "receiver failed: "+string(m.Reason)))
	default:
		s.failLocked(NewTransferError(FailIntegrity,
			fmt.Sprintf("unexpected sender-inbound type %d", msg.FrameType())))
	}
}

// --- internal ---------------------------------------------------------------

// gate blocks until the block is within the in-flight window of the receiver's last ack, or
// the transfer settles.
func (s *Sender) gate(blockIdx int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for !s.settled && blockIdx-s.lastRecvBlock > s.window {
		s.cond.Wait()
	}
}

func (s *Sender) isSettled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settled
}

// waitDone blocks until the transfer settles and returns the fail error, or nil on done.
func (s *Sender) waitDone() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for !s.settled {
		s.cond.Wait()
	}
	return s.err
}

// settleLocked marks a successful finish; the caller holds the mutex.
func (s *Sender) settleLocked() {
	if s.settled {
		return
	}
	s.settled = true
	s.cond.Broadcast()
}

// failLocked records the first failure and wakes every waiter; the caller holds the mutex.
func (s *Sender) failLocked(err error) {
	if s.settled {
		return
	}
	s.settled = true
	s.err = err
	s.cond.Broadcast()
}

// sendControl seals and sends a control message; its frame-header type is the message's tag.
func (s *Sender) sendControl(msg ControlMsg) error {
	payload, err := EncodeControl(msg)
	if err != nil {
		return err
	}
	return s.sendFrame(FrameHeaderInput{
		Version: FrameVersion,
		Type:    msg.FrameType(),
		Flags:   0,
		FileIdx: 0, BlockIdx: 0, FrameOff: 0,
	}, payload)
}

// sendFrame seals payload under the next send counter and hands the frame to the transport.
func (s *Sender) sendFrame(header FrameHeaderInput, payload []byte) error {
	frame, err := Seal(s.o.SendDir, s.sendCounter, header, payload)
	if err != nil {
		return err
	}
	s.sendCounter++
	return s.o.Send(frame)
}
