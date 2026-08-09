package wire

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"
)

// Sender streams one file while retaining only a bounded window of unacknowledged blocks.
// A block leaves the window after the receiver has verified and committed it. NACK and timeout
// retransmissions are sealed under fresh AEAD counters; integrity failures remain terminal.

// FrameFlagLastInBlock marks the final data frame in a logical block.
const FrameFlagLastInBlock uint8 = 0x01

const (
	// DefaultAckTimeout is the acknowledgement deadline before a block is retransmitted.
	DefaultAckTimeout = 15 * time.Second
	// DefaultMaxBlockRetries bounds retransmissions after the initial block send.
	DefaultMaxBlockRetries = 3
)

// SenderOptions configures a Sender. Zero-valued sizing and retry fields select defaults.
type SenderOptions struct {
	// File is the one-file compatibility shorthand. Set either File or Files, not both.
	File             FileSource
	Files            []FileSource
	Send             func(frame []byte) error
	SendDir          DirectionalKey
	RecvDir          DirectionalKey
	SendCounterStart uint64
	RecvCounterStart uint64
	CreateDigest     func() Digest
	BlockSize        int
	FrameSize        int
	Window           int
	AckTimeout       time.Duration
	MaxRetries       int
	// OnProgress reports bytes acknowledged after verify-and-sink.
	OnProgress     func(acknowledgedBytes int64)
	OnFileProgress func(fileIdx int, fileBytes, acknowledgedBytes int64)
	OnStateChange  func(TransferState)
}

type inflightBlock struct {
	bytes   []byte
	retries int
	timer   *time.Timer
}

// Sender drives one file send. Construct it with NewSender.
type Sender struct {
	o          SenderOptions
	blockSize  int
	frameSize  int
	window     int
	ackTimeout time.Duration
	maxRetries int
	files      []FileSource

	sendMu      sync.Mutex
	sendCounter uint64

	mu                     sync.Mutex
	cond                   *sync.Cond
	recvCounter            uint64
	inflight               map[int]*inflightBlock
	retryQueue             []int
	retryQueued            map[int]bool
	acknowledged           int64
	activeFileIdx          int
	activeFileAcknowledged int64
	paused                 bool
	completeSent           bool
	settled                bool
	err                    error
}

var errSenderSettled = errors.New("sender settled")

// NewSender builds a Sender and applies protocol defaults.
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
	if opts.AckTimeout == 0 {
		opts.AckTimeout = DefaultAckTimeout
	}
	if opts.MaxRetries <= 0 {
		opts.MaxRetries = DefaultMaxBlockRetries
	}
	if opts.CreateDigest == nil {
		opts.CreateDigest = NewSHA256Digest
	}
	files := opts.Files
	if len(files) == 0 && opts.File != nil {
		files = []FileSource{opts.File}
	}
	s := &Sender{
		o:             opts,
		blockSize:     opts.BlockSize,
		frameSize:     opts.FrameSize,
		window:        opts.Window,
		ackTimeout:    opts.AckTimeout,
		maxRetries:    opts.MaxRetries,
		files:         files,
		sendCounter:   opts.SendCounterStart,
		recvCounter:   opts.RecvCounterStart,
		inflight:      make(map[int]*inflightBlock),
		retryQueued:   make(map[int]bool),
		activeFileIdx: -1,
	}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// Run sends the file and returns its canonical digest after every block is acknowledged and the
// receiver confirms the whole-file digest.
func (s *Sender) Run(ctx context.Context) (string, error) {
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			s.cancelFromContext(ctx.Err())
		case <-stop:
		}
	}()

	if len(s.files) == 0 || (s.o.File != nil && len(s.o.Files) > 0) {
		err := errors.New("transfer: exactly one of File or Files is required")
		s.fail(err)
		return "", err
	}
	entries := make([]FileEntry, len(s.files))
	var totalSize int64
	for idx, source := range s.files {
		meta := source.Meta()
		digest := s.o.CreateDigest()
		if err := source.Stream(func(chunk []byte) error {
			digest.Update(chunk)
			return nil
		}); err != nil {
			s.fail(err)
			return "", err
		}
		blocks := 0
		if meta.Size > 0 {
			blocks = int((meta.Size-1)/int64(s.blockSize) + 1)
		}
		entries[idx] = FileEntry{
			Idx: idx, Name: meta.Name, Size: meta.Size, Mime: meta.Mime,
			LastModified: meta.LastModified, BlockSize: s.blockSize, Blocks: blocks,
			FileDigest: digest.HexDigest(),
		}
		if meta.Size > math.MaxInt64-totalSize {
			err := errors.New("transfer: total size overflow")
			s.fail(err)
			return "", err
		}
		totalSize += meta.Size
	}
	manifest, err := ValidateManifest(*NewManifest(entries, totalSize))
	if err != nil {
		s.fail(err)
		return "", err
	}
	transferDigest := CompletionDigest(manifest.Files)
	if err := s.sendControl(&manifest); err != nil {
		s.fail(err)
		return "", err
	}

	for fileIdx, source := range s.files {
		s.mu.Lock()
		s.activeFileIdx = fileIdx
		s.activeFileAcknowledged = 0
		s.mu.Unlock()
		streamErr := ReChunk(StreamFunc(source.Stream), s.blockSize, s.blockSize, func(p FramePiece) error {
			if err := s.beforeNewBlock(); err != nil {
				return err
			}
			block := append([]byte(nil), p.Payload...)
			s.mu.Lock()
			if s.settled {
				s.mu.Unlock()
				return errSenderSettled
			}
			s.inflight[p.BlockIdx] = &inflightBlock{bytes: block}
			s.mu.Unlock()
			if err := s.sendBlock(p.BlockIdx, block); err != nil {
				return err
			}
			s.armTimeout(p.BlockIdx)
			return nil
		})
		if streamErr != nil && !errors.Is(streamErr, errSenderSettled) {
			s.fail(streamErr)
			return "", streamErr
		}
		if err := s.waitInflight(); err != nil {
			return "", err
		}
		if s.o.OnFileProgress != nil {
			s.o.OnFileProgress(fileIdx, entries[fileIdx].Size, s.acknowledged)
		}
	}
	s.mu.Lock()
	s.completeSent = true
	s.mu.Unlock()
	if err := s.sendControl(NewComplete(transferDigest)); err != nil {
		s.fail(err)
		return "", err
	}
	if err := s.waitDone(); err != nil {
		return "", err
	}
	return transferDigest, nil
}

// Handle consumes one encrypted receiver control frame. Calls must remain ordered.
func (s *Sender) Handle(frame []byte) {
	s.mu.Lock()
	if s.settled {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	opened, err := OpenSequenced(s.o.RecvDir, s.recvCounter, frame)
	if err != nil {
		if errors.Is(err, ErrFrameReplay) {
			return
		}
		s.fail(NewTransferError(FailIntegrity, err.Error()))
		return
	}
	s.mu.Lock()
	s.recvCounter = opened.Counter + 1
	s.mu.Unlock()
	msg, err := DecodeControl(opened.Plaintext)
	if err != nil {
		s.fail(NewTransferError(FailIntegrity, err.Error()))
		return
	}
	if opened.Header.Type != msg.FrameType() {
		s.fail(NewTransferError(FailIntegrity, "control frame header/payload type mismatch"))
		return
	}

	switch m := msg.(type) {
	case *Ack:
		s.onAck(m)
	case *Nack:
		s.mu.Lock()
		active := s.activeFileIdx
		s.mu.Unlock()
		if m.FileIdx < active {
			return
		}
		if m.FileIdx != active {
			s.fail(NewTransferError(FailIntegrity, "nack for unknown file"))
			return
		}
		s.queueRetry(m.BlockIdx)
	case *Control:
		s.applyRemoteControl(m.Op)
	case *Done:
		s.mu.Lock()
		premature := !s.completeSent || len(s.inflight) != 0
		s.mu.Unlock()
		if premature {
			s.fail(NewTransferError(FailIntegrity, "done before every block was acknowledged"))
			return
		}
		s.settle()
	case *Fail:
		s.fail(NewTransferError(m.Reason, "receiver failed: "+string(m.Reason)))
	default:
		s.fail(NewTransferError(FailIntegrity,
			fmt.Sprintf("unexpected sender-inbound type %d", msg.FrameType())))
	}
}

// Pause stops new data frames locally and notifies the peer.
func (s *Sender) Pause() error {
	if !s.setPaused(true) {
		return nil
	}
	return s.sendControl(NewControl(ControlPause))
}

// Resume reopens the data path and notifies the peer.
func (s *Sender) Resume() error {
	if !s.setPaused(false) {
		return nil
	}
	return s.sendControl(NewControl(ControlResume))
}

// Cancel notifies the peer and terminates the sender. It is idempotent.
func (s *Sender) Cancel(reason string) error {
	s.mu.Lock()
	settled := s.settled
	s.mu.Unlock()
	if settled {
		return nil
	}
	err := s.sendControl(NewControl(ControlCancel))
	s.fail(NewTransferError(FailCanceled, reason))
	return err
}

func (s *Sender) onAck(ack *Ack) {
	s.mu.Lock()
	if ack.FileIdx < s.activeFileIdx {
		s.mu.Unlock()
		return
	}
	if ack.FileIdx != s.activeFileIdx {
		s.mu.Unlock()
		s.fail(NewTransferError(FailIntegrity, "ack for unknown file"))
		return
	}
	state := s.inflight[ack.BlockIdx]
	if state == nil {
		s.mu.Unlock()
		return
	}
	if state.timer != nil {
		state.timer.Stop()
	}
	delete(s.inflight, ack.BlockIdx)
	delete(s.retryQueued, ack.BlockIdx)
	s.acknowledged += int64(len(state.bytes))
	s.activeFileAcknowledged += int64(len(state.bytes))
	acknowledged := s.acknowledged
	fileAcknowledged := s.activeFileAcknowledged
	fileIdx := s.activeFileIdx
	s.cond.Broadcast()
	s.mu.Unlock()
	if s.o.OnProgress != nil {
		s.o.OnProgress(acknowledged)
	}
	if s.o.OnFileProgress != nil {
		s.o.OnFileProgress(fileIdx, fileAcknowledged, acknowledged)
	}
}

func (s *Sender) applyRemoteControl(op ControlOp) {
	switch op {
	case ControlPause:
		s.setPaused(true)
	case ControlResume:
		s.setPaused(false)
	case ControlCancel:
		if s.o.OnStateChange != nil {
			s.o.OnStateChange(TransferCanceled)
		}
		s.fail(NewTransferError(FailCanceled, "peer canceled the transfer"))
	}
}

func (s *Sender) setPaused(paused bool) bool {
	s.mu.Lock()
	if s.settled || s.paused == paused {
		s.mu.Unlock()
		return false
	}
	s.paused = paused
	for idx, state := range s.inflight {
		if state.timer != nil {
			state.timer.Stop()
			state.timer = nil
		}
		if !paused {
			s.armTimeoutLocked(idx, state)
		}
	}
	s.cond.Broadcast()
	s.mu.Unlock()
	if s.o.OnStateChange != nil {
		if paused {
			s.o.OnStateChange(TransferPaused)
		} else {
			s.o.OnStateChange(TransferRunning)
		}
	}
	return true
}

func (s *Sender) beforeNewBlock() error {
	for {
		idx, state, err := s.nextRetryOrWait(true)
		if err != nil {
			return err
		}
		if state == nil {
			return nil
		}
		if err := s.resend(idx, state); err != nil {
			return err
		}
	}
}

func (s *Sender) waitInflight() error {
	for {
		idx, state, err := s.nextRetryOrWait(false)
		if err != nil {
			return err
		}
		if state == nil {
			return nil
		}
		if err := s.resend(idx, state); err != nil {
			return err
		}
	}
}

// nextRetryOrWait returns one queued retry. With capacity=true it returns nil once a new block
// may enter the window; otherwise it returns nil once the entire window is acknowledged.
func (s *Sender) nextRetryOrWait(capacity bool) (int, *inflightBlock, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if s.settled {
			if s.err != nil {
				return 0, nil, s.err
			}
			return 0, nil, errSenderSettled
		}
		if s.paused {
			s.cond.Wait()
			continue
		}
		for len(s.retryQueue) > 0 {
			idx := s.retryQueue[0]
			s.retryQueue = s.retryQueue[1:]
			delete(s.retryQueued, idx)
			if state := s.inflight[idx]; state != nil {
				return idx, state, nil
			}
		}
		if capacity && len(s.inflight) < s.window {
			return 0, nil, nil
		}
		if !capacity && len(s.inflight) == 0 {
			return 0, nil, nil
		}
		s.cond.Wait()
	}
}

func (s *Sender) resend(blockIdx int, state *inflightBlock) error {
	s.mu.Lock()
	current := s.inflight[blockIdx]
	if current == nil || current != state {
		s.mu.Unlock()
		return nil
	}
	if state.retries >= s.maxRetries {
		s.mu.Unlock()
		err := NewTransferError(FailRetryExhausted,
			fmt.Sprintf("block %d remained unacknowledged", blockIdx))
		_ = s.sendControl(NewFail(FailRetryExhausted))
		s.fail(err)
		return err
	}
	state.retries++
	s.mu.Unlock()
	if err := s.sendBlock(blockIdx, state.bytes); err != nil {
		s.fail(err)
		return err
	}
	s.armTimeout(blockIdx)
	return nil
}

func (s *Sender) queueRetry(blockIdx int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.inflight[blockIdx]
	if state == nil || s.retryQueued[blockIdx] || s.settled {
		return
	}
	if state.timer != nil {
		state.timer.Stop()
		state.timer = nil
	}
	s.retryQueued[blockIdx] = true
	s.retryQueue = append(s.retryQueue, blockIdx)
	s.cond.Broadcast()
}

func (s *Sender) armTimeout(blockIdx int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if state := s.inflight[blockIdx]; state != nil {
		s.armTimeoutLocked(blockIdx, state)
	}
}

func (s *Sender) armTimeoutLocked(blockIdx int, state *inflightBlock) {
	if s.paused || s.ackTimeout < 0 || s.settled {
		return
	}
	if state.timer != nil {
		state.timer.Stop()
	}
	state.timer = time.AfterFunc(s.ackTimeout, func() { s.queueRetry(blockIdx) })
}

func (s *Sender) sendBlock(blockIdx int, block []byte) error {
	s.mu.Lock()
	fileIdx := s.activeFileIdx
	s.mu.Unlock()
	for off := 0; off < len(block); off += s.frameSize {
		end := off + s.frameSize
		if end > len(block) {
			end = len(block)
		}
		flags := uint8(0)
		if end == len(block) {
			flags = FrameFlagLastInBlock
		}
		if err := s.sendFrame(FrameHeaderInput{
			Version: FrameVersion, Type: FrameBlockData, Flags: flags,
			FileIdx: uint16(fileIdx), BlockIdx: uint32(blockIdx), FrameOff: uint32(off),
		}, block[off:end]); err != nil {
			return err
		}
	}
	sum := sha256.Sum256(block)
	return s.sendControl(NewBlockHash(fileIdx, blockIdx, hex.EncodeToString(sum[:])))
}

func (s *Sender) waitDone() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for !s.settled {
		s.cond.Wait()
	}
	return s.err
}

func (s *Sender) settle() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.settled {
		return
	}
	s.settled = true
	s.clearTimersLocked()
	s.cond.Broadcast()
}

func (s *Sender) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.settled {
		return
	}
	s.settled = true
	s.err = err
	s.clearTimersLocked()
	s.cond.Broadcast()
}

func (s *Sender) cancelLocal(cause error) {
	s.fail(NewTransferError(FailCanceled, cause.Error()))
}

func (s *Sender) cancelFromContext(cause error) {
	sent := make(chan struct{})
	go func() {
		_ = s.sendControl(NewControl(ControlCancel))
		close(sent)
	}()
	select {
	case <-sent:
	case <-time.After(250 * time.Millisecond):
	}
	s.cancelLocal(cause)
}

func (s *Sender) clearTimersLocked() {
	for _, state := range s.inflight {
		if state.timer != nil {
			state.timer.Stop()
		}
	}
}

func (s *Sender) sendControl(msg ControlMsg) error {
	payload, err := EncodeControl(msg)
	if err != nil {
		return err
	}
	return s.sendFrame(FrameHeaderInput{Version: FrameVersion, Type: msg.FrameType()}, payload)
}

// sendFrame serializes sealing and transport writes so controls cannot race data for a nonce.
func (s *Sender) sendFrame(header FrameHeaderInput, payload []byte) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	frame, err := Seal(s.o.SendDir, s.sendCounter, header, payload)
	if err != nil {
		return err
	}
	s.sendCounter++
	return s.o.Send(frame)
}
