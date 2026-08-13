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
	Files     []FileEntry
	Digests   []string
	TotalSize int64
	File      FileEntry
	Digest    string
}

// ResumeFileProgress is a reloaded receiver's restored seed for one file: the persisted
// high-water mark and a digest already fed exactly the persisted bytes [0, HaveBlocks). The
// host owns SeedDigest because only it can read those bytes back from durable storage.
type ResumeFileProgress struct {
	HaveBlocks int
	SeedDigest Digest
}

// ReceiverResume is the state a reloaded receiver restores to resume a transfer in place. It is
// applied only when TransferID equals the arriving manifest's; a mismatch means the room was
// reused for a different file set, so the offsets are ignored and a fresh receive starts.
type ReceiverResume struct {
	TransferID string
	Files      map[int]ResumeFileProgress
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
	Destination      Destination
	// OnProgress reports bytes only after verify-and-sink.
	OnProgress     func(acknowledgedBytes int64)
	OnFileProgress func(fileIdx int, fileBytes, acknowledgedBytes int64)
	OnStateChange  func(TransferState)
	OnManifestSet  func(manifest Manifest) error
	OnManifest     func(file FileEntry) error
	// Resume restores a reloaded receiver's progress. When the arriving manifest carries a matching
	// TransferID, each file restarts at its HaveBlocks high-water mark and the sender is asked to
	// stream only the missing blocks. Nil (or a TransferID mismatch) means a fresh receive.
	Resume *ReceiverResume
}

// Receiver drives one file receive. Handle calls must remain ordered.
type Receiver struct {
	o           ReceiverOptions
	destination Destination

	sendMu      sync.Mutex
	sendCounter uint64
	handleMu    sync.Mutex

	// Assembly state belongs to the serial Handle path.
	recvCounter     uint64
	manifest        *Manifest
	fileIdx         int
	file            *FileEntry
	sink            Sink
	digest          Digest
	digests         []string
	acknowledged    int64
	nextBlock       int
	assemblingFile  int
	assembling      int
	blockBuf        []byte
	blockReceived   int
	awaitingRestart bool
	seenAhead       map[int]bool
	nackOutstanding int
	// activeResume is the caller's seed, kept only once its TransferID matches the manifest.
	activeResume *ReceiverResume

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
	destination := opts.Destination
	if destination == nil && opts.Sink != nil {
		destination = SingleSinkDestination(opts.Sink)
	}
	return &Receiver{
		o:               opts,
		destination:     destination,
		sendCounter:     opts.SendCounterStart,
		recvCounter:     opts.RecvCounterStart,
		assembling:      -1,
		assemblingFile:  -1,
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
	r.handleMu.Lock()
	defer r.handleMu.Unlock()
	if err := r.process(frame); err != nil {
		var te *TransferError
		if !errors.As(err, &te) {
			te = NewTransferError(FailIntegrity, err.Error())
		}
		r.abortWith(te, true)
	}
}

// TransportChanged discards an unverified partial block from the old ordered path. The sender
// retransmits its unacknowledged window on the new path; already committed blocks stay intact.
func (r *Receiver) TransportChanged() {
	r.handleMu.Lock()
	r.blockBuf = nil
	r.blockReceived = 0
	r.assembling = -1
	r.assemblingFile = -1
	r.seenAhead = make(map[int]bool)
	r.nackOutstanding = -1
	r.awaitingRestart = true
	r.handleMu.Unlock()
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
		return r.replyDoneAfterCutover(frame)
	}
	opened, err := OpenSequenced(r.o.RecvDir, r.recvCounter, frame)
	if err != nil {
		if errors.Is(err, ErrFrameReplay) {
			return nil
		}
		return NewTransferError(FailIntegrity, err.Error())
	}
	r.recvCounter = opened.Counter + 1
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
	msg, err := DecodeControl(payload)
	if err != nil {
		return NewTransferError(FailIntegrity, err.Error())
	}
	m, ok := msg.(*Manifest)
	if !ok {
		return NewTransferError(FailIntegrity, "expected manifest")
	}
	validated, err := ValidateManifest(*m)
	if err != nil {
		return NewTransferError(FailIntegrity, err.Error())
	}
	if r.manifest != nil {
		// A path cutover can retransmit the manifest while the original is still
		// being processed. An identical copy is harmless; a different one is a
		// protocol violation.
		if manifestsEqual(&validated, r.manifest) {
			return nil
		}
		return NewTransferError(FailIntegrity, "duplicate manifest")
	}
	if r.destination == nil {
		return NewTransferError(FailSinkError, "transfer destination is required")
	}
	if err := r.destination.Prepare(validated); err != nil {
		return asTransferError(err, FailSinkError)
	}
	if r.o.OnManifestSet != nil {
		if err := r.o.OnManifestSet(validated); err != nil {
			return asTransferError(err, FailSinkError)
		}
	}
	r.manifest = &validated
	r.digests = make([]string, len(validated.Files))
	// The sender may already be retrying blocks on the old path while the
	// cutover's manifest copy arrives; discard that stale tail (fragments
	// before the next block boundary, plus its hash) instead of assembling it.
	r.awaitingRestart = true
	if validated.TransferID != "" {
		// The sender opted into resumption. Apply persisted offsets only when they belong to this
		// exact transfer, then report each file's high-water mark so the sender skips held blocks.
		if r.o.Resume != nil && r.o.Resume.TransferID == validated.TransferID {
			r.activeResume = r.o.Resume
		}
		if err := r.sendResumeState(&validated); err != nil {
			return err
		}
	}
	return r.openNextFile()
}

func (r *Receiver) sendResumeState(manifest *Manifest) error {
	files := make([]ResumeFileState, len(manifest.Files))
	for i, file := range manifest.Files {
		have := 0
		if r.activeResume != nil {
			if p, ok := r.activeResume.Files[file.Idx]; ok {
				have = p.HaveBlocks
			}
		}
		if have > file.Blocks {
			have = file.Blocks
		}
		files[i] = ResumeFileState{Idx: file.Idx, HaveBlocks: have}
	}
	return r.sendControl(NewResumeState(manifest.TransferID, files))
}

func (r *Receiver) openNextFile() error {
	if r.manifest == nil {
		return NewTransferError(FailIntegrity, "file opened before manifest")
	}
	for r.fileIdx < len(r.manifest.Files) {
		file := r.manifest.Files[r.fileIdx]
		r.file = &file
		r.nextBlock = 0
		r.digest = r.o.CreateDigest()
		if r.activeResume != nil {
			if p, ok := r.activeResume.Files[file.Idx]; ok {
				r.nextBlock = p.HaveBlocks
				if r.nextBlock > file.Blocks {
					r.nextBlock = file.Blocks
				}
				if p.SeedDigest != nil {
					// The seed digest already holds the persisted prefix; the remainder appends.
					r.digest = p.SeedDigest
				}
			}
		}
		// Persisted bytes count as acknowledged so progress resumes without a backwards jump.
		if r.nextBlock >= file.Blocks {
			r.acknowledged += file.Size
		} else {
			r.acknowledged += int64(r.nextBlock) * int64(file.BlockSize)
		}
		r.seenAhead = make(map[int]bool)
		r.nackOutstanding = -1
		if r.o.OnManifest != nil {
			if err := r.o.OnManifest(file); err != nil {
				return asTransferError(err, FailSinkError)
			}
		}
		sink, err := r.destination.Open(file)
		if err != nil {
			return asTransferError(err, FailSinkError)
		}
		r.sink = sink
		// Return to receive blocks only when some remain; empty and fully-held files finish now.
		if r.nextBlock < file.Blocks {
			return nil
		}
		if err := r.finishCurrentFile(); err != nil {
			return err
		}
	}
	r.file = nil
	r.sink = nil
	r.digest = nil
	return nil
}

func (r *Receiver) finishCurrentFile() error {
	if r.file == nil || r.sink == nil || r.digest == nil {
		return NewTransferError(FailIntegrity, "no active file")
	}
	got := r.digest.HexDigest()
	if got != r.file.FileDigest {
		return NewTransferError(FailDigestMismatch, fmt.Sprintf("file %d digest mismatch", r.file.Idx))
	}
	if err := r.sink.Close(); err != nil {
		return asTransferError(err, FailSinkError)
	}
	r.digests[r.file.Idx] = got
	if r.o.OnFileProgress != nil {
		r.o.OnFileProgress(r.file.Idx, r.file.Size, r.acknowledged)
	}
	r.fileIdx++
	r.file = nil
	r.sink = nil
	r.digest = nil
	return nil
}

func (r *Receiver) onBlockData(fileIdx uint16, blockIdx uint32, frameOff uint32, payload []byte) error {
	if r.manifest == nil {
		// A cutover may lose the manifest while block data is already streaming;
		// the sender retransmits it, so stray data before the manifest is ignored
		// rather than treated as a protocol violation.
		return nil
	}
	fileNumber := int(fileIdx)
	if fileNumber < 0 || fileNumber >= len(r.manifest.Files) || fileNumber > r.fileIdx {
		return NewTransferError(FailIntegrity, fmt.Sprintf("block_data outside manifest: %d", blockIdx))
	}
	entry := r.manifest.Files[fileNumber]
	idx := int(blockIdx)
	if idx < 0 || idx >= entry.Blocks {
		return NewTransferError(FailIntegrity, fmt.Sprintf("block_data outside manifest: %d", idx))
	}
	if r.awaitingRestart && frameOff != 0 {
		return nil // discard the abandoned old-path tail until a fresh block begins
	}
	if frameOff == 0 {
		if r.blockBuf != nil {
			return NewTransferError(FailIntegrity, "new block before block_hash")
		}
		blockLen := min(entry.BlockSize, MaxManifestBlockBytes)
		if rem := entry.Size - int64(idx)*int64(entry.BlockSize); int64(blockLen) > rem {
			blockLen = int(rem)
		}
		r.assemblingFile = fileNumber
		r.assembling = idx
		r.blockBuf = make([]byte, blockLen)
		r.blockReceived = 0
		r.awaitingRestart = false
	}
	if r.blockBuf == nil || r.assemblingFile != fileNumber || r.assembling != idx {
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
	if r.blockBuf == nil && r.awaitingRestart {
		return nil // hash for the abandoned partial block
	}
	if r.manifest == nil {
		return nil // pre-manifest; the manifest may be in flight after a cutover
	}
	if r.blockBuf == nil {
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
	if bh.FileIdx != r.assemblingFile || bh.BlockIdx != r.assembling {
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
	r.assemblingFile = -1

	if bh.FileIdx < r.fileIdx {
		return r.sendControl(NewAck(bh.FileIdx, bh.BlockIdx))
	}
	if r.file == nil || r.sink == nil || r.digest == nil || bh.FileIdx != r.fileIdx {
		return NewTransferError(FailIntegrity, "block_hash for inactive file")
	}

	if bh.BlockIdx < r.nextBlock {
		return r.sendControl(NewAck(bh.FileIdx, bh.BlockIdx))
	}
	if bh.BlockIdx > r.nextBlock {
		if len(r.seenAhead) < DefaultInflightBlocks {
			r.seenAhead[bh.BlockIdx] = true
		}
		return r.requestMissing()
	}

	offset := int64(r.nextBlock) * int64(r.file.BlockSize)
	// The digest must cover the block before the sink checkpoints it: sink.Write advances
	// the durable checkpoint, and the digest state for that exact prefix is carried into
	// the same atomic journal update through the optional DigestStateSink seam. Advancing
	// the in-memory digest before the durable write is safe because any later sink failure
	// terminates this receive attempt while the persisted journal stays at its previous
	// valid checkpoint (ADR 0004).
	r.digest.Update(block)
	if err := r.attachDigestState(); err != nil {
		return err
	}
	if err := r.sink.Write(offset, block); err != nil {
		return asTransferError(err, FailSinkError)
	}
	r.nextBlock++
	r.nackOutstanding = -1
	r.acknowledged += int64(len(block))
	if r.o.OnProgress != nil {
		r.o.OnProgress(r.acknowledged)
	}
	if r.o.OnFileProgress != nil {
		r.o.OnFileProgress(r.file.Idx, offset+int64(len(block)), r.acknowledged)
	}
	if err := r.sendControl(NewAck(bh.FileIdx, bh.BlockIdx)); err != nil {
		return err
	}
	if r.nextBlock == r.file.Blocks {
		if err := r.finishCurrentFile(); err != nil {
			return err
		}
		return r.openNextFile()
	}
	if r.seenAhead[r.nextBlock] {
		delete(r.seenAhead, r.nextBlock)
		return r.requestMissing()
	}
	return nil
}

// attachDigestState hands the sink the digest state covering exactly the block that the
// following sink.Write will checkpoint, so a durable sink can persist committedBlocks and
// the matching digest checkpoint in one atomic journal update (V13-PR05). Sinks without
// the optional DigestStateSink capability journal a checkpoint without digest state, and
// digests without DigestState support contribute nil — the storage layer then omits the
// checkpoint and resume re-hashes the persisted prefix.
func (r *Receiver) attachDigestState() error {
	sink, ok := r.sink.(DigestStateSink)
	if !ok {
		return nil
	}
	var state []byte
	if ds, ok := r.digest.(DigestState); ok {
		var err error
		state, err = ds.MarshalState()
		if err != nil {
			return asTransferError(err, FailSinkError)
		}
	}
	return sink.SetDigestState(state)
}

func (r *Receiver) requestMissing() error {
	if r.nackOutstanding == r.nextBlock {
		return nil
	}
	r.nackOutstanding = r.nextBlock
	return r.sendControl(NewNack(r.fileIdx, r.nextBlock, NackMissing))
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

// settledOK reports whether the receiver already settled successfully (err is nil).
func (r *Receiver) settledOK() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.settled && r.err == nil
}

// replyDoneAfterCutover handles a frame that arrives after the receiver has already settled.
// A direct→relay cutover can lose the receiver's one-shot Done after it settled; the sender
// then retransmits Complete on the new path and must get a fresh Done, or it stalls waiting
// for Done until it times out. A settled receiver ignores everything else — it has no more
// work to do and no longer validates data.
func (r *Receiver) replyDoneAfterCutover(frame []byte) error {
	if !r.settledOK() {
		return nil
	}
	opened, err := OpenSequenced(r.o.RecvDir, r.recvCounter, frame)
	if err != nil {
		return nil
	}
	if opened.Header.Type != FrameComplete {
		return nil
	}
	r.recvCounter = opened.Counter + 1
	return r.sendControl(NewDone())
}

func (r *Receiver) onComplete(payload []byte) error {
	if r.manifest == nil {
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
	if r.file != nil && r.nextBlock != r.file.Blocks {
		return r.requestMissing()
	}
	if r.fileIdx != len(r.manifest.Files) {
		return NewTransferError(FailIntegrity, "complete before every file was received")
	}
	got := CompletionDigest(r.manifest.Files)
	if complete.FileDigest != got {
		return NewTransferError(FailDigestMismatch, "file-set mismatch")
	}
	if err := r.destination.Close(); err != nil {
		return asTransferError(err, FailSinkError)
	}
	if err := r.sendControl(NewDone()); err != nil {
		return err
	}
	r.settle(ReceiveResult{
		Files: append([]FileEntry(nil), r.manifest.Files...), Digests: append([]string(nil), r.digests...),
		TotalSize: r.manifest.TotalSize, File: r.manifest.Files[0], Digest: got,
	})
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
	if r.destination != nil {
		_ = r.destination.Abort(string(err.Reason))
	}
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

// manifestsEqual reports whether two validated manifests describe the same
// transfer: same id, same total size, and identical file entries.
func manifestsEqual(a, b *Manifest) bool {
	if a == nil || b == nil || a.TransferID != b.TransferID || a.TotalSize != b.TotalSize ||
		len(a.Files) != len(b.Files) {
		return false
	}
	for i := range a.Files {
		if a.Files[i] != b.Files[i] {
			return false
		}
	}
	return true
}
