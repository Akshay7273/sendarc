package wire

// Re-chunk an arbitrary byte stream into block-aligned frame pieces (design §5.4, §6).
// Incoming chunk boundaries are irrelevant; output frames are frameSize bytes (a block's final
// frame may be smaller), each tagged with its block index, its offset within the block, and
// whether it is the block's last frame. Memory stays bounded to roughly one incoming chunk
// plus one frame — the whole file is never held. Go twin of transfer-chunker.ts.

// FramePiece is one frame's worth of file bytes, positioned within its block. Payload is a
// view valid only until ReChunk emits the next piece; copy it to retain.
type FramePiece struct {
	BlockIdx    int
	FrameOff    int // byte offset within the block
	Payload     []byte
	LastInBlock bool
}

// StreamFunc pushes a byte stream chunk by chunk; it is the shape of FileSource.Stream. It
// must return the first error its callback returns, and be re-callable for the two sender
// passes.
type StreamFunc func(fn func(chunk []byte) error) error

// ReChunk reads stream and calls emit once per block-aligned frame. A block boundary is never
// crossed by a frame. emit's error (or the stream's) aborts and is returned.
func ReChunk(stream StreamFunc, blockSize, frameSize int, emit func(FramePiece) error) error {
	pos := 0           // absolute file offset of the next byte to emit
	buf := []byte(nil) // unconsumed bytes, plus an already-consumed prefix up to start
	start := 0         // consumed-prefix cursor into buf

	avail := func() int { return len(buf) - start }
	// A frame is capped at the block's remaining bytes so it never spans two blocks.
	targetLen := func() int {
		rem := blockSize - (pos % blockSize)
		if frameSize < rem {
			return frameSize
		}
		return rem
	}
	emitPiece := func(t int) FramePiece {
		offsetInBlock := pos % blockSize
		blockIdx := pos / blockSize
		payload := buf[start : start+t]
		start += t
		pos += t
		return FramePiece{
			BlockIdx:    blockIdx,
			FrameOff:    offsetInBlock,
			Payload:     payload,
			LastInBlock: offsetInBlock+t == blockSize,
		}
	}

	if err := stream(func(chunk []byte) error {
		// Drop the consumed prefix before growing, keeping the retained tail small. A fresh
		// allocation means any payload view already emitted stays valid.
		tail := buf[start:]
		buf = make([]byte, 0, len(tail)+len(chunk))
		buf = append(buf, tail...)
		buf = append(buf, chunk...)
		start = 0
		for avail() >= targetLen() {
			if err := emit(emitPiece(targetLen())); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}

	// Flush the trailing partial frame — also the file's final, possibly-partial block.
	for avail() > 0 {
		t := targetLen()
		if a := avail(); a < t {
			t = a
		}
		piece := emitPiece(t)
		// At EOF the block is "last" whether it filled or the stream simply ended.
		if avail() == 0 {
			piece.LastInBlock = true
		}
		if err := emit(piece); err != nil {
			return err
		}
	}
	return nil
}
