/**
 * Re-chunk an arbitrary byte stream into block-aligned frame pieces (design §5.4, §6).
 * Incoming chunk boundaries are irrelevant; output frames are `frameSize` bytes (the block's
 * final frame may be smaller), each tagged with its block index, its offset within the block,
 * and whether it is the block's last frame. Memory stays bounded to roughly one incoming
 * chunk plus one frame — the whole file is never held.
 */

import { concatBytes } from './bytes.js';

/** One frame's worth of file bytes, positioned within its block. */
export interface FramePiece {
  blockIdx: number;
  frameOff: number; // byte offset within the block
  payload: Uint8Array;
  lastInBlock: boolean;
}

export async function* reChunk(
  stream: AsyncIterable<Uint8Array>,
  blockSize: number,
  frameSize: number,
): AsyncGenerator<FramePiece> {
  let pos = 0; // absolute file offset of the next byte to emit
  let buf = new Uint8Array(0);
  let start = 0; // consumed-prefix cursor into buf

  const avail = () => buf.length - start;
  // A frame never crosses a block boundary; it is capped at the block's remaining bytes.
  const targetLen = () => Math.min(frameSize, blockSize - (pos % blockSize));

  const emit = (t: number): FramePiece => {
    const offsetInBlock = pos % blockSize;
    const blockIdx = Math.floor(pos / blockSize);
    const payload = buf.subarray(start, start + t);
    start += t;
    pos += t;
    return {
      blockIdx,
      frameOff: offsetInBlock,
      payload,
      lastInBlock: offsetInBlock + t === blockSize,
    };
  };

  for await (const chunk of stream) {
    // Drop the consumed prefix before growing the buffer, keeping the tail small.
    if (start > 0) buf = buf.subarray(start);
    start = 0;
    buf = concatBytes(buf, chunk);
    while (avail() >= targetLen()) {
      yield emit(targetLen());
    }
  }
  // Flush the trailing partial frame (also the file's final, possibly-partial block).
  while (avail() > 0) {
    const t = Math.min(targetLen(), avail());
    const piece = emit(t);
    // At EOF the block is "last" whether it filled or the stream simply ended.
    yield { ...piece, lastInBlock: piece.lastInBlock || avail() === 0 };
  }
}
