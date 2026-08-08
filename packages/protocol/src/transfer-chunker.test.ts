import { describe, it, expect } from 'vitest';
import { reChunk } from './transfer-chunker.js';

async function* fromChunks(chunks: number[][]): AsyncGenerator<Uint8Array> {
  for (const c of chunks) yield new Uint8Array(c);
}
async function collect(stream: AsyncIterable<Uint8Array>, block: number, frame: number) {
  const pieces: Array<{
    blockIdx: number;
    frameOff: number;
    payload: number[];
    lastInBlock: boolean;
  }> = [];
  for await (const p of reChunk(stream, block, frame)) {
    pieces.push({
      blockIdx: p.blockIdx,
      frameOff: p.frameOff,
      payload: [...p.payload],
      lastInBlock: p.lastInBlock,
    });
  }
  return pieces;
}

describe('reChunk', () => {
  it('yields nothing for a 0-byte stream', async () => {
    expect(await collect(fromChunks([]), 8, 4)).toEqual([]);
  });

  it('emits one small last frame for a sub-frame file', async () => {
    const pieces = await collect(fromChunks([[1, 2, 3]]), 8, 4);
    expect(pieces).toEqual([{ blockIdx: 0, frameOff: 0, payload: [1, 2, 3], lastInBlock: true }]);
  });

  it('splits an exact block-multiple across full frames, flagging block ends', async () => {
    // block=8, frame=4, 16 bytes = 2 blocks × 2 frames, all full.
    const data = Array.from({ length: 16 }, (_, i) => i);
    const pieces = await collect(fromChunks([data]), 8, 4);
    expect(pieces.map((p) => [p.blockIdx, p.frameOff, p.lastInBlock])).toEqual([
      [0, 0, false],
      [0, 4, true],
      [1, 0, false],
      [1, 4, true],
    ]);
    expect(pieces.flatMap((p) => p.payload)).toEqual(data);
  });

  it('re-chunks awkward input boundaries into aligned frames', async () => {
    // Same 16 bytes delivered as 3+7+6 — output must be identical to one 16-byte chunk.
    const data = Array.from({ length: 16 }, (_, i) => i);
    const pieces = await collect(
      fromChunks([
        [0, 1, 2],
        [3, 4, 5, 6, 7, 8, 9],
        [10, 11, 12, 13, 14, 15],
      ]),
      8,
      4,
    );
    expect(pieces.map((p) => [p.blockIdx, p.frameOff, p.lastInBlock])).toEqual([
      [0, 0, false],
      [0, 4, true],
      [1, 0, false],
      [1, 4, true],
    ]);
    expect(pieces.flatMap((p) => p.payload)).toEqual(data);
  });

  it('handles a final partial block (tail smaller than a block)', async () => {
    // block=8, frame=4, 10 bytes → block0 full (2 frames), block1 has one 2-byte frame.
    const data = Array.from({ length: 10 }, (_, i) => i);
    const pieces = await collect(fromChunks([data]), 8, 4);
    expect(pieces.map((p) => [p.blockIdx, p.frameOff, p.payload.length, p.lastInBlock])).toEqual([
      [0, 0, 4, false],
      [0, 4, 4, true],
      [1, 0, 2, true],
    ]);
  });

  it('frame equal to block yields one frame per block', async () => {
    const data = Array.from({ length: 20 }, (_, i) => i); // block=8: 8,8,4
    const pieces = await collect(fromChunks([data]), 8, 8);
    expect(pieces.map((p) => [p.blockIdx, p.frameOff, p.payload.length, p.lastInBlock])).toEqual([
      [0, 0, 8, true],
      [1, 0, 8, true],
      [2, 0, 4, true],
    ]);
  });
});
