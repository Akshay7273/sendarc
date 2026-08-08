package wire

import "testing"

// piece is a comparable snapshot of a FramePiece for table assertions.
type piece struct {
	block, off, plen int
	last             bool
	payload          string
}

// collect runs ReChunk over data delivered as the given chunk groups and records each piece.
func collect(t *testing.T, chunks [][]byte, block, frame int) []piece {
	t.Helper()
	stream := func(fn func([]byte) error) error {
		for _, c := range chunks {
			if err := fn(c); err != nil {
				return err
			}
		}
		return nil
	}
	var got []piece
	err := ReChunk(stream, block, frame, func(p FramePiece) error {
		got = append(got, piece{p.BlockIdx, p.FrameOff, len(p.Payload), p.LastInBlock, string(p.Payload)})
		return nil
	})
	if err != nil {
		t.Fatalf("ReChunk: %v", err)
	}
	return got
}

func seq(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func TestReChunkEmptyStream(t *testing.T) {
	if got := collect(t, nil, 8, 4); len(got) != 0 {
		t.Errorf("empty stream produced %d pieces, want 0", len(got))
	}
}

func TestReChunkSubFrameFile(t *testing.T) {
	got := collect(t, [][]byte{{1, 2, 3}}, 8, 4)
	want := []piece{{0, 0, 3, true, string([]byte{1, 2, 3})}}
	assertPieces(t, got, want)
}

func TestReChunkExactBlockMultiple(t *testing.T) {
	// block=8, frame=4, 16 bytes = 2 blocks × 2 frames, all full.
	got := collect(t, [][]byte{seq(16)}, 8, 4)
	wantShape := [][4]int{{0, 0, 4, 0}, {0, 4, 4, 1}, {1, 0, 4, 0}, {1, 4, 4, 1}}
	assertShape(t, got, wantShape)
	assertBytes(t, got, seq(16))
}

func TestReChunkAwkwardBoundaries(t *testing.T) {
	// Same 16 bytes delivered as 3+7+6 must produce output identical to one 16-byte chunk.
	d := seq(16)
	got := collect(t, [][]byte{d[0:3], d[3:10], d[10:16]}, 8, 4)
	wantShape := [][4]int{{0, 0, 4, 0}, {0, 4, 4, 1}, {1, 0, 4, 0}, {1, 4, 4, 1}}
	assertShape(t, got, wantShape)
	assertBytes(t, got, d)
}

func TestReChunkFinalPartialBlock(t *testing.T) {
	// block=8, frame=4, 10 bytes → block0 full (2 frames), block1 one 2-byte frame.
	got := collect(t, [][]byte{seq(10)}, 8, 4)
	assertShape(t, got, [][4]int{{0, 0, 4, 0}, {0, 4, 4, 1}, {1, 0, 2, 1}})
}

func TestReChunkFrameEqualsBlock(t *testing.T) {
	// block=8, frame=8, 20 bytes → 8, 8, 4; one frame per block, each the block's last.
	got := collect(t, [][]byte{seq(20)}, 8, 8)
	assertShape(t, got, [][4]int{{0, 0, 8, 1}, {1, 0, 8, 1}, {2, 0, 4, 1}})
}

func TestReChunkPropagatesEmitError(t *testing.T) {
	stream := func(fn func([]byte) error) error { return fn(seq(16)) }
	sentinel := NewTransferError(FailSinkError, "stop")
	calls := 0
	err := ReChunk(stream, 8, 4, func(FramePiece) error {
		calls++
		return sentinel
	})
	if err != sentinel {
		t.Errorf("ReChunk error = %v, want sentinel", err)
	}
	if calls != 1 {
		t.Errorf("kept emitting after error: %d calls, want 1", calls)
	}
}

func assertPieces(t *testing.T, got, want []piece) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d pieces, want %d: %+v", len(got), len(want), got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("piece %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// assertShape checks [blockIdx, frameOff, payloadLen, lastInBlock(0/1)] per piece.
func assertShape(t *testing.T, got []piece, want [][4]int) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d pieces, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		last := 0
		if got[i].last {
			last = 1
		}
		if got[i].block != w[0] || got[i].off != w[1] || got[i].plen != w[2] || last != w[3] {
			t.Errorf("piece %d = [%d %d %d %d], want %v",
				i, got[i].block, got[i].off, got[i].plen, last, w)
		}
	}
}

// assertBytes checks the concatenated payloads equal want.
func assertBytes(t *testing.T, got []piece, want []byte) {
	t.Helper()
	var all []byte
	for _, p := range got {
		all = append(all, []byte(p.payload)...)
	}
	if string(all) != string(want) {
		t.Errorf("reassembled bytes = %v, want %v", all, want)
	}
}
