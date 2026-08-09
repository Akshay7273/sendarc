package wire

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// senderFrames builds sender-side (o2j) frames the way the real Sender would, for driving a
// Receiver under test. ctr advances one seal counter per frame.
type senderFrames struct {
	t      *testing.T
	keys   TransferKeys
	ctr    uint64
	frames [][]byte
}

func newSenderFrames(t *testing.T, keys TransferKeys) *senderFrames {
	return &senderFrames{t: t, keys: keys}
}

func (s *senderFrames) push(h FrameHeaderInput, payload []byte) {
	f, err := Seal(s.keys.O2J, s.ctr, h, payload)
	if err != nil {
		s.t.Fatalf("seal: %v", err)
	}
	s.ctr++
	s.frames = append(s.frames, f)
}

func (s *senderFrames) ctrl(msg ControlMsg) {
	payload, err := EncodeControl(msg)
	if err != nil {
		s.t.Fatalf("encode: %v", err)
	}
	s.push(FrameHeaderInput{Version: FrameVersion, Type: msg.FrameType()}, payload)
}

// blockData splits data into frames of frameSize, tagging each with its block/offset and the
// last-in-block flag, followed by the block's block_hash — the sender's on-wire grammar.
func (s *senderFrames) blockData(data []byte, blockSize, frameSize int) {
	for blk := 0; blk*blockSize < len(data); blk++ {
		start := blk * blockSize
		end := start + blockSize
		if end > len(data) {
			end = len(data)
		}
		block := data[start:end]
		for off := 0; off < len(block); off += frameSize {
			fe := off + frameSize
			if fe > len(block) {
				fe = len(block)
			}
			frag := block[off:fe]
			flags := uint8(0)
			if off+len(frag) == len(block) {
				flags = FrameFlagLastInBlock
			}
			s.push(FrameHeaderInput{
				Version: FrameVersion, Type: FrameBlockData, Flags: flags,
				BlockIdx: uint32(blk), FrameOff: uint32(off),
			}, frag)
		}
		sum := sha256.Sum256(block)
		s.ctrl(NewBlockHash(0, blk, hex.EncodeToString(sum[:])))
	}
}

func (s *senderFrames) oneBlock(blockIdx int, block []byte, frameSize int) {
	for off := 0; off < len(block); off += frameSize {
		end := off + frameSize
		if end > len(block) {
			end = len(block)
		}
		flags := uint8(0)
		if end == len(block) {
			flags = FrameFlagLastInBlock
		}
		s.push(FrameHeaderInput{
			Version: FrameVersion, Type: FrameBlockData, Flags: flags,
			BlockIdx: uint32(blockIdx), FrameOff: uint32(off),
		}, block[off:end])
	}
	s.ctrl(NewBlockHash(0, blockIdx, hexSHA256(block)))
}

func hexSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestReceiverAssemblesVerifiesWritesDone(t *testing.T) {
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 20)
	for i := range data {
		data[i] = byte((i * 7) & 0xff) // block=8: blocks 0,1 (8B), block2 (4B)
	}
	const blockSize, frameSize = 8, 4
	fileDigest := hexSHA256(data)

	sf := newSenderFrames(t, keys)
	sf.ctrl(NewManifest([]FileEntry{{
		Idx: 0, Name: "f", Size: 20, BlockSize: blockSize, Blocks: 3, FileDigest: fileDigest,
	}}, 20))
	sf.blockData(data, blockSize, frameSize)
	sf.ctrl(NewComplete(fileDigest))

	sink := &MemorySink{}
	var back outbox
	r := NewReceiver(ReceiverOptions{
		Send: back.push, SendDir: keys.J2O, RecvDir: keys.O2J, Sink: sink,
	})
	for _, f := range sf.frames {
		r.Handle(f)
	}
	res, err := r.Wait(context.Background())
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if res.Digest != fileDigest {
		t.Errorf("digest = %s, want %s", res.Digest, fileDigest)
	}
	if string(sink.Bytes()) != string(data) {
		t.Errorf("sink bytes = %v, want %v", sink.Bytes(), data)
	}
	if !sink.IsClosed() {
		t.Error("sink not closed on done")
	}

	// Back-channel: verified ACK ×3 then done.
	wantBack := []uint8{FrameAck, FrameAck, FrameAck, FrameDone}
	got := back.snapshot()
	if len(got) != len(wantBack) {
		t.Fatalf("back-channel has %d frames, want %d", len(got), len(wantBack))
	}
	for i, f := range got {
		o, err := Open(keys.J2O, uint64(i), f)
		if err != nil {
			t.Fatalf("open back frame %d: %v", i, err)
		}
		if o.Header.Type != wantBack[i] {
			t.Errorf("back frame %d type = %d, want %d", i, o.Header.Type, wantBack[i])
		}
	}
}

func TestReceiverAbortsIntegrityOnCorruptFrame(t *testing.T) {
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	data := seq(8)
	fileDigest := hexSHA256(data)
	sf := newSenderFrames(t, keys)
	sf.ctrl(NewManifest([]FileEntry{{
		Idx: 0, Name: "f", Size: 8, BlockSize: 8, Blocks: 1, FileDigest: fileDigest,
	}}, 8))
	sf.push(FrameHeaderInput{Version: FrameVersion, Type: FrameBlockData, Flags: FrameFlagLastInBlock}, data)
	// Corrupt the GCM tag of the last frame.
	last := sf.frames[len(sf.frames)-1]
	last[len(last)-1] ^= 0x01

	sink := &MemorySink{}
	var back outbox
	r := NewReceiver(ReceiverOptions{
		Send: back.push, SendDir: keys.J2O, RecvDir: keys.O2J, Sink: sink,
	})
	for _, f := range sf.frames {
		r.Handle(f)
	}
	_, err = r.Wait(context.Background())
	if err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("Wait error = %v, want one mentioning integrity", err)
	}
	if sink.AbortReason() != "integrity" {
		t.Errorf("sink abort reason = %q, want integrity", sink.AbortReason())
	}
	frames := back.snapshot()
	if len(frames) != 1 {
		t.Fatalf("back-channel has %d frames, want one terminal fail", len(frames))
	}
	opened, openErr := Open(keys.J2O, 0, frames[0])
	if openErr != nil {
		t.Fatal(openErr)
	}
	if opened.Header.Type != FrameFail {
		t.Fatalf("corruption response type = %d, want fail", opened.Header.Type)
	}
}

// recordingSink records the order of its calls so a test can assert onManifest ran first.
type recordingSink struct{ events *[]string }

func (s recordingSink) Write(int64, []byte) error { *s.events = append(*s.events, "write"); return nil }
func (s recordingSink) Close() error              { return nil }
func (s recordingSink) Abort(string) error        { return nil }

func TestReceiverOnManifestBeforeFirstWrite(t *testing.T) {
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	data := seq(8)
	fileDigest := hexSHA256(data)
	sf := newSenderFrames(t, keys)
	sf.ctrl(NewManifest([]FileEntry{{
		Idx: 0, Name: "note.txt", Size: 8, Mime: "text/plain", BlockSize: 8, Blocks: 1, FileDigest: fileDigest,
	}}, 8))
	sf.push(FrameHeaderInput{Version: FrameVersion, Type: FrameBlockData, Flags: FrameFlagLastInBlock}, data)
	sf.ctrl(NewBlockHash(0, 0, fileDigest))
	sf.ctrl(NewComplete(fileDigest))

	var events []string
	var seen []string
	r := NewReceiver(ReceiverOptions{
		Send: func([]byte) error { return nil }, SendDir: keys.J2O, RecvDir: keys.O2J,
		Sink: recordingSink{events: &events},
		OnManifest: func(f FileEntry) error {
			events = append(events, "manifest")
			seen = append(seen, f.Name)
			return nil
		},
	})
	for _, f := range sf.frames {
		r.Handle(f)
	}
	if _, err := r.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if len(seen) != 1 || seen[0] != "note.txt" {
		t.Errorf("onManifest saw %v, want [note.txt]", seen)
	}
	if len(events) == 0 || events[0] != "manifest" {
		t.Fatalf("first event = %v, want manifest first", events)
	}
	if idxOf(events, "manifest") >= idxOf(events, "write") {
		t.Errorf("manifest did not precede write: %v", events)
	}
}

func TestReceiverFailsDigestMismatch(t *testing.T) {
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	data := seq(8)
	sf := newSenderFrames(t, keys)
	sf.ctrl(NewManifest([]FileEntry{{
		Idx: 0, Name: "f", Size: 8, BlockSize: 8, Blocks: 1, FileDigest: "ff",
	}}, 8))
	sf.push(FrameHeaderInput{Version: FrameVersion, Type: FrameBlockData, Flags: FrameFlagLastInBlock}, data)
	sf.ctrl(NewBlockHash(0, 0, hexSHA256(data)))
	sf.ctrl(NewComplete("deadbeef"))

	r := NewReceiver(ReceiverOptions{
		Send: func([]byte) error { return nil }, SendDir: keys.J2O, RecvDir: keys.O2J, Sink: &MemorySink{},
	})
	for _, f := range sf.frames {
		r.Handle(f)
	}
	_, err = r.Wait(context.Background())
	if err == nil || !strings.Contains(err.Error(), "digest_mismatch") {
		t.Fatalf("Wait error = %v, want one mentioning digest_mismatch", err)
	}
}

func TestReceiverRequestsMissingAndRecoversReorderedBlocks(t *testing.T) {
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	first := []byte{1, 2, 3, 4}
	second := []byte{5, 6, 7, 8}
	data := append(append([]byte(nil), first...), second...)
	fileDigest := hexSHA256(data)

	sf := newSenderFrames(t, keys)
	sf.ctrl(NewManifest([]FileEntry{{
		Idx: 0, Name: "reordered.bin", Size: int64(len(data)), BlockSize: 4,
		Blocks: 2, FileDigest: fileDigest,
	}}, int64(len(data))))
	// A transport transition exposes block 1 first. It is authenticated but not committed;
	// the requested sequence then arrives under fresh counters.
	sf.oneBlock(1, second, 4)
	sf.oneBlock(0, first, 4)
	sf.oneBlock(1, second, 4)
	sf.ctrl(NewComplete(fileDigest))

	sink := &MemorySink{}
	var back outbox
	r := NewReceiver(ReceiverOptions{
		Send: back.push, SendDir: keys.J2O, RecvDir: keys.O2J, Sink: sink,
	})
	for _, frame := range sf.frames {
		r.Handle(frame)
	}
	result, err := r.Wait(context.Background())
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if result.Digest != fileDigest || string(sink.Bytes()) != string(data) {
		t.Fatalf("recovered result digest=%s bytes=%v", result.Digest, sink.Bytes())
	}

	want := []ControlMsg{
		NewNack(0, 0, NackMissing),
		NewAck(0, 0),
		NewNack(0, 1, NackMissing),
		NewAck(0, 1),
		NewDone(),
	}
	frames := back.snapshot()
	if len(frames) != len(want) {
		t.Fatalf("back-channel has %d frames, want %d", len(frames), len(want))
	}
	for i, frame := range frames {
		opened, openErr := Open(keys.J2O, uint64(i), frame)
		if openErr != nil {
			t.Fatalf("open back frame %d: %v", i, openErr)
		}
		got, decodeErr := DecodeControl(opened.Plaintext)
		if decodeErr != nil {
			t.Fatalf("decode back frame %d: %v", i, decodeErr)
		}
		gotJSON, _ := EncodeControl(got)
		wantJSON, _ := EncodeControl(want[i])
		if string(gotJSON) != string(wantJSON) {
			t.Errorf("back frame %d = %s, want %s", i, gotJSON, wantJSON)
		}
	}
}

func TestReceiverDiscardsPartialBlockAcrossTransportChange(t *testing.T) {
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	data := seq(8)
	fileDigest := hexSHA256(data)
	sf := newSenderFrames(t, keys)
	sf.ctrl(NewManifest([]FileEntry{{
		Idx: 0, Name: "switched.bin", Size: 8, BlockSize: 8, Blocks: 1, FileDigest: fileDigest,
	}}, 8))
	sf.push(FrameHeaderInput{
		Version: FrameVersion, Type: FrameBlockData, FileIdx: 0, BlockIdx: 0, FrameOff: 0,
	}, data[:4])
	partialEnd := len(sf.frames)
	sf.oneBlock(0, data, 8)
	sf.ctrl(NewComplete(fileDigest))

	sink := &MemorySink{}
	var back outbox
	r := NewReceiver(ReceiverOptions{
		Send: back.push, SendDir: keys.J2O, RecvDir: keys.O2J, Sink: sink,
	})
	for _, frame := range sf.frames[:partialEnd] {
		r.Handle(frame)
	}
	r.TransportChanged()
	for _, frame := range sf.frames[partialEnd:] {
		r.Handle(frame)
	}
	result, err := r.Wait(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Digest != fileDigest || !bytes.Equal(sink.Bytes(), data) {
		t.Fatalf("recovered digest=%s bytes=%v", result.Digest, sink.Bytes())
	}
}

func TestReceiverContextCancellationNotifiesPeer(t *testing.T) {
	keys, err := DeriveTransferKeys(senderMaster())
	if err != nil {
		t.Fatal(err)
	}
	var back outbox
	sink := &MemorySink{}
	r := NewReceiver(ReceiverOptions{
		Send: back.push, SendDir: keys.J2O, RecvDir: keys.O2J, Sink: sink,
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = r.Wait(ctx)
	if err == nil || !strings.Contains(err.Error(), string(FailCanceled)) {
		t.Fatalf("Wait error = %v, want canceled", err)
	}
	frames := back.snapshot()
	if len(frames) != 1 {
		t.Fatalf("back-channel has %d frames, want cancel control", len(frames))
	}
	opened, openErr := Open(keys.J2O, 0, frames[0])
	if openErr != nil {
		t.Fatal(openErr)
	}
	msg, decodeErr := DecodeControl(opened.Plaintext)
	control, ok := msg.(*Control)
	if decodeErr != nil || !ok || control.Op != ControlCancel {
		t.Fatalf("cancellation frame = %#v, err=%v", msg, decodeErr)
	}
}

func idxOf(xs []string, want string) int {
	for i, x := range xs {
		if x == want {
			return i
		}
	}
	return -1
}
