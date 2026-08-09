package wire

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

// loopbackMaster is the fixed master key the loopback derives both directions from.
func loopbackMaster() []byte {
	m := make([]byte, 32)
	for i := range m {
		m[i] = 3
	}
	return m
}

type loopbackResult struct {
	runErr  error
	recvRes ReceiveResult
	recvErr error
	sink    *MemorySink
}

// runLoopback wires a Sender (offerer, o2j) to a Receiver (joiner) over two buffered channels,
// each drained by its own goroutine so delivery is ordered and genuinely concurrent — the same
// shape as a real reliable, ordered DataChannel. When corrupt is set, one byte of the second
// frame the sender emits is flipped in flight, forcing an integrity abort.
func runLoopback(t *testing.T, data []byte, blockSize, frameSize, window int, corrupt bool) loopbackResult {
	t.Helper()
	keys, err := DeriveTransferKeys(loopbackMaster())
	if err != nil {
		t.Fatal(err)
	}
	sink := &MemorySink{}

	// Buffers comfortably exceed the window's in-flight frames so no send blocks; the window
	// gate, not the buffer, is what bounds the sender.
	s2r := make(chan []byte, 4096)
	r2s := make(chan []byte, 4096)
	cp := func(f []byte) []byte { return append([]byte(nil), f...) }

	var sentCount int64
	senderSend := func(f []byte) error {
		if corrupt && atomic.AddInt64(&sentCount, 1) == 2 {
			f = cp(f)
			f[len(f)-1] ^= 0x01
		}
		s2r <- cp(f)
		return nil
	}

	sender := NewSender(SenderOptions{
		File:      BytesSource(data, FileMeta{Name: "f", Size: int64(len(data)), Mime: "application/octet-stream", LastModified: 1}, 0),
		Send:      senderSend,
		SendDir:   keys.O2J,
		RecvDir:   keys.J2O,
		BlockSize: blockSize,
		FrameSize: frameSize,
		Window:    window,
	})
	receiver := NewReceiver(ReceiverOptions{
		Send:    func(f []byte) error { r2s <- cp(f); return nil },
		SendDir: keys.J2O,
		RecvDir: keys.O2J,
		Sink:    sink,
	})

	go func() {
		for f := range s2r {
			receiver.Handle(f)
		}
	}()
	go func() {
		for f := range r2s {
			sender.Handle(f)
		}
	}()

	runErrCh := make(chan error, 1)
	go func() { _, e := sender.Run(context.Background()); runErrCh <- e }()

	recvRes, recvErr := receiver.Wait(context.Background())
	var runErr error
	select {
	case runErr = <-runErrCh:
	case <-time.After(5 * time.Second):
		t.Fatal("sender.Run did not return after the receiver settled")
	}
	close(s2r)
	close(r2s)
	return loopbackResult{runErr: runErr, recvRes: recvRes, recvErr: recvErr, sink: sink}
}

func TestLoopbackStreamsVariousSizes(t *testing.T) {
	sizes := []int{0, 1, 7, 8, 20, 4096, 100_000}
	for _, size := range sizes {
		size := size
		t.Run(fmt.Sprintf("%d_bytes", size), func(t *testing.T) {
			data := make([]byte, size)
			for i := range data {
				data[i] = byte((i*131 + 7) & 0xff)
			}
			res := runLoopback(t, data, 1024, 256, 4, false)
			if res.runErr != nil {
				t.Fatalf("sender: %v", res.runErr)
			}
			if res.recvErr != nil {
				t.Fatalf("receiver: %v", res.recvErr)
			}
			if string(res.sink.Bytes()) != string(data) {
				t.Fatalf("received bytes differ from source (%d bytes)", size)
			}
			want := sha256.Sum256(data)
			if res.recvRes.Digest != hex.EncodeToString(want[:]) {
				t.Errorf("digest = %s, want %s", res.recvRes.Digest, hex.EncodeToString(want[:]))
			}
		})
	}
}

// runResumeLoopback wires a resumable sender to a reloaded receiver whose sink and digest are
// pre-seeded with the first haveBlocks blocks, mirroring a real reload from durable storage.
func runResumeLoopback(t *testing.T, data []byte, blockSize, haveBlocks int, senderID, resumeID string) (loopbackResult, int) {
	t.Helper()
	keys, err := DeriveTransferKeys(loopbackMaster())
	if err != nil {
		t.Fatal(err)
	}
	prefix := haveBlocks * blockSize
	if prefix > len(data) {
		prefix = len(data)
	}
	sink := &MemorySink{}
	if resumeID == senderID && prefix > 0 {
		_ = sink.Write(0, data[:prefix])
	}
	seed := NewSHA256Digest()
	if resumeID == senderID {
		seed.Update(data[:prefix])
	}

	s2r := make(chan []byte, 4096)
	r2s := make(chan []byte, 4096)
	cp := func(f []byte) []byte { return append([]byte(nil), f...) }

	sender := NewSender(SenderOptions{
		File:       BytesSource(data, FileMeta{Name: "f", Size: int64(len(data)), Mime: "application/octet-stream", LastModified: 1}, 0),
		Send:       func(f []byte) error { s2r <- cp(f); return nil },
		SendDir:    keys.O2J,
		RecvDir:    keys.J2O,
		BlockSize:  blockSize,
		FrameSize:  256,
		Window:     4,
		TransferID: senderID,
	})
	var commits int
	receiver := NewReceiver(ReceiverOptions{
		Send:       func(f []byte) error { r2s <- cp(f); return nil },
		SendDir:    keys.J2O,
		RecvDir:    keys.O2J,
		Sink:       sink,
		OnProgress: func(int64) { commits++ },
		Resume: &ReceiverResume{
			TransferID: resumeID,
			Files:      map[int]ResumeFileProgress{0: {HaveBlocks: haveBlocks, SeedDigest: seed}},
		},
	})

	go func() {
		for f := range s2r {
			receiver.Handle(f)
		}
	}()
	go func() {
		for f := range r2s {
			sender.Handle(f)
		}
	}()
	runErrCh := make(chan error, 1)
	go func() { _, e := sender.Run(context.Background()); runErrCh <- e }()
	recvRes, recvErr := receiver.Wait(context.Background())
	var runErr error
	select {
	case runErr = <-runErrCh:
	case <-time.After(5 * time.Second):
		t.Fatal("sender.Run did not return after the receiver settled")
	}
	close(s2r)
	close(r2s)
	return loopbackResult{runErr: runErr, recvRes: recvRes, recvErr: recvErr, sink: sink}, commits
}

func TestLoopbackResumesFromHighWaterMark(t *testing.T) {
	blockSize := 1024
	data := make([]byte, 100_000)
	for i := range data {
		data[i] = byte((i*131 + 7) & 0xff)
	}
	blocks := (len(data)-1)/blockSize + 1
	haveBlocks := 10
	id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	res, commits := runResumeLoopback(t, data, blockSize, haveBlocks, id, id)
	if res.runErr != nil || res.recvErr != nil {
		t.Fatalf("send=%v receive=%v", res.runErr, res.recvErr)
	}
	if string(res.sink.Bytes()) != string(data) {
		t.Fatal("resumed transfer did not reassemble the full file")
	}
	want := sha256.Sum256(data)
	if res.recvRes.Digest != hex.EncodeToString(want[:]) {
		t.Errorf("digest = %s, want %s", res.recvRes.Digest, hex.EncodeToString(want[:]))
	}
	if commits != blocks-haveBlocks {
		t.Errorf("committed %d blocks, want %d (only the missing suffix)", commits, blocks-haveBlocks)
	}
}

func TestLoopbackIgnoresResumeOnTransferIDMismatch(t *testing.T) {
	blockSize := 1024
	data := make([]byte, 20_000)
	for i := range data {
		data[i] = byte((i*131 + 7) & 0xff)
	}
	blocks := (len(data)-1)/blockSize + 1

	// The seed carries a stale id, so the receiver must discard it and receive every block fresh.
	res, commits := runResumeLoopback(t, data, blockSize, 5, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if res.runErr != nil || res.recvErr != nil {
		t.Fatalf("send=%v receive=%v", res.runErr, res.recvErr)
	}
	if string(res.sink.Bytes()) != string(data) {
		t.Fatal("mismatched-resume transfer did not reassemble the full file")
	}
	if commits != blocks {
		t.Errorf("committed %d blocks, want %d (a full fresh receive)", commits, blocks)
	}
}

func TestLoopbackAbortsOnCorruptedFrame(t *testing.T) {
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i & 0xff)
	}
	res := runLoopback(t, data, 1024, 256, 4, true)
	if res.runErr == nil && res.recvErr == nil {
		t.Fatal("corrupted transfer settled cleanly; expected an abort on at least one side")
	}
	if res.sink.IsClosed() {
		t.Error("sink was closed despite a corrupted frame; it must not commit")
	}
}

type multiMemoryDestination struct {
	manifest Manifest
	sinks    map[string]*MemorySink
	closed   bool
}

func (d *multiMemoryDestination) Prepare(manifest Manifest) error {
	d.manifest = manifest
	d.sinks = make(map[string]*MemorySink, len(manifest.Files))
	return nil
}

func (d *multiMemoryDestination) Open(file FileEntry) (Sink, error) {
	sink := &MemorySink{}
	d.sinks[file.Name] = sink
	return sink, nil
}

func (d *multiMemoryDestination) Close() error { d.closed = true; return nil }

func (d *multiMemoryDestination) Abort(reason string) error {
	for _, sink := range d.sinks {
		_ = sink.Abort(reason)
	}
	return nil
}

func TestLoopbackStreamsNestedMultiFileSet(t *testing.T) {
	keys, err := DeriveTransferKeys(loopbackMaster())
	if err != nil {
		t.Fatal(err)
	}
	contents := [][]byte{{1, 2, 3}, {}, make([]byte, 3000)}
	for i := range contents[2] {
		contents[2][i] = byte(i & 0xff)
	}
	names := []string{"folder/a.bin", "folder/empty.txt", "b.bin"}
	sources := make([]FileSource, len(contents))
	var total int64
	for i, content := range contents {
		sources[i] = BytesSource(content, FileMeta{Name: names[i], Size: int64(len(content)), LastModified: 1}, 0)
		total += int64(len(content))
	}
	s2r := make(chan []byte, 4096)
	r2s := make(chan []byte, 4096)
	copyFrame := func(frame []byte) []byte { return append([]byte(nil), frame...) }
	destination := &multiMemoryDestination{}
	var progress int64
	sender := NewSender(SenderOptions{
		Files: sources, Send: func(frame []byte) error { s2r <- copyFrame(frame); return nil },
		SendDir: keys.O2J, RecvDir: keys.J2O, BlockSize: 1024, FrameSize: 256, Window: 2,
		OnProgress: func(bytes int64) { progress = bytes },
	})
	receiver := NewReceiver(ReceiverOptions{
		Send:    func(frame []byte) error { r2s <- copyFrame(frame); return nil },
		SendDir: keys.J2O, RecvDir: keys.O2J, Destination: destination,
	})
	go func() {
		for frame := range s2r {
			receiver.Handle(frame)
		}
	}()
	go func() {
		for frame := range r2s {
			sender.Handle(frame)
		}
	}()
	sendDone := make(chan struct {
		digest string
		err    error
	}, 1)
	go func() {
		digest, runErr := sender.Run(context.Background())
		sendDone <- struct {
			digest string
			err    error
		}{digest, runErr}
	}()
	received, recvErr := receiver.Wait(context.Background())
	sent := <-sendDone
	close(s2r)
	close(r2s)
	if sent.err != nil || recvErr != nil {
		t.Fatalf("send=%v receive=%v", sent.err, recvErr)
	}
	if sent.digest != received.Digest || progress != total || !destination.closed {
		t.Fatalf("digest/progress/commit mismatch: sent=%s received=%s progress=%d closed=%v",
			sent.digest, received.Digest, progress, destination.closed)
	}
	if len(received.Files) != len(contents) || len(received.Digests) != len(contents) {
		t.Fatalf("received %d files and %d digests", len(received.Files), len(received.Digests))
	}
	for i, name := range names {
		if got := destination.sinks[name].Bytes(); string(got) != string(contents[i]) {
			t.Errorf("%s differs", name)
		}
		want := sha256.Sum256(contents[i])
		if received.Digests[i] != hex.EncodeToString(want[:]) {
			t.Errorf("%s digest = %s", name, received.Digests[i])
		}
	}
}
