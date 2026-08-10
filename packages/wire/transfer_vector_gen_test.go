package wire

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestGenerateTransferVector regenerates docs/test-vectors/transfer.json from the Go
// transfer engine. The generator drives a Sender and Receiver over two unbuffered
// channels with a priority pump, so the recorded frame sequence is deterministic:
// every byte in the file is exactly what the codec produced for these inputs.
//
// Run with GENERATE_VECTORS=1 to rewrite the committed vector:
//
//	cd packages/wire && GENERATE_VECTORS=1 go test -run TestGenerateTransferVector ./...
func TestGenerateTransferVector(t *testing.T) {
	if os.Getenv("GENERATE_VECTORS") != "1" {
		t.Skip("set GENERATE_VECTORS=1 to regenerate docs/test-vectors/transfer.json")
	}

	master := make([]byte, 32)
	for i := range master {
		master[i] = 0x42
	}
	keys, err := DeriveTransferKeys(master)
	if err != nil {
		t.Fatal(err)
	}

	const (
		blockSize = 32
		frameSize = 16
		window    = 2
	)
	data := make([]byte, 40)
	for i := range data {
		data[i] = byte((i*131 + 7) & 0xff)
	}

	type entry struct {
		dir  string
		note string
		hex  string
	}
	var log []entry

	s2r := make(chan []byte, 64)
	r2s := make(chan []byte, 64)
	cp := func(f []byte) []byte { return append([]byte(nil), f...) }

	name := func(dir string, f []byte) string {
		k := keys.O2J
		if dir == "r2s" {
			k = keys.J2O
		}
		op, err := OpenSequenced(k, 0, cp(f))
		if err != nil {
			return "?"
		}
		return fmt.Sprintf("type=%d", op.Header.Type)
	}

	sender := NewSender(SenderOptions{
		File:      BytesSource(data, FileMeta{Name: "hello.txt", Size: int64(len(data)), Mime: "text/plain", LastModified: 1}, 0),
		Send:      func(f []byte) error { s2r <- cp(f); return nil },
		SendDir:   keys.O2J,
		RecvDir:   keys.J2O,
		BlockSize: blockSize,
		FrameSize: frameSize,
		Window:    window,
	})
	sink := &MemorySink{}
	receiver := NewReceiver(ReceiverOptions{
		Send:    func(f []byte) error { r2s <- cp(f); return nil },
		SendDir: keys.J2O,
		RecvDir: keys.O2J,
		Sink:    sink,
	})

	runErrCh := make(chan error, 1)
	go func() { _, e := sender.Run(context.Background()); runErrCh <- e }()
	type recvResult struct {
		res ReceiveResult
		err error
	}
	recvCh := make(chan recvResult, 1)
	go func() {
		res, err := receiver.Wait(context.Background())
		recvCh <- recvResult{res, err}
	}()

	// Priority pump: drain sender→receiver first, then receiver→sender, recording every
	// frame byte-exactly. The pump is the ONLY consumer of both channels (unbuffered), so
	// each handoff is synchronous and the fixed priority makes the interleaving
	// deterministic.
pump:
	for {
		pumped := false
		select {
		case f := <-s2r:
			log = append(log, entry{"s2r", name("s2r", f), hex.EncodeToString(f)})
			receiver.Handle(f)
			pumped = true
		default:
		}
		select {
		case f := <-r2s:
			log = append(log, entry{"r2s", name("r2s", f), hex.EncodeToString(f)})
			sender.Handle(f)
			pumped = true
		default:
		}
		if !pumped {
			select {
			case err := <-runErrCh:
				if err != nil {
					t.Fatalf("sender: %v", err)
				}
				rr := <-recvCh
				if rr.err != nil {
					t.Fatalf("receiver: %v", rr.err)
				}
				break pump
			default:
				time.Sleep(time.Millisecond)
			}
		}
	}

	digest := sha256.Sum256(data)
	doc := TransferVector{
		Description: "Full sendarc/1 transfer vector produced by the Go transfer engine " +
			"(packages/wire). Replay the s2r frames into any receiver implementation and " +
			"expect the recorded r2s replies and the canonical SHA-256 below.",
		Master:    hex.EncodeToString(master),
		BlockSize: blockSize,
		FrameSize: frameSize,
		Window:    window,
		Keys: VectorKeys{
			O2J: VectorKey{Key: hex.EncodeToString(keys.O2J.Key), Salt: hex.EncodeToString(keys.O2J.Salt)},
			J2O: VectorKey{Key: hex.EncodeToString(keys.J2O.Key), Salt: hex.EncodeToString(keys.J2O.Salt)},
		},
		File: VectorFile{
			Name:   "hello.txt",
			Size:   int64(len(data)),
			Mime:   "text/plain",
			Hex:    hex.EncodeToString(data),
			Sha256: hex.EncodeToString(digest[:]),
		},
		WireLog: make([]VectorFrame, 0, len(log)),
	}
	for _, e := range log {
		doc.WireLog = append(doc.WireLog, VectorFrame{Dir: e.dir, Note: e.note, Hex: e.hex})
	}

	path := filepath.Join("..", "..", "docs", "test-vectors", "transfer.json")
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s", path)
}
