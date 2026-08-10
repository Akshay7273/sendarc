package wire

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TransferVector is the committed full-transfer vector (docs/test-vectors/transfer.json):
// keys derived from a fixed master, one 40-byte file, and the byte-exact wire frames the
// engine exchanged for it. An independent implementation can replay WireLog s2r frames
// through its receiver and must produce the same r2s replies, the same file bytes, and
// the same SHA-256.
type TransferVector struct {
	Description string        `json:"description"`
	Master      string        `json:"master"`
	BlockSize   int           `json:"blockSize"`
	FrameSize   int           `json:"frameSize"`
	Window      int           `json:"window"`
	Keys        VectorKeys    `json:"keys"`
	File        VectorFile    `json:"file"`
	WireLog     []VectorFrame `json:"wireLog"`
}

type VectorKeys struct {
	O2J VectorKey `json:"o2j"`
	J2O VectorKey `json:"j2o"`
}

type VectorKey struct {
	Key  string `json:"key"`
	Salt string `json:"salt"`
}

type VectorFile struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Mime   string `json:"mime"`
	Hex    string `json:"hex"`
	Sha256 string `json:"sha256"`
}

type VectorFrame struct {
	Dir  string `json:"dir"`
	Note string `json:"note"`
	Hex  string `json:"hex"`
}

func loadTransferVector(t *testing.T) TransferVector {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "test-vectors", "transfer.json"))
	if err != nil {
		t.Fatalf("read transfer.json: %v", err)
	}
	var v TransferVector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse transfer.json: %v", err)
	}
	return v
}

// TestTransferVectorReplays validates the committed transfer vector by replaying the
// recorded frames through a fresh receiver: the receiver must emit byte-identical replies,
// reconstruct the exact file bytes, and verify the canonical digest. The vector is also
// the oracle any independent implementation can check against.
func TestTransferVectorReplays(t *testing.T) {
	v := loadTransferVector(t)

	master, err := hex.DecodeString(v.Master)
	if err != nil {
		t.Fatalf("master hex: %v", err)
	}
	keys, err := DeriveTransferKeys(master)
	if err != nil {
		t.Fatal(err)
	}
	o2j := DirectionalKey{Key: mustHex(t, v.Keys.O2J.Key), Salt: mustHex(t, v.Keys.O2J.Salt)}
	j2o := DirectionalKey{Key: mustHex(t, v.Keys.J2O.Key), Salt: mustHex(t, v.Keys.J2O.Salt)}
	if !bytes.Equal(keys.O2J.Key, o2j.Key) || !bytes.Equal(keys.O2J.Salt, o2j.Salt) ||
		!bytes.Equal(keys.J2O.Key, j2o.Key) || !bytes.Equal(keys.J2O.Salt, j2o.Salt) {
		t.Fatal("recorded keys do not derive from the recorded master (key schedule drift)")
	}

	wantBytes, err := hex.DecodeString(v.File.Hex)
	if err != nil {
		t.Fatalf("file hex: %v", err)
	}
	if int64(len(wantBytes)) != v.File.Size {
		t.Fatalf("file hex length %d != recorded size %d", len(wantBytes), v.File.Size)
	}
	sum := sha256.Sum256(wantBytes)
	if hex.EncodeToString(sum[:]) != v.File.Sha256 {
		t.Fatalf("recorded file does not hash to its recorded digest")
	}

	sink := &MemorySink{}
	var gotReplies []string
	receiver := NewReceiver(ReceiverOptions{
		Send: func(f []byte) error {
			gotReplies = append(gotReplies, hex.EncodeToString(f))
			return nil
		},
		SendDir: j2o,
		RecvDir: o2j,
		Sink:    sink,
	})

	var s2rCount int
	for _, fr := range v.WireLog {
		switch fr.Dir {
		case "s2r":
			frame, err := hex.DecodeString(fr.Hex)
			if err != nil {
				t.Fatalf("frame %d hex: %v", s2rCount, err)
			}
			receiver.Handle(frame)
			s2rCount++
		case "r2s":
			// The receiver's own replies are asserted below, byte-for-byte.
		default:
			t.Fatalf("unknown frame direction %q", fr.Dir)
		}
	}

	wantReplies := make([]string, 0, len(v.WireLog))
	for _, fr := range v.WireLog {
		if fr.Dir == "r2s" {
			wantReplies = append(wantReplies, fr.Hex)
		}
	}
	if len(gotReplies) != len(wantReplies) {
		t.Fatalf("receiver replied %d frames, vector records %d", len(gotReplies), len(wantReplies))
	}
	for i := range gotReplies {
		if gotReplies[i] != wantReplies[i] {
			t.Errorf("reply frame %d diverges:\n got %s\nwant %s", i, gotReplies[i], wantReplies[i])
		}
	}

	if !bytes.Equal(sink.Bytes(), wantBytes) {
		t.Fatalf("reconstructed file differs from the vector bytes")
	}
	res, err := receiver.Wait(context.Background())
	if err != nil {
		t.Fatalf("receiver: %v", err)
	}
	if res.Digest != v.File.Sha256 {
		t.Errorf("receiver digest = %s, vector digest = %s", res.Digest, v.File.Sha256)
	}
}
