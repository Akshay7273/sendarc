package wire

import (
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// fixedSeeds are the seeds every CI run exercises; a failure at seed N is
// reproduced locally with -run TestFaultRandomizedFailClosed (SB-1127).
var fixedSeeds = []int64{11, 22, 33, 44, 55, 66, 77, 88}

// TestFaultRandomizedFailClosed pins the fail-closed contract under every
// randomized fault mix: a transfer either completes with the exact source
// bytes, or fails on at least one side with the sink never committed. Silent
// corruption is never acceptable.
func TestFaultRandomizedFailClosed(t *testing.T) {
	for _, seed := range fixedSeeds {
		for _, destructive := range []bool{false, true} {
			size := 16_000 + int(seed%97)*64
			data := testData(size, byte(seed))
			res := runFaultLoopback(t, data, 1024, 256, 4, faultScript{}, rand.New(rand.NewSource(seed)),
				faultRunOptions{ackTimeout: 120 * time.Millisecond, maxRetries: 3, deadline: 3 * time.Second, benignOnly: !destructive})
			if res.runErr == nil && res.recvErr == nil {
				res.wantSuccess(t, data)
			} else {
				if res.recvSettled {
					t.Fatalf("seed %d destructive=%v: receiver settled on a failed transfer", seed, destructive)
				}
				if res.sink.AbortReason() == "" {
					t.Fatalf("seed %d destructive=%v: failed transfer left committed output", seed, destructive)
				}
			}
		}
	}
}

// faultFixture is one recorded regression scenario (SB-1128). Want is
// "success" or "fail_closed".
type faultFixture struct {
	Seed        int64  `json:"seed"`
	Size        int    `json:"size"`
	BlockSize   int    `json:"blockSize"`
	FrameSize   int    `json:"frameSize"`
	Window      int    `json:"window"`
	AckTimeout  int    `json:"ackTimeoutMs"`
	MaxRetries  int    `json:"maxRetries"`
	Destructive bool   `json:"destructive"`
	Want        string `json:"want"`
}

// TestFaultSeededRegressionFixtures replays every stored seed so a seed that
// once exposed a bug stays pinned to its recorded outcome.
func TestFaultSeededRegressionFixtures(t *testing.T) {
	path := filepath.Join("testdata", "fault-seeds", "regression.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []faultFixture
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	if len(fixtures) == 0 {
		t.Fatal("no regression fixtures recorded")
	}
	for _, fx := range fixtures {
		fx := fx
		t.Run(fx.name(), func(t *testing.T) {
			data := testData(fx.Size, byte(fx.Seed))
			res := runFaultLoopback(t, data, fx.BlockSize, fx.FrameSize, fx.Window, faultScript{}, rand.New(rand.NewSource(fx.Seed)),
				faultRunOptions{
					ackTimeout: time.Duration(fx.AckTimeout) * time.Millisecond,
					maxRetries: fx.MaxRetries,
					deadline:   3 * time.Second,
					benignOnly: !fx.Destructive,
				})
			succeeded := res.runErr == nil && res.recvErr == nil
			if fx.Want == "success" {
				if !succeeded {
					t.Fatalf("fixture %s regressed: expected success, got runErr=%v recvErr=%v", fx.name(), res.runErr, res.recvErr)
				}
				res.wantSuccess(t, data)
			} else {
				if succeeded {
					t.Fatalf("fixture %s regressed: expected fail_closed, transfer succeeded", fx.name())
				}
				if res.recvSettled {
					t.Fatalf("fixture %s: receiver settled on a failed transfer", fx.name())
				}
				if res.sink.AbortReason() == "" {
					t.Fatalf("fixture %s: failed transfer left committed output", fx.name())
				}
			}
		})
	}
}

func (f faultFixture) name() string {
	mode := "benign"
	if f.Destructive {
		mode = "destructive"
	}
	return "seed-" + strconv.FormatInt(f.Seed, 10) + "-" + mode
}
