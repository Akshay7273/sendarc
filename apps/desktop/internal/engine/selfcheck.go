package engine

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/wire"
)

// SelfCheckResult reports the outcome of an in-process engine self-check.
type SelfCheckResult struct {
	OK        bool   `json:"ok"`
	Phase     string `json:"phase"`
	Bytes     int64  `json:"bytes"`
	Files     int    `json:"files"`
	ElapsedMS int64  `json:"elapsedMs"`
	Failure   string `json:"failure,omitempty"`
}

// SelfCheck runs a complete transfer through the shared engine's public API:
// SPAKE2 rendezvous, encrypted relay path, durable receive, whole-file
// verification — all in-process over the loopback relay, no network. It is the
// desktop shell's proof that the bundled engine works end to end.
func (s *Service) SelfCheck() SelfCheckResult {
	start := time.Now()
	dir, err := os.MkdirTemp("", "sendbeam-selfcheck-*")
	if err != nil {
		return selfcheckFail(start, fmt.Sprintf("temp dir: %v", err))
	}
	defer func() { _ = os.RemoveAll(dir) }()

	// Deterministic payload crossing a 1 MiB block boundary.
	payload := make([]byte, 1<<20+40000)
	for i := range payload {
		payload[i] = byte(i*31 + 7)
	}
	srcPath := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(srcPath, payload, 0o600); err != nil {
		return selfcheckFail(start, fmt.Sprintf("source write: %v", err))
	}
	senderStore, err := transfer.OpenSenderStore(filepath.Join(dir, "sender"))
	if err != nil {
		return selfcheckFail(start, fmt.Sprintf("sender store: %v", err))
	}
	outDir := filepath.Join(dir, "out")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sendErr, recvErr := runLoopbackPair(ctx, senderStore, outDir, srcPath)

	files := 0
	var gotBytes int64
	if recvErr == nil {
		got, statErr := os.Stat(filepath.Join(outDir, "payload.bin"))
		if statErr == nil {
			files = 1
			gotBytes = got.Size()
		}
	}
	if sendErr != nil || recvErr != nil {
		why := "receiver"
		if sendErr != nil {
			why = "sender: " + sendErr.Error()
		}
		if recvErr != nil {
			why += "; receiver: " + recvErr.Error()
		}
		return selfcheckFail(start, why)
	}
	if !bytes.Equal(payload, mustRead(filepath.Join(outDir, "payload.bin"))) {
		return selfcheckFail(start, "received bytes differ from source")
	}
	return SelfCheckResult{
		OK:        true,
		Phase:     "verified",
		Bytes:     gotBytes,
		Files:     files,
		ElapsedMS: time.Since(start).Milliseconds(),
	}
}

// runLoopbackPair runs one forced-relay send+receive pair through transfer.Run
// over the loopback relay, mirroring the CLI's consumption of the engine.
func runLoopbackPair(ctx context.Context, senderStore *transfer.SenderStore, outDir, srcPath string) (sendErr, recvErr error) {
	sources, _, err := transfer.NewOSFileSources([]string{srcPath})
	if err != nil {
		return err, nil
	}
	id, onManifest, _, err := transfer.PrepareSender(senderStore, []string{srcPath}, sources)
	if err != nil {
		return err, nil
	}
	hub := newLoopbackRelay()
	defer hub.off.Close()
	defer hub.join.Close()

	sendDone := make(chan error, 1)
	recvDone := make(chan error, 1)
	go func() {
		_, err := transfer.Run(ctx, hub.off, transfer.Spec{
			Session:        rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "alpha-bravo"},
			Sources:        sources,
			TransferID:     id,
			OnSendManifest: onManifest,
			OnResumeCredential: func(_ wire.Manifest, _ []byte) error {
				return nil
			},
			ForceRelay: true,
			ICEServers: []webrtc.ICEServer{},
		})
		sendDone <- err
	}()
	go func() {
		_, err := transfer.Run(ctx, hub.join, transfer.Spec{
			Session:    rendezvous.Options{Role: rendezvous.RoleJoiner, Code: "7-alpha-bravo"},
			DestDir:    outDir,
			ForceRelay: true,
			ICEServers: []webrtc.ICEServer{},
		})
		recvDone <- err
	}()

	select {
	case e := <-sendDone:
		sendErr = e
		recvErr = <-recvDone
	case e := <-recvDone:
		recvErr = e
		sendErr = <-sendDone
	}
	return sendErr, recvErr
}

func selfcheckFail(start time.Time, why string) SelfCheckResult {
	return SelfCheckResult{OK: false, Phase: "failed", Failure: why, ElapsedMS: time.Since(start).Milliseconds()}
}

func mustRead(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return b
}
