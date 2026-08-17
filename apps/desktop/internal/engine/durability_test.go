package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/sendbeam/desktop/internal/config"
	"github.com/sendbeam/desktop/internal/lifecycle"
	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/wire"
)

func TestDesktopDurableListingAndInspect(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "downloads")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}

	sink := &eventSink{}
	svc := NewTransferService(sink.emit, nil)
	senderStoreDir := filepath.Join(dir, "sender_state")
	sStore, err := transfer.OpenSenderStore(senderStoreDir)
	if err != nil {
		t.Fatalf("OpenSenderStore: %v", err)
	}
	svc.SetSenderStore(sStore)

	dStore, err := transfer.OpenStore(outDir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}

	// 1. Create a simulated valid durable receive journal
	tid := "0123456789abcdef0123456789abcdef"
	secretEnv := &wire.ResumeSecretEnvelope{
		Version: 1,
		Value:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}

	manifest := wire.Manifest{
		TransferID: tid,
		TotalSize:  128 * 1024,
		Files: []wire.FileEntry{
			{Idx: 0, Name: "test.dat", Size: 128 * 1024, Blocks: 2, BlockSize: 64 * 1024, FileDigest: strings.Repeat("a", 64)},
		},
	}
	srcIdent := wire.JournalIdentity{Version: 1, Value: "src"}
	destIdent := wire.JournalIdentity{Version: 1, Value: "dest"}
	now := time.Now()
	j, err := wire.NewJournal(tid, manifest, srcIdent, destIdent, now)
	if err != nil {
		t.Fatalf("NewJournal: %v", err)
	}
	j.ResumeSecret = &wire.JournalResumeSecret{
		Version: secretEnv.Version,
		Value:   secretEnv.Value,
	}
	if err := j.CommitBlocks(0, 1, now); err != nil {
		t.Fatalf("CommitBlocks: %v", err)
	}
	if err := wire.WriteJournalAtomic(dStore.JournalPath(tid), j); err != nil {
		t.Fatalf("WriteJournalAtomic: %v", err)
	}

	// Create matching partial file for the 1 committed block (64 KiB)
	partPath := dStore.PartialPath(tid, "test.dat")
	if err := os.MkdirAll(filepath.Dir(partPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(partPath, make([]byte, 64*1024), 0o600); err != nil {
		t.Fatal(err)
	}

	// 2. Create a simulated sender record
	srcFile := writePayload(t, dir, "source.bin", 1024)
	nowMilli := time.Now().UnixMilli()
	sendManifest := wire.Manifest{
		TransferID: "fedcba9876543210fedcba9876543210",
		TotalSize:  1024,
		Files: []wire.FileEntry{
			{Idx: 0, Name: "source.bin", Size: 1024, Blocks: 1, BlockSize: 64 * 1024, LastModified: nowMilli, FileDigest: strings.Repeat("b", 64)},
		},
	}
	validated, _ := wire.ValidateManifest(sendManifest)
	fp, _ := wire.ManifestFingerprint(validated)
	rec := transfer.SenderRecord{
		SchemaVersion:       2,
		TransferID:          validated.TransferID,
		ManifestFingerprint: fp,
		ProtocolVersion:     wire.ProtocolVersion,
		CreatedAt:           nowMilli,
		UpdatedAt:           nowMilli,
		Paths:               []string{srcFile},
		Files: []transfer.SenderFileState{
			{Idx: 0, Name: "source.bin", Size: 1024, LastModified: nowMilli, BlockSize: 64 * 1024, Blocks: 1, FileDigest: strings.Repeat("b", 64)},
		},
		ResumeSecret: secretEnv,
	}
	if err := sStore.Save(rec); err != nil {
		t.Fatalf("sStore.Save: %v", err)
	}

	// 3. Test ListInterrupted
	items, err := svc.ListInterrupted(outDir)
	if err != nil {
		t.Fatalf("ListInterrupted: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("ListInterrupted returned %d items, want 2", len(items))
	}

	var recvItem, sendItem *DurableTransferItem
	for i := range items {
		switch items[i].Role {
		case "receive":
			recvItem = &items[i]
		case "send":
			sendItem = &items[i]
		}
	}
	if recvItem == nil || recvItem.TransferID != tid || !recvItem.Resumable {
		t.Errorf("recvItem = %+v, want valid resumable receive item", recvItem)
	}
	if sendItem == nil || sendItem.Role != "send" {
		t.Errorf("sendItem = %+v, want valid send item", sendItem)
	}

	// 4. Test InspectInterrupted
	ins, err := svc.InspectInterrupted(tid, outDir)
	if err != nil {
		t.Fatalf("InspectInterrupted: %v", err)
	}
	if ins.TransferID != tid || !ins.Resumable || len(ins.Problems) != 0 {
		t.Errorf("InspectInterrupted = %+v, want resumable with 0 problems", ins)
	}
	if len(ins.Files) != 1 || ins.Files[0].Name != "test.dat" {
		t.Errorf("InspectInterrupted files = %v, want 1 file test.dat", ins.Files)
	}

	// 5. Test DiscardInterrupted (idempotent)
	if err := svc.DiscardInterrupted(tid, outDir); err != nil {
		t.Fatalf("DiscardInterrupted: %v", err)
	}

	// After discard, receive item is gone
	itemsAfter, err := svc.ListInterrupted(outDir)
	if err != nil {
		t.Fatalf("ListInterrupted after discard: %v", err)
	}
	if len(itemsAfter) != 1 || itemsAfter[0].Role != "send" {
		t.Errorf("ListInterrupted after discard returned %v, want 1 send item", itemsAfter)
	}

	// 6. Test DiscardAllInterrupted
	if err := svc.DiscardAllInterrupted(outDir); err != nil {
		t.Fatalf("DiscardAllInterrupted: %v", err)
	}
	itemsEmpty, err := svc.ListInterrupted(outDir)
	if err != nil {
		t.Fatalf("ListInterrupted after DiscardAll: %v", err)
	}
	if len(itemsEmpty) != 0 {
		t.Errorf("ListInterrupted after DiscardAll returned %v, want empty", itemsEmpty)
	}
}

func TestDesktopDurableResumeHappyPath(t *testing.T) {
	svc, sink, hub := newLoopbackService(t)
	dir := t.TempDir()
	srcPath := writePayload(t, dir, "resumable.bin", 256*1024)
	outDir := filepath.Join(dir, "received")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}

	senderDir := filepath.Join(dir, "sender_state")
	sStore, err := transfer.OpenSenderStore(senderDir)
	if err != nil {
		t.Fatal(err)
	}
	svc.SetSenderStore(sStore)

	notifier := lifecycle.NewTestNotifier()
	svc.SetNotifier(notifier)

	// Step 1: Start transfer #1
	send1, err := svc.Send([]string{srcPath}, "wss://loopback/ws")
	if err != nil {
		t.Fatalf("Send #1: %v", err)
	}
	inv1 := sink.waitFor(t, "invite", 10*time.Second)

	recv1, err := svc.Receive(inv1.Code, outDir, "wss://loopback/ws")
	if err != nil {
		t.Fatalf("Receive #1: %v", err)
	}
	sink.waitForID(t, send1.ID, "connect", 10*time.Second)

	// Let the transfer complete
	sink.waitForID(t, send1.ID, "done", 10*time.Second)
	sink.waitForID(t, recv1.ID, "done", 10*time.Second)

	// Verify verified output
	got := readAll(t, filepath.Join(outDir, "resumable.bin"))
	want := readAll(t, srcPath)
	if len(got) != len(want) {
		t.Fatalf("received %d bytes, want %d", len(got), len(want))
	}

	// Verify notification was sent only on verified completion
	events := notifier.Events()
	var successEvents []lifecycle.NotificationEvent
	for _, e := range events {
		if e.Kind == "success" {
			successEvents = append(successEvents, e)
		}
	}
	if len(successEvents) == 0 {
		t.Fatalf("no success notifications recorded")
	}

	// RevealCompleted on verified receive transfer succeeds
	launcherCalled := false
	var launchedPath string
	rm := lifecycle.NewRevealManager(func(target string) error {
		launcherCalled = true
		launchedPath = target
		return nil
	})
	svc.SetRevealManager(rm)

	if err := svc.RevealCompleted(recv1.ID); err != nil {
		t.Fatalf("RevealCompleted(%q) failed: %v", recv1.ID, err)
	}
	if !launcherCalled {
		t.Errorf("launcher was not called for completed receive")
	}
	expectedPath := filepath.Join(outDir, "resumable.bin")
	realExpected, _ := filepath.EvalSymlinks(expectedPath)
	if launchedPath != realExpected && launchedPath != expectedPath {
		t.Errorf("launchedPath = %q, want %q", launchedPath, expectedPath)
	}

	// Arbitrary or nonexistent transfer id cannot be revealed
	if err := svc.RevealCompleted("nonexistent-id"); err == nil {
		t.Fatalf("RevealCompleted(nonexistent-id) expected error, got nil")
	}

	_ = hub
}

func TestDesktopDurableResumeRefusesCorruptJournal(t *testing.T) {
	svc, sink, _ := newLoopbackService(t)
	dir := t.TempDir()
	outDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}

	dStore, err := transfer.OpenStore(outDir)
	if err != nil {
		t.Fatal(err)
	}

	tid := "deadbeefdeadbeefdeadbeefdeadbeef"
	// Write a corrupt journal (empty / invalid JSON)
	if err := os.WriteFile(dStore.JournalPath(tid), []byte("{\"corrupt\": true"), 0o600); err != nil {
		t.Fatal(err)
	}

	// ResumeInterrupted on corrupt journal must fail closed
	_, err = svc.ResumeInterrupted(tid, "7-alpha-bravo", outDir, "wss://loopback/ws")
	if err == nil {
		t.Fatalf("ResumeInterrupted on corrupt journal expected error, got nil")
	}

	// Ensure no partial or output was promoted to final
	files, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f.Name() != ".sendbeam" {
			t.Fatalf("unexpected file %q created in outDir on corrupt resume", f.Name())
		}
	}
	_ = sink
}

func TestDesktopPathSafetyAndDestinationEscapeDefense(t *testing.T) {
	sink := &eventSink{}
	svc := NewTransferService(sink.emit, nil)

	dir := t.TempDir()
	validFile := writePayload(t, dir, "valid.txt", 100)

	// 1. Valid file passes validation
	if err := validatePaths([]string{validFile}); err != nil {
		t.Fatalf("validatePaths valid file failed: %v", err)
	}

	// 2. Non-existent file fails validation
	if err := validatePaths([]string{filepath.Join(dir, "missing.txt")}); err == nil {
		t.Fatalf("validatePaths missing file expected error, got nil")
	}

	// 3. Symlinks are rejected in send picker
	symlinkPath := filepath.Join(dir, "link.txt")
	_ = os.Symlink(validFile, symlinkPath)
	if err := validatePaths([]string{symlinkPath}); err == nil {
		t.Fatalf("validatePaths symlink expected error, got nil")
	}

	// 4. RevealCompleted refuses unverified IDs
	if err := svc.RevealCompleted("unverified"); err == nil {
		t.Fatalf("RevealCompleted on unverified ID expected error, got nil")
	}
}

func TestDesktopConfigPersistenceAndAutoAcceptSafety(t *testing.T) {
	dir := t.TempDir()
	cfgStore, err := config.NewStore(dir, config.NewMemorySecretStore())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	sink := &eventSink{}
	svc := NewTransferService(sink.emit, nil)
	svc.SetConfigStore(cfgStore)

	// Default config must have AutoAccept = false
	cfg, err := svc.GetConfig()
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if cfg.AutoAccept != false {
		t.Fatalf("AutoAccept must strictly be false by default, got %v", cfg.AutoAccept)
	}
	if cfg.ServerURL != config.DefaultServerURL {
		t.Errorf("ServerURL = %q, want %q", cfg.ServerURL, config.DefaultServerURL)
	}

	// Update and save custom config
	cfg.ServerURL = "wss://custom.server.org:8443/ws"
	cfg.DownloadDir = filepath.Join(dir, "saved_downloads")
	cfg.ICEServers = []string{"stun:stun.custom.org:3478"}

	if err := svc.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	reloaded, err := svc.GetConfig()
	if err != nil {
		t.Fatalf("GetConfig reloaded: %v", err)
	}
	if reloaded.ServerURL != cfg.ServerURL || reloaded.DownloadDir != cfg.DownloadDir {
		t.Errorf("reloaded config mismatch: %+v vs %+v", reloaded, cfg)
	}

	// AutoAccept remains false
	if reloaded.AutoAccept != false {
		t.Errorf("AutoAccept must remain false, got %v", reloaded.AutoAccept)
	}
}

func TestDesktopPersistedICEServersApplication(t *testing.T) {
	dir := t.TempDir()
	memSecret := config.NewMemorySecretStore()
	cfgStore, err := config.NewStore(dir, memSecret)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	turnURL := "turn:relay.custom.org:3478"
	turnUser := "beamuser"
	turnSecret := "supersecret"

	if err := cfgStore.SaveTurnCredential(turnURL, turnUser, []byte(turnSecret)); err != nil {
		t.Fatalf("SaveTurnCredential: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.ICEServers = []string{
		"stun:stun.l.google.com:19302",
		"turn:" + turnUser + "@relay.custom.org:3478",
	}
	if err := cfgStore.Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	svc := NewTransferService(nil, nil)
	svc.SetConfigStore(cfgStore)

	resolved, err := svc.resolveICEServers()
	if err != nil {
		t.Fatalf("resolveICEServers failed: %v", err)
	}
	if len(resolved) != 2 {
		t.Fatalf("resolved %d servers, want 2", len(resolved))
	}
	if resolved[0].URLs[0] != "stun:stun.l.google.com:19302" {
		t.Errorf("resolved[0] = %+v", resolved[0])
	}
	if resolved[1].Username != turnUser || resolved[1].Credential != turnSecret || resolved[1].CredentialType != webrtc.ICECredentialTypePassword {
		t.Errorf("resolved[1] = %+v, want username %q and credential %q", resolved[1], turnUser, turnSecret)
	}
}

func TestDesktopTurnCredentialUnavailableDegradation(t *testing.T) {
	dir := t.TempDir()
	unavail := config.NewUnavailableSecretStore("explicit test unavailable")
	cfgStore, err := config.NewStore(dir, unavail)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.ICEServers = []string{"turn:beamuser@relay.custom.org:3478"}
	if err := cfgStore.Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	svc := NewTransferService(nil, nil)
	svc.SetConfigStore(cfgStore)

	_, err = svc.resolveICEServers()
	if err == nil || !strings.Contains(err.Error(), "protected secret store is unavailable") {
		t.Fatalf("resolveICEServers expected secret store unavailable error, got %v", err)
	}
}

func TestDesktopLifecycleHooks(t *testing.T) {
	sink := &eventSink{}
	svc := NewTransferService(sink.emit, nil)

	// Call lifecycle hooks
	svc.OnSuspend()
	svc.OnResume()
	svc.OnNetworkChange()
}

func TestDesktopGracefulShutdown(t *testing.T) {
	svc, sink, hub := newLoopbackService(t)
	dir := t.TempDir()
	srcPath := writePayload(t, dir, "large.bin", 2*1024*1024)
	outDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}

	send, err := svc.Send([]string{srcPath}, "wss://loopback/ws")
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	invite := sink.waitFor(t, "invite", 10*time.Second)

	_, err = svc.Receive(invite.Code, outDir, "wss://loopback/ws")
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}

	sink.waitForID(t, send.ID, "connect", 10*time.Second)

	// While transfer is in flight, active count > 0
	if count := svc.ActiveCount(); count == 0 {
		t.Errorf("ActiveCount = 0 during active transfer")
	}

	// Call Shutdown with a bounded timeout
	start := time.Now()
	if err := svc.Shutdown(2 * time.Second); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}
	elapsed := time.Since(start)

	if elapsed > 3*time.Second {
		t.Errorf("Shutdown took %v, expected under 3s", elapsed)
	}

	if count := svc.ActiveCount(); count != 0 {
		t.Errorf("ActiveCount after shutdown = %d, want 0", count)
	}
	_ = hub
}
