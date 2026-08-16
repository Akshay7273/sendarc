package engine

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/pion/webrtc/v4"
	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/engine/wsclient"
	"github.com/sendbeam/wire"
)

// eventSink records TransferEvents emitted by the service, for assertions and
// for waiting on particular kinds (invite, connect, done, …).
type eventSink struct {
	mu     sync.Mutex
	events []*TransferEvent
}

func (s *eventSink) emit(name string, data any) {
	if name != TransferEventName {
		return
	}
	ev, ok := data.(*TransferEvent)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}

func (s *eventSink) all() []*TransferEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*TransferEvent(nil), s.events...)
}

// waitFor blocks until a kind appears or the timeout elapses.
func (s *eventSink) waitFor(t *testing.T, kind string, timeout time.Duration) *TransferEvent {
	t.Helper()
	return s.waitForID(t, "", kind, timeout)
}

// waitForID blocks until an event of kind for the given id (or any id when id
// is empty) appears.
func (s *eventSink) waitForID(t *testing.T, id, kind string, timeout time.Duration) *TransferEvent {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, ev := range s.all() {
			if ev.Kind == kind && (id == "" || ev.ID == id) {
				return ev
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for event kind %q id %q (got %v)", kind, id, kinds(s.all()))
	return nil
}

func (s *eventSink) has(kind string) bool {
	for _, ev := range s.all() {
		if ev.Kind == kind {
			return true
		}
	}
	return false
}

func kinds(evs []*TransferEvent) []string {
	var out []string
	for _, ev := range evs {
		out = append(out, ev.Kind)
	}
	return out
}

// loopbackDialer returns the offerer/joiner end of a shared in-process relay,
// mirroring the engine parity tests' signal seam.
func loopbackDialer(hub *loopbackRelay) SignalDialer {
	return func(_ context.Context, _ string, role wire.Role) (transfer.Signal, error) {
		if role == wire.RoleOfferer {
			return hub.off, nil
		}
		return hub.join, nil
	}
}

// newLoopbackService builds a TransferService wired to a fresh loopback relay,
// ready for a send+receive pair.
func newLoopbackService(t *testing.T) (*TransferService, *eventSink, *loopbackRelay) {
	t.Helper()
	hub := newLoopbackRelay()
	sink := &eventSink{}
	svc := NewTransferService(sink.emit, loopbackDialer(hub))
	svc.setLoopbackConfig()
	t.Cleanup(func() {
		hub.off.Close()
		hub.join.Close()
	})
	return svc, sink, hub
}

// writePayload writes a deterministic file.
func writePayload(t *testing.T, dir, name string, size int) string {
	t.Helper()
	path := filepath.Join(dir, name)
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i*31 + 7)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readAll(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// startPair starts a send+receive pair: sender first (so the relay allocates
// the room), then the receiver joins with the invite code.
func startPair(t *testing.T, svc *TransferService, sink *eventSink, srcPath, outDir string) (sendID, recvID string) {
	t.Helper()
	send, err := svc.Send([]string{srcPath}, "wss://loopback/ws")
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	invite := sink.waitFor(t, "invite", 30*time.Second)
	if invite.Code == "" {
		t.Fatal("invite event has no code")
	}
	recv, err := svc.Receive(invite.Code, outDir, "wss://loopback/ws")
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	return send.ID, recv.ID
}

// TestServiceSendReceiveFullTransfer drives one complete send+receive pair
// through the service public API and checks the event stream plus the
// byte-identical verified output.
func TestServiceSendReceiveFullTransfer(t *testing.T) {
	svc, sink, _ := newLoopbackService(t)
	dir := t.TempDir()
	src := writePayload(t, dir, "payload.bin", 1<<20+40000) // crosses the 1 MiB block boundary
	outDir := filepath.Join(dir, "out")

	sendID, recvID := startPair(t, svc, sink, src, outDir)

	doneSend := sink.waitForID(t, sendID, "done", 60*time.Second)
	if doneSend.Digest == "" {
		t.Fatal("sender done event has no digest")
	}
	if doneSend.Percent != 100 {
		t.Fatalf("sender done percent = %d, want 100", doneSend.Percent)
	}

	recvDone := sink.waitForID(t, recvID, "done", 60*time.Second)
	if recvDone.Digest == "" {
		t.Fatal("receiver done event has no digest")
	}
	if recvDone.OutDir != outDir {
		t.Fatalf("receiver outDir = %q, want %q", recvDone.OutDir, outDir)
	}
	if recvDone.Digest == "" {
		t.Fatal("receiver done event has no digest")
	}

	// Byte-identical verified output.
	got := readAll(t, filepath.Join(outDir, "payload.bin"))
	want := readAll(t, src)
	if len(got) != len(want) {
		t.Fatalf("received %d bytes, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("received bytes differ at %d", i)
		}
	}

	// Invite event carried code + link + QR.
	if invite := sink.waitFor(t, "invite", 5*time.Second); invite.Link == "" || invite.QR == "" {
		t.Fatalf("invite missing link/QR: %+v", invite)
	}

	// Aggregate + current-file state appeared on the receiver manifest event.
	manifest := sink.waitFor(t, "manifest", 5*time.Second)
	if len(manifest.Files) != 1 || manifest.Files[0].Name != "payload.bin" {
		t.Fatalf("manifest files = %+v", manifest.Files)
	}
	if manifest.TotalBytes != int64(len(want)) {
		t.Fatalf("manifest total = %d, want %d", manifest.TotalBytes, len(want))
	}

	// Fingerprint set on both done events (auth state).
	if doneSend.Fingerprint == "" || recvDone.Fingerprint == "" {
		t.Fatal("done events missing fingerprint")
	}
	if doneSend.Fingerprint != recvDone.Fingerprint {
		t.Fatalf("fingerprints differ: %q vs %q", doneSend.Fingerprint, recvDone.Fingerprint)
	}

	// Transport reported (loopback config forces relay).
	if !sink.has("transport") {
		t.Fatal("no transport event")
	}
	_ = recvDone
}

// TestServiceSendReceiveMultiFile sends two files and checks aggregate state.
func TestServiceSendReceiveMultiFile(t *testing.T) {
	svc, sink, _ := newLoopbackService(t)
	dir := t.TempDir()
	a := writePayload(t, dir, "a.txt", 300000)
	b := writePayload(t, dir, "b.txt", 500000)
	outDir := filepath.Join(dir, "out")

	send, err := svc.Send([]string{a, b}, "wss://loopback/ws")
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	invite := sink.waitFor(t, "invite", 30*time.Second)
	if _, err := svc.Receive(invite.Code, outDir, "wss://loopback/ws"); err != nil {
		t.Fatalf("Receive: %v", err)
	}
	done := sink.waitForID(t, send.ID, "done", 60*time.Second)
	if done.FilesTotal != 2 {
		t.Fatalf("filesTotal = %d, want 2", done.FilesTotal)
	}
	if done.FilesDone != 2 {
		t.Fatalf("filesDone = %d, want 2", done.FilesDone)
	}
	if done.TotalBytes != 800000 {
		t.Fatalf("totalBytes = %d, want 800000", done.TotalBytes)
	}
	for _, name := range []string{"a.txt", "b.txt"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("missing received file %s: %v", name, err)
		}
	}
}

// TestServicePauseResumeCancel verifies the controls surface: pause reports
// state, resume completes, and a fresh pair can be canceled cleanly.
func TestServicePauseResumeCancel(t *testing.T) {
	svc, sink, _ := newLoopbackService(t)
	dir := t.TempDir()
	// Large enough payload that pausing mid-flight is observable.
	src := writePayload(t, dir, "big.bin", 32<<20)
	outDir := filepath.Join(dir, "out")

	sendID, _ := startPair(t, svc, sink, src, outDir)

	// Wait for controls to be live (connect event fires when the channel
	// opens, before bytes begin moving).
	waitForControls := func(id string) {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			s := svc.state(id)
			if s.controlsReady() {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("controls never became ready")
	}
	waitForControls(sendID)

	if err := svc.Pause(sendID); err != nil {
		t.Fatalf("Pause: %v", err)
	}
	// State event reports paused.
	deadline := time.Now().Add(10 * time.Second)
	for !sink.has("state") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !svc.state(sendID).paused {
		t.Fatal("transfer not paused after Pause()")
	}

	if err := svc.Resume(sendID); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	done := sink.waitForID(t, sendID, "done", 60*time.Second)
	if done.Failed || done.Canceled {
		t.Fatalf("resumed transfer ended failed/canceled: %+v", done)
	}

	// Cancel a fresh pair.
	svc2, sink2, _ := newLoopbackService(t)
	src2 := writePayload(t, dir, "big2.bin", 32<<20)
	outDir2 := filepath.Join(dir, "out2")
	sendID2, _ := startPair(t, svc2, sink2, src2, outDir2)
	waitForControls = func(id string) {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			if svc2.state(id).controlsReady() {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("controls never became ready")
	}
	waitForControls(sendID2)
	if err := svc2.Cancel(sendID2); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	// Either side settles canceled; the service must not hang and must report
	// the terminal state.
	deadline = time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		all := sink2.all()
		for _, ev := range all {
			if ev.ID == sendID2 && (ev.Kind == "done" || ev.Kind == "error") {
				if !ev.Canceled && !ev.Failed {
					t.Fatalf("canceled transfer ended without canceled/failed: %+v", ev)
				}
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("canceled transfer never settled")
}

// TestServiceInviteAndQR checks invite code normalization, link formatting, and
// that the QR is a decodable PNG data URL.
func TestServiceInviteAndQR(t *testing.T) {
	if code := normalizeCode("https://example.com/#7-alpha-bravo"); code != "7-alpha-bravo" {
		t.Fatalf("normalizeCode(link) = %q", code)
	}
	if code := normalizeCode("7-alpha-bravo"); code != "7-alpha-bravo" {
		t.Fatalf("normalizeCode(bare) = %q", code)
	}
	link := inviteLink("wss://example.com:8443/ws", "7-alpha-bravo")
	want := "https://example.com:8443/#7-alpha-bravo"
	if link != want {
		t.Fatalf("inviteLink = %q, want %q", link, want)
	}
	qr := qrDataURL(link)
	if !strings.HasPrefix(qr, "data:image/png;base64,") {
		t.Fatalf("QR is not a PNG data URL: %.40q", qr)
	}
	raw := strings.TrimPrefix(qr, "data:image/png;base64,")
	png, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("QR base64: %v", err)
	}
	if len(png) < 8 || string(png[1:4]) != "PNG" {
		t.Fatalf("QR does not decode to a PNG (first bytes %x)", png[:min(8, len(png))])
	}
}

// TestServicePickersServerMode verifies native pickers degrade to a clear
// error when no GUI is present (server mode / tests).
func TestServicePickersServerMode(t *testing.T) {
	svc, _, _ := newLoopbackService(t)
	res := svc.PickFiles()
	if res.Error == "" {
		t.Fatal("PickFiles in server mode returned no error")
	}
	res = svc.PickDestination()
	if res.Error == "" {
		t.Fatal("PickDestination in server mode returned no error")
	}
}

// TestServiceSendValidation checks pre-flight validation and id stability.
func TestServiceSendValidation(t *testing.T) {
	svc, _, _ := newLoopbackService(t)
	if _, err := svc.Send(nil, "wss://loopback/ws"); err == nil {
		t.Fatal("Send with no paths succeeded")
	}
	if _, err := svc.Send([]string{filepath.Join(t.TempDir(), "missing.txt")}, "wss://loopback/ws"); err == nil {
		t.Fatal("Send with missing path succeeded")
	}
	src := writePayload(t, t.TempDir(), "ok.bin", 1000)
	if _, err := svc.Send([]string{src}, ""); err != nil {
		t.Fatalf("Send with default server failed: %v", err)
	}
	if _, err := svc.Receive("", ".", ""); err == nil {
		t.Fatal("Receive with empty code succeeded")
	}
}

// helper state accessors (same package) for control-readiness polling.
func (s *TransferService) state(id string) *transferRun {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runs[id]
}

func (r *transferRun) controlsReady() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.controls != nil
}

// blindHub is a minimal in-process stand-in for the SendBeam signaling server
// over a REAL WebSocket, mirroring the wsclient package's own test hub. It lets
// the desktop service exercise the exact wsclient + engine stack the CLI and
// browser use — the browser/CLI interop proof at the service layer.
type blindHub struct {
	mu    sync.Mutex
	rooms map[int]*blindRoom
	next  int
}

type blindRoom struct {
	offerer, joiner *blindPeer
}

type blindPeer struct {
	conn *websocket.Conn
	wmu  sync.Mutex
}

func (p *blindPeer) send(ctx context.Context, m rendezvous.Message) {
	data, _ := rendezvous.MarshalMessage(m)
	p.wmu.Lock()
	defer p.wmu.Unlock()
	_ = p.conn.Write(ctx, websocket.MessageText, data)
}

func (p *blindPeer) forward(ctx context.Context, data []byte) {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	_ = p.conn.Write(ctx, websocket.MessageText, data)
}

func newBlindHub() *blindHub { return &blindHub{rooms: map[int]*blindRoom{}} }

func (h *blindHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer func() { _ = conn.CloseNow() }()
	ctx := r.Context()
	self := &blindPeer{conn: conn}

	var room *blindRoom
	var role rendezvous.Role
	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		if typ != websocket.MessageText {
			return
		}
		msg, err := rendezvous.UnmarshalMessage(data)
		if err != nil {
			return
		}
		switch msg.Type {
		case "create":
			h.mu.Lock()
			id := h.next
			h.next++
			room = &blindRoom{offerer: self}
			h.rooms[id] = room
			h.mu.Unlock()
			role = rendezvous.RoleOfferer
			self.send(ctx, rendezvous.Message{Type: "created", Room: &id})
		case "join":
			if msg.Room == nil {
				return
			}
			h.mu.Lock()
			room = h.rooms[*msg.Room]
			h.mu.Unlock()
			if room == nil {
				return
			}
			room.joiner = self
			role = rendezvous.RoleJoiner
			self.send(ctx, rendezvous.Message{Type: "peer-joined", Role: string(rendezvous.RoleJoiner)})
			room.offerer.send(ctx, rendezvous.Message{Type: "peer-joined", Role: string(rendezvous.RoleOfferer)})
		default:
			other := room.joiner
			if role == rendezvous.RoleJoiner {
				other = room.offerer
			}
			if other != nil {
				other.forward(ctx, data)
			}
		}
	}
}

func wsURL(httpsURL string) string { return "wss" + strings.TrimPrefix(httpsURL, "https") }

// TestServiceInteropOverRealWebSocket runs a full send+receive through the
// desktop service using the REAL wsclient dialer against a real WebSocket
// signaling hub — the same stack CLI and browser peers speak, proving desktop
// interop from the first implementation.
func TestServiceInteropOverRealWebSocket(t *testing.T) {
	if testing.Short() {
		t.Skip("real-WebSocket interop transfer")
	}
	hub := newBlindHub()
	srv := httptest.NewTLSServer(hub)
	defer srv.Close()
	server := wsURL(srv.URL)

	insecureDial := func(ctx context.Context, server string, _ wire.Role) (transfer.Signal, error) {
		return wsclient.NewReconnectingSignal(ctx, server, wsclient.DialOptions{InsecureSkipVerify: true})
	}
	sink := &eventSink{}
	svc := NewTransferService(sink.emit, insecureDial)
	// Direct path with host-only ICE: the real WebSocket carries the SDP/ICE
	// signaling (blind-forwarded by the hub) exactly as CLI/browser peers do;
	// the loopback relay's relay-open gating is not part of this hub, so the
	// direct WebRTC path is the interop surface here.
	svc.iceServers = []webrtc.ICEServer{}

	dir := t.TempDir()
	src := writePayload(t, dir, "interop.bin", 1<<20+12345)
	outDir := filepath.Join(dir, "out")

	send, err := svc.Send([]string{src}, server)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	invite := sink.waitFor(t, "invite", 30*time.Second)
	if invite.Code == "" {
		t.Fatal("no invite code")
	}
	recv, err := svc.Receive(invite.Code, outDir, server)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}

	sink.waitForID(t, send.ID, "done", 60*time.Second)
	recvDone := sink.waitForID(t, recv.ID, "done", 60*time.Second)
	if recvDone.Digest == "" {
		t.Fatal("receiver done has no digest")
	}

	got := readAll(t, filepath.Join(outDir, "interop.bin"))
	want := readAll(t, src)
	if len(got) != len(want) {
		t.Fatalf("received %d bytes, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("received bytes differ at %d", i)
		}
	}
}

// TestServiceInteropInviteLinkFormat proves the desktop invite link matches the
// CLI/browser join link for the same deployment (fragment-encoded code).
func TestServiceInteropInviteLinkFormat(t *testing.T) {
	link := inviteLink("wss://relay.example.com:8443/ws", "12-quick-brown")
	if !strings.HasPrefix(link, "https://relay.example.com:8443/#12-quick-brown") {
		t.Fatalf("unexpected invite link: %q", link)
	}
}
