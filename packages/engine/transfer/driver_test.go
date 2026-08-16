package transfer

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/wire"
)

// relay is an in-memory stand-in for the signaling server, faithful to apps/server's peer
// loop: it allocates a room on create, pairs on join (notifying each side with its own
// role, exactly as peerJoinedFrame does), and forwards every other message verbatim to the
// partner. It lets a complete offerer↔joiner exchange — SPAKE2 handshake, authenticated
// SDP/ICE, and the sealed file transfer — run in one process with no sockets.
type relay struct {
	off      *relayEnd
	join     *relayEnd
	room     int
	created  chan struct{} // closed once the offerer has created the room
	once     sync.Once
	mu       sync.Mutex
	captured [][]byte
}

func newRelay() *relay {
	r := &relay{room: 7, created: make(chan struct{})}
	r.off = newRelayEnd(r, "offerer")
	r.join = newRelayEnd(r, "joiner")
	return r
}

func (r *relay) partner(e *relayEnd) *relayEnd {
	if e == r.off {
		return r.join
	}
	return r.off
}

// route reproduces the server's dispatch: create allocates the room and answers the sender,
// join pairs and tells each peer its own role, and anything else is relayed to the partner. A
// join blocks until the room has been created, mirroring the server guarantee that a joiner
// cannot pair before the offerer exists (it needs the code, which needs the room) — without
// this, the two drivers start concurrently and a join can race ahead of create, delivering
// peer-joined to the offerer while it is still allocating.
func (r *relay) route(from *relayEnd, m rendezvous.Message) {
	switch m.Type {
	case "create":
		room := r.room
		from.enqueue(rendezvous.Message{Type: "created", Room: &room})
		r.once.Do(func() { close(r.created) })
	case "join":
		<-r.created
		r.off.enqueue(rendezvous.Message{Type: "peer-joined", Role: r.off.role})
		r.join.enqueue(rendezvous.Message{Type: "peer-joined", Role: r.join.role})
	case rendezvous.TypeRelayOpen:
		r.mu.Lock()
		from.relayOpen = true
		other := r.partner(from)
		ready := other.relayOpen
		r.mu.Unlock()
		if ready {
			from.enqueue(rendezvous.Message{Type: rendezvous.TypeRelayReady})
			other.enqueue(rendezvous.Message{Type: rendezvous.TypeRelayReady})
		} else {
			other.enqueue(rendezvous.Message{Type: rendezvous.TypeRelayRequired})
		}
	case rendezvous.TypeRelayCredit:
		r.partner(from).enqueue(rendezvous.Message{Type: rendezvous.TypeCredit, Bytes: m.Bytes})
	default:
		r.partner(from).enqueue(m)
	}
}

// relayEnd is one side of the relay. It satisfies transfer.Signal, so a driver adopts it
// exactly as it would a real *wsclient.Client.
type relayEnd struct {
	hub       *relay
	role      string
	in        chan rendezvous.Message
	bin       chan []byte
	relayOpen bool
	once      sync.Once
	done      chan struct{}
	killOnce  sync.Once
	killSig   chan struct{} // closed by killSignaling to simulate a dead signaling socket

	// resume records whether the driver armed this signal as a ReconnectSetter (V12-PR04).
	resumeCalled bool
	resumeRoom   int
	resumeRole   string
}

// SetResume implements ReconnectSetter: it records the room/role the driver arms once the
// handshake settles so a reconnectable signal can re-attach to the room.
func (e *relayEnd) SetResume(room int, role string) {
	e.resumeCalled = true
	e.resumeRoom = room
	e.resumeRole = role
}

func newRelayEnd(hub *relay, role string) *relayEnd {
	return &relayEnd{
		hub: hub, role: role, in: make(chan rendezvous.Message, 256),
		bin: make(chan []byte, 256), done: make(chan struct{}), killSig: make(chan struct{}),
	}
}

func (e *relayEnd) Send(m rendezvous.Message) error {
	e.hub.route(e, m)
	return nil
}

func (e *relayEnd) SendBinary(frame []byte) error {
	e.hub.mu.Lock()
	e.hub.captured = append(e.hub.captured, append([]byte(nil), frame...))
	e.hub.mu.Unlock()
	e.hub.partner(e).enqueueBinary(frame)
	return nil
}

func (e *relayEnd) Run(ctx context.Context, onMessage func(rendezvous.Message), onBinary func([]byte)) error {
	for {
		select {
		case <-e.killSig:
			return errSignalingClosed
		case m := <-e.in:
			onMessage(m)
		case frame := <-e.bin:
			onBinary(frame)
		case <-e.done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// errSignalingClosed is what the driver sees when the signaling socket dies.
var errSignalingClosed = errors.New("signaling socket closed")

// killSignaling simulates the signaling socket dying while the byte path (direct
// channel or relay) keeps or loses transport independently.
func (e *relayEnd) killSignaling() {
	e.killOnce.Do(func() { close(e.killSig) })
}

func (e *relayEnd) enqueueBinary(frame []byte) {
	select {
	case e.bin <- append([]byte(nil), frame...):
	case <-e.done:
	}
}

func (e *relayEnd) Close() { e.once.Do(func() { close(e.done) }) }

// enqueue delivers to this end unless it has closed, in which case the frame is dropped —
// a late trickled candidate arriving after teardown must not panic on a closed channel.
func (e *relayEnd) enqueue(m rendezvous.Message) {
	select {
	case e.in <- m:
	case <-e.done:
	}
}

// TestDriverLoopbackTransfersFile wires two drivers through an in-memory relay and completes the
// whole pipeline — SPAKE2 rendezvous, an authenticated pion
// DataChannel over host candidates, and a sealed file transfer — and the receiver writes a
// file byte-identical to the sender's, with matching whole-file digests and session keys.
func TestDriverLoopbackTransfersFile(t *testing.T) {
	hub := newRelay()

	// A payload that crosses a 1 MiB block boundary and does not divide evenly into frames,
	// so the run exercises real chunking, windowing, and multi-block reassembly.
	payload := make([]byte, 1<<20+40000)
	for i := range payload {
		payload[i] = byte(i*31 + 7)
	}
	meta := wire.FileMeta{
		Name:         "payload.bin",
		Size:         int64(len(payload)),
		Mime:         "application/octet-stream",
		LastModified: 1_700_000_000_000,
	}
	dir := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	type result struct {
		out *Outcome
		err error
	}
	sendDone := make(chan result, 1)
	recvDone := make(chan result, 1)

	go func() {
		out, err := Run(ctx, hub.off, Spec{
			Session:    rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "alpha-bravo"},
			Source:     wire.BytesSource(payload, meta, 64*1024),
			ICEServers: []webrtc.ICEServer{}, // host candidates only; loopback needs no STUN
		})
		sendDone <- result{out, err}
	}()
	go func() {
		out, err := Run(ctx, hub.join, Spec{
			Session:    rendezvous.Options{Role: rendezvous.RoleJoiner, Code: "7-alpha-bravo"},
			DestDir:    dir,
			ICEServers: []webrtc.ICEServer{},
		})
		recvDone <- result{out, err}
	}()

	send := <-sendDone
	recv := <-recvDone

	if recv.err != nil {
		t.Fatalf("receiver: %v", recv.err)
	}
	if send.err != nil {
		t.Fatalf("sender: %v", send.err)
	}

	if send.out.Digest != recv.out.Digest {
		t.Errorf("digests differ: sender %s, receiver %s", send.out.Digest, recv.out.Digest)
	}
	if recv.out.Name != "payload.bin" {
		t.Errorf("received name = %q, want payload.bin", recv.out.Name)
	}
	if recv.out.Size != meta.Size {
		t.Errorf("received size = %d, want %d", recv.out.Size, meta.Size)
	}
	if want := filepath.Join(dir, "payload.bin"); recv.out.Path != want {
		t.Errorf("written path = %q, want %q", recv.out.Path, want)
	}

	got, err := os.ReadFile(recv.out.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("received %d bytes, want %d byte-identical to the source", len(got), len(payload))
	}

	// Both peers derived the same session key, so their SAS fingerprints would match.
	if !bytes.Equal(send.out.Handshake.Master, recv.out.Handshake.Master) {
		t.Error("master keys differ across peers")
	}
}

func TestDriverForcedRelayTransfersEncryptedFile(t *testing.T) {
	hub := newRelay()
	payload := make([]byte, 512*1024+17)
	for i := range payload {
		payload[i] = byte(i*17 + 3)
	}
	meta := wire.FileMeta{Name: "relayed.bin", Size: int64(len(payload)), Mime: "application/octet-stream"}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	type result struct {
		out  *Outcome
		err  error
		path string
	}
	done := make(chan result, 2)
	go func() {
		path := ""
		out, err := Run(ctx, hub.off, Spec{
			Session: rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "alpha-bravo"},
			Source:  wire.BytesSource(payload, meta, 64*1024), ForceRelay: true,
			OnTransport: func(selected string) { path = selected },
		})
		done <- result{out: out, err: err, path: path}
	}()
	go func() {
		path := ""
		out, err := Run(ctx, hub.join, Spec{
			Session:     rendezvous.Options{Role: rendezvous.RoleJoiner, Code: "7-alpha-bravo"},
			DestDir:     dir,
			OnTransport: func(selected string) { path = selected },
		})
		done <- result{out: out, err: err, path: path}
	}()
	a, b := <-done, <-done
	if a.err != nil || b.err != nil {
		t.Fatalf("forced relay results: %v / %v", a.err, b.err)
	}
	if a.path != "relay" || b.path != "relay" {
		t.Fatalf("selected paths = %q/%q", a.path, b.path)
	}
	var recv *Outcome
	if a.out.Path != "" {
		recv = a.out
	} else {
		recv = b.out
	}
	got, err := os.ReadFile(recv.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("forced relay output differs from source")
	}
	hub.mu.Lock()
	captured := append([][]byte(nil), hub.captured...)
	hub.mu.Unlock()
	if len(captured) == 0 {
		t.Fatal("relay did not observe any binary frames")
	}
	for _, frame := range captured {
		if bytes.Contains(frame, []byte(meta.Name)) || bytes.Contains(frame, payload[:64]) {
			t.Fatal("relay observed plaintext metadata or file content")
		}
	}
}

func TestDriverSwitchesActiveDirectTransferToRelay(t *testing.T) {
	hub := newRelay()
	payload := make([]byte, 6*1024*1024+29)
	for i := range payload {
		payload[i] = byte(i*23 + 11)
	}
	meta := wire.FileMeta{Name: "switched.bin", Size: int64(len(payload)), Mime: "application/octet-stream"}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	type pathLog struct {
		mu    sync.Mutex
		paths []string
	}
	appendPath := func(log *pathLog) func(string) {
		return func(path string) {
			log.mu.Lock()
			log.paths = append(log.paths, path)
			log.mu.Unlock()
		}
	}
	trigger := make(chan struct{})
	var triggerOnce sync.Once
	sendPaths, recvPaths := &pathLog{}, &pathLog{}
	type result struct {
		out *Outcome
		err error
	}
	done := make(chan result, 2)
	go func() {
		out, err := Run(ctx, hub.off, Spec{
			Session:     rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "alpha-bravo"},
			Source:      wire.BytesSource(payload, meta, 64*1024),
			ICEServers:  []webrtc.ICEServer{},
			OnTransport: appendPath(sendPaths),
			breakDirect: trigger,
			OnProgress: func(bytes int64) {
				if bytes >= 1024*1024 {
					triggerOnce.Do(func() { close(trigger) })
				}
			},
		})
		done <- result{out: out, err: err}
	}()
	go func() {
		out, err := Run(ctx, hub.join, Spec{
			Session:     rendezvous.Options{Role: rendezvous.RoleJoiner, Code: "7-alpha-bravo"},
			DestDir:     dir,
			ICEServers:  []webrtc.ICEServer{},
			OnTransport: appendPath(recvPaths),
		})
		done <- result{out: out, err: err}
	}()

	a, b := <-done, <-done
	if a.err != nil || b.err != nil {
		t.Fatalf("switched transfer results: %v / %v", a.err, b.err)
	}
	var recv *Outcome
	if a.out.Path != "" {
		recv = a.out
	} else {
		recv = b.out
	}
	got, err := os.ReadFile(recv.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("switched transfer output differs from source")
	}
	for name, log := range map[string]*pathLog{"sender": sendPaths, "receiver": recvPaths} {
		log.mu.Lock()
		paths := append([]string(nil), log.paths...)
		log.mu.Unlock()
		expectCutover(t, name, paths)
	}
}

// TestDriverReceiverRejectsMismatchedCode proves the handshake still fails closed when
// adopted by the driver: a joiner with the wrong code never reaches a channel, and both
// sides surface a confirmation failure rather than hanging or transferring.
func TestDriverReceiverRejectsMismatchedCode(t *testing.T) {
	hub := newRelay()
	payload := []byte("must never be sent under a bad code")
	meta := wire.FileMeta{Name: "secret.bin", Size: int64(len(payload)), Mime: "application/octet-stream"}
	dir := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	errs := make(chan error, 2)
	go func() {
		_, err := Run(ctx, hub.off, Spec{
			Session:    rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "alpha-bravo"},
			Source:     wire.BytesSource(payload, meta, 64*1024),
			ICEServers: []webrtc.ICEServer{},
		})
		errs <- err
	}()
	go func() {
		_, err := Run(ctx, hub.join, Spec{
			Session:    rendezvous.Options{Role: rendezvous.RoleJoiner, Code: "7-wrong-words"},
			DestDir:    dir,
			ICEServers: []webrtc.ICEServer{},
		})
		errs <- err
	}()

	for i := 0; i < 2; i++ {
		if err := <-errs; err == nil {
			t.Fatal("expected a handshake failure under a mismatched code, got nil")
		}
	}
	// No file should have been created from a failed handshake.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("destination dir has %d entries, want 0 after a failed handshake", len(entries))
	}
}

// TestDriverArmsReconnectableSignal pins the V12-PR04 signaling-recovery wiring: once the
// handshake settles, the driver arms a ReconnectSetter signal with the room and role so a later
// signaling drop can re-attach to the room.
func TestDriverArmsReconnectableSignal(t *testing.T) {
	hub := newRelay()
	payload := faultPayload(256 * 1024)
	meta := wire.FileMeta{Name: "resume-arm.bin", Size: int64(len(payload)), Mime: "application/octet-stream"}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	done := make(chan error, 2)
	go func() {
		_, err := Run(ctx, hub.off, Spec{
			Session:    rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "alpha-bravo"},
			Source:     wire.BytesSource(payload, meta, 64*1024),
			ICEServers: []webrtc.ICEServer{},
		})
		done <- err
	}()
	go func() {
		_, err := Run(ctx, hub.join, Spec{
			Session:    rendezvous.Options{Role: rendezvous.RoleJoiner, Code: "7-alpha-bravo"},
			DestDir:    dir,
			ICEServers: []webrtc.ICEServer{},
		})
		done <- err
	}()

	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatalf("transfer error: %v", err)
		}
	}
	for name, e := range map[string]*relayEnd{"offerer": hub.off, "joiner": hub.join} {
		if !e.resumeCalled {
			t.Fatalf("%s signal was not armed as a ReconnectSetter", name)
		}
		if e.resumeRoom != hub.room {
			t.Fatalf("%s resume room = %d, want %d", name, e.resumeRoom, hub.room)
		}
		if e.resumeRole != name {
			t.Fatalf("%s resume role = %q, want %q", name, e.resumeRole, name)
		}
	}
}

// TestDriverAuthenticatedCrossSessionResume drives the full V13-PR08 cross-session resume
// loop through the real driver and the real durable destination: leg 1 persists the sender
// record and the receiver journal (each carrying the transfer-scoped resume credential)
// and is interrupted mid-file; leg 2 is a FRESH rendezvous where both peers run mutual
// resume-auth BEFORE any verified progress is reused, then continue under a fresh key
// epoch and complete byte-identical.
func TestDriverAuthenticatedCrossSessionResume(t *testing.T) {
	senderStore := testSenderStore(t)
	outDir := t.TempDir()
	srcDir := t.TempDir()
	payload := make([]byte, 32<<20) // 32 MiB: plenty of headroom for a mid-file interrupt
	for i := range payload {
		payload[i] = byte(i*13 + 5)
	}
	srcPath := filepath.Join(srcDir, "payload.bin")
	if err := os.WriteFile(srcPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{srcPath}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	type result struct {
		out *Outcome
		err error
	}
	capsResume := func() *rendezvous.Caps {
		c := rendezvous.DefaultCaps()
		c.Features = append(c.Features, wire.ResumeAuthCapability)
		return &c
	}
	runLeg := func(interrupt bool, sendResume, recvResume *ResumeContext, sendCaps, recvCaps *rendezvous.Caps) (send, recv result, id string, reused bool) {
		hub := newRelay()
		sources, _, err := NewOSFileSources(args)
		if err != nil {
			t.Fatal(err)
		}
		var hook func(wire.Manifest) error
		id, hook, reused, err = PrepareSender(senderStore, args, sources)
		if err != nil {
			t.Fatal(err)
		}
		legCtx, legCancel := context.WithCancel(ctx)
		defer legCancel()
		firstProgress := make(chan struct{})
		var once sync.Once
		if interrupt {
			go func() {
				select {
				case <-firstProgress:
					legCancel()
				case <-legCtx.Done():
				}
			}()
		}
		sendDone := make(chan result, 1)
		recvDone := make(chan result, 1)
		go func() {
			out, err := Run(legCtx, hub.off, Spec{
				Session:        rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "alpha-bravo", LocalCaps: sendCaps},
				Sources:        sources,
				TransferID:     id,
				OnSendManifest: hook,
				OnResumeCredential: func(manifest wire.Manifest, resumeRoot []byte) error {
					return senderStore.AttachResumeSecret(manifest, resumeRoot, !reused)
				},
				Resume:     sendResume,
				ICEServers: []webrtc.ICEServer{},
			})
			sendDone <- result{out, err}
		}()
		go func() {
			out, err := Run(legCtx, hub.join, Spec{
				Session:    rendezvous.Options{Role: rendezvous.RoleJoiner, Code: "7-alpha-bravo", LocalCaps: recvCaps},
				DestDir:    outDir,
				Resume:     recvResume,
				ICEServers: []webrtc.ICEServer{},
				OnProgress: func(int64) {
					if interrupt {
						once.Do(func() { close(firstProgress) })
					}
				},
			})
			recvDone <- result{out, err}
		}()
		send = <-sendDone
		recv = <-recvDone
		return send, recv, id, reused
	}

	// Leg 1: interrupt the transfer after the first committed block. Both peers persist the
	// transfer-scoped resume credential derived from the ORIGINAL session master.
	send1, recv1, id1, _ := runLeg(true, nil, nil, capsResume(), capsResume())
	if send1.err == nil || recv1.err == nil {
		t.Fatalf("interrupted leg unexpectedly succeeded: send=%v recv=%v", send1.err, recv1.err)
	}
	recvStore, err := OpenStore(outDir)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := recvStore.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].CommittedBytes <= 0 || entries[0].CommittedBytes >= int64(len(payload)) {
		t.Fatalf("leg 1 journal: %#v, want a strictly-partial committed checkpoint", entries)
	}
	srec, ok, err := senderStore.Lookup(PathKey(args))
	if err != nil || !ok {
		t.Fatalf("sender record not persisted after interruption: ok=%v err=%v", ok, err)
	}
	// Leg 1 minted a fresh id (the record carries it); the journal is keyed by it.
	j, ok, err := recvStore.LoadJournal(srec.TransferID)
	if err != nil || !ok {
		t.Fatalf("receiver journal not persisted: ok=%v err=%v", ok, err)
	}
	_ = id1
	if srec.ResumeSecret == nil || j.ResumeSecret == nil {
		t.Fatalf("resume credentials not persisted after leg 1: record=%v journal=%v", srec.ResumeSecret != nil, j.ResumeSecret != nil)
	}
	secret, err := wire.DecodeResumeSecretEnvelope(srec.ResumeSecret)
	if err != nil {
		t.Fatal(err)
	}
	jSecret, err := wire.DecodeResumeSecretEnvelope(&wire.ResumeSecretEnvelope{Version: j.ResumeSecret.Version, Value: j.ResumeSecret.Value})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret, jSecret) {
		t.Fatal("both peers must derive the same transfer-scoped credential")
	}

	// Leg 2: a FRESH rendezvous with authenticated cross-session resume. The sender reuses
	// its record (source identity re-verified) and the receiver pre-selects its journal;
	// both advertise resume-auth-v1, run the preamble BEFORE the manifest, then continue
	// under a fresh key epoch.
	send2, recv2, id2, reused := runLeg(false,
		&ResumeContext{TransferID: srec.TransferID, ManifestFingerprint: srec.ManifestFingerprint, Role: wire.RoleOfferer, ResumeSecret: secret},
		&ResumeContext{TransferID: j.TransferID, ManifestFingerprint: j.ManifestFingerprint, Role: wire.RoleJoiner, ResumeSecret: jSecret},
		capsResume(), capsResume())
	if send2.err != nil || recv2.err != nil {
		t.Fatalf("restart leg: send=%v recv=%v", send2.err, recv2.err)
	}
	if !reused || id2 != srec.TransferID {
		t.Fatalf("restart reused=%v id=%q, want reuse of %s", reused, id2, srec.TransferID)
	}
	if send2.out.Digest != recv2.out.Digest {
		t.Fatalf("digests differ: %s vs %s", send2.out.Digest, recv2.out.Digest)
	}
	got, err := os.ReadFile(filepath.Join(outDir, "payload.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("resumed receive produced %d bytes, want byte-identical payload", len(got))
	}
	// The receiver finalized: its journal is gone.
	entries, err = recvStore.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.TransferID == srec.TransferID && entry.JournalOK {
			t.Fatalf("journal %s still present after a verified resume", srec.TransferID)
		}
	}
	// Bounded cleanup: the completed send's record is discarded.
	if err := senderStore.Discard(srec.TransferID); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := senderStore.Lookup(PathKey(args)); err != nil || ok {
		t.Fatalf("sender record still present after discard: ok=%v err=%v", ok, err)
	}
}
