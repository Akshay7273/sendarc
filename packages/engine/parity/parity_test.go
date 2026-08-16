// Package parity_test exercises the shared SendBeam engine strictly through its exported
// API — exactly as apps/cli and the future desktop client consume it — and pins behavior
// parity: a full send/receive transfer completes with verified, byte-identical output over
// both the direct (WebRTC) and forced-relay byte paths, and an interrupted transfer resumes
// only through authenticated cross-session resume-auth with the same verified output.
//
// No engine internals and no CLI code are referenced: the relay below is a minimal
// in-process stand-in for the signaling server, and everything else is public API
// (transfer.Run/Spec, rendezvous.Options, DurableStore, SenderStore, wire helpers).
package parity_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/wire"
)

// relay is an in-memory stand-in for the signaling server: it allocates a room on create,
// pairs on join (notifying each side with its own role), and forwards every other message
// verbatim to the partner, exactly as apps/server does.
type relay struct {
	off     *relayEnd
	join    *relayEnd
	room    int
	created chan struct{}
	once    sync.Once
	mu      sync.Mutex
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

// route mirrors the server's dispatch; a join blocks until the room exists, matching the
// guarantee that a joiner cannot pair before the offerer (it needs the code).
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

// relayEnd is one side of the relay and satisfies transfer.Signal + transfer.ReconnectSetter,
// so a driver adopts it exactly as it would a real *wsclient.ReconnectingSignal.
type relayEnd struct {
	hub       *relay
	role      string
	in        chan rendezvous.Message
	bin       chan []byte
	relayOpen bool
	once      sync.Once
	done      chan struct{}
}

func newRelayEnd(hub *relay, role string) *relayEnd {
	return &relayEnd{
		hub: hub, role: role,
		in: make(chan rendezvous.Message, 256), bin: make(chan []byte, 256),
		done: make(chan struct{}),
	}
}

func (e *relayEnd) SetResume(_ int, _ string) {}

func (e *relayEnd) Send(m rendezvous.Message) error {
	e.hub.route(e, m)
	return nil
}

func (e *relayEnd) SendBinary(frame []byte) error {
	e.hub.partner(e).enqueueBinary(frame)
	return nil
}

func (e *relayEnd) Run(ctx context.Context, onMessage func(rendezvous.Message), onBinary func([]byte)) error {
	for {
		select {
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

func (e *relayEnd) Close() { e.once.Do(func() { close(e.done) }) }

func (e *relayEnd) enqueueBinary(frame []byte) {
	select {
	case e.bin <- append([]byte(nil), frame...):
	case <-e.done:
	}
}

func (e *relayEnd) enqueue(m rendezvous.Message) {
	select {
	case e.in <- m:
	case <-e.done:
	}
}

type result struct {
	out *transfer.Outcome
	err error
}

// runPair runs one send+receive pair concurrently through transfer.Run and returns both
// results. It mirrors the CLI: the sender carries an OS-file source + restart record, the
// receiver writes into a durable destination directory. sendMut/recvMut let a test tweak
// each side's spec (forced relay, transport callbacks, resume contexts).
func runPair(ctx context.Context, t *testing.T, hub *relay, senderStore *transfer.SenderStore, outDir string, paths []string, sendMut, recvMut func(s *transfer.Spec)) (send, recv result) {
	t.Helper()
	sources, _, err := transfer.NewOSFileSources(paths)
	if err != nil {
		t.Fatal(err)
	}
	id, onManifest, reused, err := transfer.PrepareSender(senderStore, paths, sources)
	if err != nil {
		t.Fatal(err)
	}
	sendDone := make(chan result, 1)
	recvDone := make(chan result, 1)
	go func() {
		spec := transfer.Spec{
			Session:        rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "alpha-bravo"},
			Sources:        sources,
			TransferID:     id,
			OnSendManifest: onManifest,
			OnResumeCredential: func(manifest wire.Manifest, resumeRoot []byte) error {
				return senderStore.AttachResumeSecret(manifest, resumeRoot, !reused)
			},
			ICEServers: []webrtc.ICEServer{}, // host candidates only; loopback needs no STUN
		}
		if sendMut != nil {
			sendMut(&spec)
		}
		out, err := transfer.Run(ctx, hub.off, spec)
		sendDone <- result{out, err}
	}()
	go func() {
		spec := transfer.Spec{
			Session:    rendezvous.Options{Role: rendezvous.RoleJoiner, Code: "7-alpha-bravo"},
			DestDir:    outDir,
			ICEServers: []webrtc.ICEServer{},
		}
		if recvMut != nil {
			recvMut(&spec)
		}
		out, err := transfer.Run(ctx, hub.join, spec)
		recvDone <- result{out, err}
	}()
	// Wait for whichever side settles first.
	select {
	case s := <-sendDone:
		send = s
		recv = <-recvDone
	case r := <-recvDone:
		recv = r
		send = <-sendDone
	}
	return send, recv
}

func resumeCaps() *rendezvous.Caps {
	c := rendezvous.DefaultCaps()
	c.Features = append(c.Features, wire.ResumeAuthCapability)
	return &c
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestParityLoopbackTransferDirect runs a full transfer through the public engine API over
// the authenticated direct (WebRTC) path: SPAKE2 rendezvous, sealed transfer, durable
// receive, whole-file verification. The receiver's output must be byte-identical with
// matching digests and the durable journal must be removed after verified finalization.
func TestParityLoopbackTransferDirect(t *testing.T) {
	payload := make([]byte, 1<<20+40000) // crosses a 1 MiB block boundary, uneven frames
	for i := range payload {
		payload[i] = byte(i*31 + 7)
	}
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(srcPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	senderStore, err := transfer.OpenSenderStore(filepath.Join(dir, "sender"))
	if err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	send, recv := runPair(ctx, t, newRelay(), senderStore, outDir, []string{srcPath}, nil, nil)
	if send.err != nil {
		t.Fatalf("sender failed: %v", send.err)
	}
	if recv.err != nil {
		t.Fatalf("receiver failed: %v", recv.err)
	}
	if send.out.Digest == "" || send.out.Digest != recv.out.Digest {
		t.Fatalf("digest parity broken: send=%q recv=%q", send.out.Digest, recv.out.Digest)
	}
	if recv.out.Digest != sha256Hex(payload) {
		t.Fatalf("received digest %q != source digest %q", recv.out.Digest, sha256Hex(payload))
	}
	got, err := os.ReadFile(filepath.Join(outDir, "payload.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("received file is not byte-identical to the source")
	}
	// Verified finalization removes the durable journal (PR02 contract).
	store, err := transfer.OpenStore(outDir)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("journal must be gone after verified finalization, found %d entries", len(entries))
	}
}

// TestParityLoopbackTransferRelay runs the same public-API transfer over the forced
// encrypted relay, proving the relay + supervisor + sealed-channel path is equally
// consumable and byte-identical.
func TestParityLoopbackTransferRelay(t *testing.T) {
	payload := make([]byte, 300_000)
	for i := range payload {
		payload[i] = byte(i*13 + 3)
	}
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(srcPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	senderStore, err := transfer.OpenSenderStore(filepath.Join(dir, "sender"))
	if err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}

	var sendTransport, recvTransport string
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	send, recv := runPair(ctx, t, newRelay(), senderStore, outDir, []string{srcPath},
		func(s *transfer.Spec) {
			s.ForceRelay = true
			s.OnTransport = func(p string) { sendTransport = p }
		},
		func(s *transfer.Spec) {
			s.OnTransport = func(p string) { recvTransport = p }
		},
	)
	if send.err != nil {
		t.Fatalf("sender failed: %v", send.err)
	}
	if recv.err != nil {
		t.Fatalf("receiver failed: %v", recv.err)
	}
	if sendTransport != "relay" || recvTransport != "relay" {
		t.Fatalf("forced relay must select the relay path on both peers: send=%q recv=%q", sendTransport, recvTransport)
	}
	if send.out.Digest == "" || send.out.Digest != recv.out.Digest || recv.out.Digest != sha256Hex(payload) {
		t.Fatalf("relay digest parity broken: send=%q recv=%q want=%q", send.out.Digest, recv.out.Digest, sha256Hex(payload))
	}
	got, err := os.ReadFile(filepath.Join(outDir, "payload.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("relayed output is not byte-identical to the source")
	}
}

// TestParityCrossSessionResume runs an interrupted first leg (canceled mid-transfer), then
// an authenticated resume leg through the public engine API: the sender reuses its record,
// the receiver reuses its journal, mutual resume-auth-v1 authenticates, only verified
// progress is reused, and the final output is byte-identical.
func TestParityCrossSessionResume(t *testing.T) {
	payload := make([]byte, 4<<20)
	for i := range payload {
		payload[i] = byte(i*3 + 1)
	}
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(srcPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	senderStore, err := transfer.OpenSenderStore(filepath.Join(dir, "sender"))
	if err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	paths := []string{srcPath}

	// Leg 1: cancel once the first verified block is acknowledged; both sides must fail and
	// leave a sender record + receiver journal carrying the resume credential.
	legCtx, legCancel := context.WithCancel(context.Background())
	firstProgress := make(chan struct{})
	var once sync.Once
	hub := newRelay()
	sendDone := make(chan result, 1)
	recvDone := make(chan result, 1)
	sources, _, err := transfer.NewOSFileSources(paths)
	if err != nil {
		t.Fatal(err)
	}
	id, onManifest, reused, err := transfer.PrepareSender(senderStore, paths, sources)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		spec := transfer.Spec{
			Session:        rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "alpha-bravo", LocalCaps: resumeCaps()},
			Sources:        sources,
			TransferID:     id,
			OnSendManifest: onManifest,
			OnResumeCredential: func(manifest wire.Manifest, resumeRoot []byte) error {
				return senderStore.AttachResumeSecret(manifest, resumeRoot, !reused)
			},
			ICEServers: []webrtc.ICEServer{},
		}
		out, err := transfer.Run(legCtx, hub.off, spec)
		sendDone <- result{out, err}
	}()
	go func() {
		first := func() {
			once.Do(func() { close(firstProgress) })
		}
		spec := transfer.Spec{
			Session:    rendezvous.Options{Role: rendezvous.RoleJoiner, Code: "7-alpha-bravo", LocalCaps: resumeCaps()},
			DestDir:    outDir,
			ICEServers: []webrtc.ICEServer{},
			OnProgress: func(int64) { first() },
		}
		out, err := transfer.Run(legCtx, hub.join, spec)
		recvDone <- result{out, err}
	}()
	go func() {
		select {
		case <-firstProgress:
			legCancel()
		case <-legCtx.Done():
		}
	}()
	send := <-sendDone
	recv := <-recvDone
	if send.err == nil || recv.err == nil {
		t.Fatalf("interrupted leg unexpectedly succeeded: send=%v recv=%v", send.err, recv.err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "payload.bin")); err == nil {
		t.Fatal("interrupted leg must not produce the final file")
	}

	// The sender record and receiver journal must carry the transfer-scoped credential.
	srec, ok, err := senderStore.Lookup(transfer.PathKey(paths))
	if err != nil || !ok {
		t.Fatalf("sender record missing after interruption: ok=%v err=%v", ok, err)
	}
	if srec.ResumeSecret == nil {
		t.Fatal("sender record must carry the resume credential")
	}
	recvStore, err := transfer.OpenStore(outDir)
	if err != nil {
		t.Fatal(err)
	}
	j, ok, err := recvStore.LoadJournal(srec.TransferID)
	if err != nil || !ok {
		t.Fatalf("receiver journal missing after interruption: ok=%v err=%v", ok, err)
	}
	if j.ResumeSecret == nil {
		t.Fatal("receiver journal must carry the resume credential")
	}
	if srec.TransferID != j.TransferID {
		t.Fatalf("sender/receiver transfer id mismatch: %q != %q", srec.TransferID, j.TransferID)
	}

	// Leg 2: authenticated resume through the public API. Both peers advertise resume-auth-v1
	// and carry their local resume context; mutual auth must complete and the output must be
	// byte-identical.
	sendSecret, err := wire.DecodeResumeSecretEnvelope(srec.ResumeSecret)
	if err != nil {
		t.Fatal(err)
	}
	recvSecret, err := wire.DecodeResumeSecretEnvelope(&wire.ResumeSecretEnvelope{Version: j.ResumeSecret.Version, Value: j.ResumeSecret.Value})
	if err != nil {
		t.Fatal(err)
	}
	var sendAuth, recvAuth bool
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	hub2 := newRelay()
	send2Done := make(chan result, 1)
	recv2Done := make(chan result, 1)
	sources2, _, err := transfer.NewOSFileSources(paths)
	if err != nil {
		t.Fatal(err)
	}
	id2, onManifest2, reused2, err := transfer.PrepareSender(senderStore, paths, sources2)
	if err != nil {
		t.Fatal(err)
	}
	if id2 != srec.TransferID {
		t.Fatalf("resume must reuse the transfer id: got %q want %q", id2, srec.TransferID)
	}
	go func() {
		spec := transfer.Spec{
			Session:        rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "alpha-bravo", LocalCaps: resumeCaps()},
			Sources:        sources2,
			TransferID:     id2,
			OnSendManifest: onManifest2,
			OnResumeCredential: func(manifest wire.Manifest, resumeRoot []byte) error {
				return senderStore.AttachResumeSecret(manifest, resumeRoot, !reused2)
			},
			Resume: &transfer.ResumeContext{
				TransferID:          srec.TransferID,
				ManifestFingerprint: srec.ManifestFingerprint,
				Role:                wire.RoleOfferer,
				ResumeSecret:        sendSecret,
			},
			OnResume: func(r transfer.ResumeResult) {
				if r.Attempted && r.Authenticated {
					sendAuth = true
				}
			},
			ICEServers: []webrtc.ICEServer{},
		}
		out, err := transfer.Run(ctx, hub2.off, spec)
		send2Done <- result{out, err}
	}()
	go func() {
		spec := transfer.Spec{
			Session: rendezvous.Options{Role: rendezvous.RoleJoiner, Code: "7-alpha-bravo", LocalCaps: resumeCaps()},
			DestDir: outDir,
			Resume: &transfer.ResumeContext{
				TransferID:          j.TransferID,
				ManifestFingerprint: j.ManifestFingerprint,
				Role:                wire.RoleJoiner,
				ResumeSecret:        recvSecret,
			},
			OnResume: func(r transfer.ResumeResult) {
				if r.Attempted && r.Authenticated {
					recvAuth = true
				}
			},
			ICEServers: []webrtc.ICEServer{},
		}
		out, err := transfer.Run(ctx, hub2.join, spec)
		recv2Done <- result{out, err}
	}()
	send2 := <-send2Done
	recv2 := <-recv2Done
	if send2.err != nil {
		t.Fatalf("resume sender failed: %v", send2.err)
	}
	if recv2.err != nil {
		t.Fatalf("resume receiver failed: %v", recv2.err)
	}
	if !sendAuth || !recvAuth {
		t.Fatalf("resume-auth must authenticate both peers: sendAuth=%v recvAuth=%v", sendAuth, recvAuth)
	}
	if send2.out.Digest == "" || send2.out.Digest != recv2.out.Digest || recv2.out.Digest != sha256Hex(payload) {
		t.Fatalf("resume digest parity broken: send=%q recv=%q want=%q", send2.out.Digest, recv2.out.Digest, sha256Hex(payload))
	}
	got, err := os.ReadFile(filepath.Join(outDir, "payload.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("resumed output is not byte-identical to the source")
	}
	// Verified finalization removes the receiver journal.
	if _, ok, err := recvStore.LoadJournal(j.TransferID); err != nil || ok {
		t.Fatalf("journal must be gone after verified resume finalization: ok=%v err=%v", ok, err)
	}
}
