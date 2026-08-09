// Package transfer wires a completed rendezvous into a direct file transfer: it adopts
// the open signaling socket, brings up the authenticated WebRTC DataChannel (internal/rtc), and
// runs the transport-agnostic transfer engine (packages/wire) over it — the offerer sends the
// file, the joiner writes it to disk. It is the CLI counterpart of
// apps/web/src/lib/transfer/transfer-core.ts, adapted to Go concurrency and OS files.
package transfer

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/pion/webrtc/v4"
	"github.com/sendarc/cli/internal/rendezvous"
	"github.com/sendarc/cli/internal/rtc"
	"github.com/sendarc/wire"
)

// Signal is the live signaling connection the driver adopts for the whole exchange — first the
// handshake, then the sdp/ice negotiation. *wsclient.Client satisfies it; tests supply an
// in-memory relay.
type Signal interface {
	Send(rendezvous.Message) error
	Run(ctx context.Context, onMessage func(rendezvous.Message)) error
	Close()
}

// Controls is the live transfer surface exposed to terminal frontends.
type Controls interface {
	Pause() error
	Resume() error
	Cancel(reason string) error
}

// Spec configures one side of a transfer. Session carries the handshake inputs (role, code,
// caps, progress callbacks); the driver supplies its Transport. A sending (offerer) spec sets
// Source; a receiving (joiner) spec sets DestDir.
type Spec struct {
	Session rendezvous.Options
	// Source is the file to send; required for an offerer, ignored for a joiner.
	Source wire.FileSource
	// Sources is an ordered multi-file/folder set. Set either Source or Sources.
	Sources []wire.FileSource
	// DestDir is the directory the received file is written into; used by a joiner.
	DestDir string
	// ICEServers overrides rtc.DefaultICEServers. An explicit empty slice uses host candidates
	// only (loopback tests); nil takes the default STUN server.
	ICEServers []webrtc.ICEServer
	// OnConnect fires once the DataChannel opens, before the first byte moves.
	OnConnect func()
	// OnManifest fires on the receiver when the sender's manifest arrives (file named and sized).
	OnManifest func(wire.FileEntry)
	// OnManifestSet fires once with the complete validated file set.
	OnManifestSet func(wire.Manifest)
	// OnProgress reports cumulative bytes acknowledged after verify-and-sink.
	OnProgress     func(int64)
	OnFileProgress func(fileIdx int, fileBytes, acknowledgedBytes int64)
	// OnControls receives the live engine after the channel opens, before bytes begin moving.
	OnControls func(Controls)
	// OnStateChange reports pause, resume, and remote cancellation.
	OnStateChange func(wire.TransferState)
}

// Outcome is the result of a completed transfer.
type Outcome struct {
	Handshake *rendezvous.Result
	Name      string
	Size      int64
	Digest    string // whole-file SHA-256 (hex); identical on both peers
	Path      string // receiver: the written file; empty for a sender
	Files     []FileOutcome
}

// FileOutcome is one source or received destination within an Outcome.
type FileOutcome struct {
	Name   string
	Size   int64
	Digest string
	Path   string
}

// Run performs the handshake over sig and then the file transfer, returning when the transfer
// settles. It adopts sig for the whole exchange: the same socket that carries the SPAKE2
// handshake carries the sdp/ice signaling afterwards, so the read loop switches from feeding the
// session to feeding the peer once the key is established.
func Run(ctx context.Context, sig Signal, spec Spec) (*Outcome, error) {
	d := &driver{sig: sig, spec: spec, peerCh: make(chan *rtc.Peer, 1)}
	return d.run(ctx)
}

type driver struct {
	sig  Signal
	spec Spec

	mu   sync.Mutex // serializes every socket write (session, sendOffer, pion's ICE goroutine)
	sess *rendezvous.Session

	// peer and res are set once, by the read-loop goroutine, at establishment; peerCh publishes
	// the peer to run once it exists.
	peer   *rtc.Peer
	res    *rendezvous.Result
	peerCh chan *rtc.Peer
}

// Send implements rendezvous.Sink for the handshake session and doubles as the peer's send
// callback. It serializes every socket write: the read loop (relaying an answer),
// the offerer's sendOffer goroutine, and pion's ICE-candidate goroutine can all write at once,
// and coder/websocket permits only one writer at a time.
func (d *driver) Send(m rendezvous.Message) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sig.Send(m)
}

func (d *driver) run(ctx context.Context) (*Outcome, error) {
	opts := d.spec.Session
	opts.Transport = d
	d.sess = rendezvous.New(opts)

	// On a handshake failure, close the socket so the read loop unblocks; on success keep it
	// open — WebRTC signaling still needs it.
	go func() {
		<-d.sess.Done()
		if _, err := d.sess.Result(); err != nil {
			d.sig.Close()
		}
	}()

	readErr := make(chan error, 1)
	go func() { readErr <- d.sig.Run(ctx, d.route) }()

	d.sess.Start()

	var peer *rtc.Peer
	select {
	case peer = <-d.peerCh:
	case err := <-readErr:
		// The socket ended before the peer was built: surface the handshake failure, or a raw
		// transport error if it dropped mid-handshake.
		if _, herr := d.sess.Result(); herr != nil {
			return nil, herr
		}
		if err == nil {
			err = errors.New("transfer: signaling closed before the channel opened")
		}
		return nil, err
	case <-ctx.Done():
		d.sess.Abort("cancelled")
		return nil, ctx.Err()
	}

	res := d.res
	conn, err := peer.Channel(ctx)
	if err != nil {
		_ = peer.Close()
		d.sig.Close()
		return nil, fmt.Errorf("transfer: data channel: %w", err)
	}
	if d.spec.OnConnect != nil {
		d.spec.OnConnect()
	}

	out, terr := d.transfer(ctx, conn, res)

	// Drain the data channel before tearing down the peer: the first side to finish (the
	// receiver, once it has sent done) must let that final frame reach the wire, or closing the
	// PeerConnection aborts SCTP and the waiting sender never learns the transfer completed.
	_ = conn.Close()
	_ = peer.Close()
	d.sig.Close()
	<-readErr // let the read loop drain once the socket is closed

	if terr != nil {
		return nil, terr
	}
	out.Handshake = res
	return out, nil
}

// route is the single inbound dispatch. Before establishment it feeds the handshake session;
// the instant the session establishes it builds the peer — synchronously, so the peer exists
// before the next frame (the offer, for a joiner) is read — and thereafter feeds the peer.
// Running entirely on the read-loop goroutine makes the switch race-free.
func (d *driver) route(m rendezvous.Message) {
	if d.peer != nil {
		d.peer.Accept(m)
		return
	}
	d.sess.Handle(m)
	if d.peer != nil {
		return
	}
	select {
	case <-d.sess.Done():
	default:
		return // still handshaking
	}
	res, err := d.sess.Result()
	if err != nil {
		return // handshake failed; the watcher goroutine closes the socket
	}
	peer, perr := rtc.NewPeer(rtc.PeerOptions{
		Role:       res.Role,
		Auth:       rtc.FromSession(res.Role, res.Room, res.Spake2),
		Send:       d.Send,
		ICEServers: d.spec.ICEServers,
	})
	if perr != nil {
		d.sig.Close() // unrecoverable; run's readErr branch reports it
		return
	}
	d.res = res
	d.peer = peer
	d.peerCh <- peer
}

// transfer runs the engine over the open channel: the offerer sends its file, the joiner
// receives one. Counters continue from the handshake so the AES-GCM nonce is never reused, and
// block/frame sizes are the min of the two peers' announced caps. Canceling ctx aborts the
// in-flight transfer.
func (d *driver) transfer(ctx context.Context, conn *rtc.DataConn, res *rendezvous.Result) (*Outcome, error) {
	sendDir, recvDir := directionalKeys(res)
	if res.Role == wire.RoleOfferer {
		return d.send(ctx, conn, res, sendDir, recvDir)
	}
	return d.receive(ctx, conn, res, sendDir, recvDir)
}

func (d *driver) send(ctx context.Context, conn *rtc.DataConn, res *rendezvous.Result, sendDir, recvDir wire.DirectionalKey) (*Outcome, error) {
	if (d.spec.Source == nil) == (len(d.spec.Sources) == 0) {
		return nil, errors.New("transfer: exactly one of Source or Sources is required to send")
	}
	sources := d.spec.Sources
	if len(sources) == 0 {
		sources = []wire.FileSource{d.spec.Source}
	}
	needsFolders := len(sources) > 1
	for _, source := range sources {
		if strings.Contains(source.Meta().Name, "/") {
			needsFolders = true
		}
	}
	if needsFolders && !containsString(res.RemoteCaps.Features, "folders") {
		return nil, errors.New("transfer: receiver does not support files or folders as a set")
	}
	sender := wire.NewSender(wire.SenderOptions{
		Files:            sources,
		Send:             conn.Send,
		SendDir:          sendDir,
		RecvDir:          recvDir,
		SendCounterStart: res.SendCounter,
		RecvCounterStart: res.RecvCounter,
		BlockSize:        negotiate(res.LocalCaps.BlockSize, res.RemoteCaps.BlockSize, wire.DefaultBlockBytes),
		FrameSize:        negotiate(res.LocalCaps.MaxFrame, res.RemoteCaps.MaxFrame, wire.DefaultFrameBytes),
		OnProgress:       d.spec.OnProgress,
		OnFileProgress:   d.spec.OnFileProgress,
		OnStateChange:    d.spec.OnStateChange,
	})
	conn.OnData(sender.Handle)
	if d.spec.OnControls != nil {
		d.spec.OnControls(sender)
	}
	digest, err := sender.Run(ctx)
	if err != nil {
		return nil, err
	}
	files := make([]FileOutcome, len(sources))
	var total int64
	for i, source := range sources {
		meta := source.Meta()
		files[i] = FileOutcome{Name: meta.Name, Size: meta.Size}
		total += meta.Size
	}
	return &Outcome{Name: files[0].Name, Size: total, Digest: digest, Files: files}, nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func (d *driver) receive(ctx context.Context, conn *rtc.DataConn, res *rendezvous.Result, sendDir, recvDir wire.DirectionalKey) (*Outcome, error) {
	destination, err := NewOSDestination(d.spec.DestDir)
	if err != nil {
		return nil, wire.NewTransferError(wire.FailSinkError, err.Error())
	}
	receiver := wire.NewReceiver(wire.ReceiverOptions{
		Send:             conn.Send,
		SendDir:          sendDir,
		RecvDir:          recvDir,
		SendCounterStart: res.SendCounter,
		RecvCounterStart: res.RecvCounter,
		Destination:      destination,
		OnProgress:       d.spec.OnProgress,
		OnFileProgress:   d.spec.OnFileProgress,
		OnStateChange:    d.spec.OnStateChange,
		OnManifestSet: func(manifest wire.Manifest) error {
			if d.spec.OnManifestSet != nil {
				d.spec.OnManifestSet(manifest)
			}
			return nil
		},
		OnManifest: func(file wire.FileEntry) error {
			if d.spec.OnManifest != nil {
				d.spec.OnManifest(file)
			}
			return nil
		},
	})
	conn.OnData(receiver.Handle)
	if d.spec.OnControls != nil {
		d.spec.OnControls(receiver)
	}
	result, err := receiver.Wait(ctx)
	if err != nil {
		return nil, err
	}
	files := make([]FileOutcome, len(result.Files))
	for i, file := range result.Files {
		files[i] = FileOutcome{Name: file.Name, Size: file.Size, Digest: result.Digests[i], Path: destination.Path(file.Idx)}
	}
	return &Outcome{
		Name: result.File.Name, Size: result.TotalSize, Digest: result.Digest,
		Path: destination.Path(result.File.Idx), Files: files,
	}, nil
}

// directionalKeys selects the seal/open keys for this peer's role, mirroring the session's
// sendDir/recvDir: the offerer sends on O2J and receives on J2O; the joiner is the mirror.
func directionalKeys(res *rendezvous.Result) (send, recv wire.DirectionalKey) {
	if res.Role == wire.RoleOfferer {
		return res.Keys.O2J, res.Keys.J2O
	}
	return res.Keys.J2O, res.Keys.O2J
}

// negotiate picks the smaller of the two announced sizes, falling back to def if either side did
// not announce a positive value. Both peers compute the same result from the same caps.
func negotiate(local, remote, def int) int {
	m := local
	if remote < m {
		m = remote
	}
	if m <= 0 {
		return def
	}
	return m
}
