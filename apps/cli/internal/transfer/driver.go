// Package transfer wires a completed M1 rendezvous into an M2 direct file transfer: it adopts
// the open signaling socket, brings up the authenticated WebRTC DataChannel (internal/rtc), and
// runs the transport-agnostic transfer engine (packages/wire) over it — the offerer sends the
// file, the joiner writes it to disk. It is the CLI counterpart of
// apps/web/src/lib/transfer/transfer-core.ts, adapted to Go concurrency and OS files.
package transfer

import (
	"context"
	"errors"
	"fmt"
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

// Spec configures one side of a transfer. Session carries the handshake inputs (role, code,
// caps, progress callbacks); the driver supplies its Transport. A sending (offerer) spec sets
// Source; a receiving (joiner) spec sets DestDir.
type Spec struct {
	Session rendezvous.Options
	// Source is the file to send; required for an offerer, ignored for a joiner.
	Source wire.FileSource
	// DestDir is the directory the received file is written into; used by a joiner.
	DestDir string
	// ICEServers overrides rtc.DefaultICEServers. An explicit empty slice uses host candidates
	// only (loopback tests); nil takes the default STUN server.
	ICEServers []webrtc.ICEServer
	// OnConnect fires once the DataChannel opens, before the first byte moves.
	OnConnect func()
	// OnManifest fires on the receiver when the sender's manifest arrives (file named and sized).
	OnManifest func(wire.FileEntry)
	// OnProgress reports cumulative bytes transferred.
	OnProgress func(int64)
}

// Outcome is the result of a completed transfer.
type Outcome struct {
	Handshake *rendezvous.Result
	Name      string
	Size      int64
	Digest    string // whole-file SHA-256 (hex); identical on both peers
	Path      string // receiver: the written file; empty for a sender
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
// callback. It serializes every socket write: during M2 the read loop (relaying an answer),
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
	// open — the M2 signaling still needs it.
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
	if d.spec.Source == nil {
		return nil, errors.New("transfer: a file source is required to send")
	}
	sender := wire.NewSender(wire.SenderOptions{
		File:             d.spec.Source,
		Send:             conn.Send,
		SendDir:          sendDir,
		RecvDir:          recvDir,
		SendCounterStart: res.SendCounter,
		RecvCounterStart: res.RecvCounter,
		BlockSize:        negotiate(res.LocalCaps.BlockSize, res.RemoteCaps.BlockSize, wire.DefaultBlockBytes),
		FrameSize:        negotiate(res.LocalCaps.MaxFrame, res.RemoteCaps.MaxFrame, wire.DefaultFrameBytes),
		OnProgress:       d.spec.OnProgress,
	})
	conn.OnData(sender.Handle)
	digest, err := sender.Run(ctx)
	if err != nil {
		return nil, err
	}
	meta := d.spec.Source.Meta()
	return &Outcome{Name: meta.Name, Size: meta.Size, Digest: digest}, nil
}

func (d *driver) receive(ctx context.Context, conn *rtc.DataConn, res *rendezvous.Result, sendDir, recvDir wire.DirectionalKey) (*Outcome, error) {
	deferred := &deferredSink{}
	var sinkPath string
	receiver := wire.NewReceiver(wire.ReceiverOptions{
		Send:             conn.Send,
		SendDir:          sendDir,
		RecvDir:          recvDir,
		SendCounterStart: res.SendCounter,
		RecvCounterStart: res.RecvCounter,
		Sink:             deferred,
		OnProgress:       d.spec.OnProgress,
		OnManifest: func(file wire.FileEntry) error {
			// Open the destination lazily, named after the (sanitized) manifest file, before the
			// first block is written — the browser DeferredSink pattern.
			sink, err := NewOSFileSink(d.spec.DestDir, file.Name)
			if err != nil {
				return wire.NewTransferError(wire.FailSinkError, err.Error())
			}
			deferred.attach(sink)
			sinkPath = sink.Path()
			if d.spec.OnManifest != nil {
				d.spec.OnManifest(file)
			}
			return nil
		},
	})
	conn.OnData(receiver.Handle)
	result, err := receiver.Wait(ctx)
	if err != nil {
		return nil, err
	}
	return &Outcome{Name: result.File.Name, Size: result.File.Size, Digest: result.Digest, Path: sinkPath}, nil
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
