// Package wsclient binds a rendezvous.Session to the SendBeam signaling server over a
// WebSocket. It is the CLI's counterpart to the browser's SignalingClient +
// rendezvous orchestrator (apps/web/src/lib/signaling, .../session): it dials the
// server, JSON-encodes the session's outbound messages as text frames, decodes inbound
// frames back into rendezvous.Message, and drives one handshake to completion.
package wsclient

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/sendbeam/engine/rendezvous"
)

// reconnectRetries bounds how many times a post-establishment socket drop is re-dialed and
// resumed before the read loop gives up and surfaces the terminal error (the driver then keeps
// a healthy direct path alive, or fails a relay path). Never infinite.
const reconnectRetries = 5

// reconnectBaseDelay is the base backoff between reconnect attempts.
const reconnectBaseDelay = 250 * time.Millisecond

// reconnectMaxDelay caps the reconnect backoff.
const reconnectMaxDelay = 4 * time.Second

// serverControlTypes are server→client control frames the reconnecting signal consumes
// internally during the room resume flow: they describe signaling-room state, not application
// frames, and would otherwise be mis-fed to the peer/relay transfer layer.
var serverControlTypes = map[string]bool{
	"resumed":       true, // the server re-attached this peer to its lingering room
	"peer_left":     true, // the partner's socket dropped; room is resumable (byte path may live on)
	"peer_rejoined": true, // the partner re-attached to the room
}

// ReconnectingSignal is a transfer.Signal (see apps/cli/internal/transfer) whose socket is
// re-established after a post-establishment drop: it re-dials the server and resends the room
// `resume` request so the room re-attaches, keeping an established direct transfer healthy
// through a signaling blip and restoring signaling for a later ICE-restart renegotiation.
//
// It must be told the room number and role (SetResume) once the handshake settles — before
// that, a drop is a handshake failure like the base client. Reconnect is bounded and cancellable.
type ReconnectingSignal struct {
	url   string
	dopts DialOptions

	mu     sync.Mutex
	cur    *Client
	closed bool

	room      int
	role      string
	resumeSet bool
}

// NewReconnectingSignal builds a signal that re-establishes the signaling socket on drop. The
// first connection is dialed eagerly (with the base backoff) so Sends succeed immediately; it
// returns an error only if the initial connect fails, mirroring the base wsclient.Dial.
func NewReconnectingSignal(ctx context.Context, url string, dopts DialOptions) (*ReconnectingSignal, error) {
	client, err := Dial(ctx, url, dopts)
	if err != nil {
		return nil, err
	}
	return &ReconnectingSignal{url: url, dopts: dopts, cur: client}, nil
}

// SetResume records the room and role once the handshake settles, enabling post-establishment
// reconnect. Must be called before any drop that should reconnect.
func (s *ReconnectingSignal) SetResume(room int, role string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.room = room
	s.role = role
	s.resumeSet = true
}

// Send writes one signaling message to the current socket.
func (s *ReconnectingSignal) Send(m rendezvous.Message) error {
	s.mu.Lock()
	c := s.cur
	s.mu.Unlock()
	if c == nil {
		return errors.New("wsclient: signaling not connected")
	}
	return c.Send(m)
}

// SendBinary writes one opaque encrypted relay frame to the current socket.
func (s *ReconnectingSignal) SendBinary(frame []byte) error {
	s.mu.Lock()
	c := s.cur
	s.mu.Unlock()
	if c == nil {
		return errors.New("wsclient: signaling not connected")
	}
	return c.SendBinary(frame)
}

// Run reads and dispatches inbound frames, re-establishing the socket on a post-establishment
// drop while resume info is set. It returns when the socket closes cleanly, the caller closes,
// ctx is cancelled, or reconnect attempts are exhausted.
func (s *ReconnectingSignal) Run(
	ctx context.Context,
	onMessage func(rendezvous.Message),
	onBinary func([]byte),
) error {
	for {
		s.mu.Lock()
		c := s.cur
		s.mu.Unlock()
		if c == nil {
			return errors.New("wsclient: signaling not connected")
		}
		runErr := c.Run(ctx, s.filter(onMessage), onBinary)
		if runErr == nil {
			return nil // clean close
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !s.wantReconnect() {
			return runErr
		}
		if !s.reconnect(ctx) {
			return runErr
		}
	}
}

// wantReconnect reports whether a drop should trigger a reconnect: resume info is set and the
// signal is not closed.
func (s *ReconnectingSignal) wantReconnect() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resumeSet && !s.closed
}

// reconnect re-establishes the socket: re-dial with bounded backoff and resend the resume
// request so the room re-attaches. Returns true on success.
func (s *ReconnectingSignal) reconnect(ctx context.Context) bool {
	for n := 0; n < reconnectRetries; n++ {
		s.mu.Lock()
		room, role := s.room, s.role
		closed := s.closed
		s.mu.Unlock()
		if closed || ctx.Err() != nil {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(reconnectDelay(n)):
		}
		client, err := Dial(ctx, s.url, s.dopts)
		if err != nil {
			continue
		}
		s.swap(client)
		if err := client.Send(rendezvous.Message{Type: "resume", Room: &room, Role: role}); err != nil {
			client.Close()
			continue
		}
		return true
	}
	return false
}

// filter wraps the inbound dispatch so server-control frames are consumed internally rather
// than forwarded to the transfer layer, which only understands application signaling and relay
// frames.
func (s *ReconnectingSignal) filter(onMessage func(rendezvous.Message)) func(rendezvous.Message) {
	return func(m rendezvous.Message) {
		if serverControlTypes[m.Type] {
			return
		}
		onMessage(m)
	}
}

func (s *ReconnectingSignal) swap(c *Client) {
	s.mu.Lock()
	old := s.cur
	s.cur = c
	s.mu.Unlock()
	if old != nil {
		old.Close()
	}
}

// Close tears down the signal. Idempotent.
func (s *ReconnectingSignal) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	c := s.cur
	s.mu.Unlock()
	if c != nil {
		c.Close()
	}
}

// reconnectDelay computes the bounded backoff for attempt n.
func reconnectDelay(n int) time.Duration {
	d := reconnectBaseDelay
	for i := 0; i < n; i++ {
		d *= 2
	}
	if d > reconnectMaxDelay {
		d = reconnectMaxDelay
	}
	return d
}
