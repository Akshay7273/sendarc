// Package wsclient binds a rendezvous.Session to the SendArc signaling server over a
// WebSocket. It is the CLI's counterpart to the browser's SignalingClient +
// rendezvous orchestrator (apps/web/src/lib/signaling, .../session): it dials the
// server, JSON-encodes the session's outbound messages as text frames, decodes inbound
// frames back into rendezvous.Message, and drives one handshake to completion.
//
// As in the browser, reconnection is limited to the initial connect. Once the socket is
// open the server holds this session's room on this connection; a drop tears the room
// down and notifies the peer with bye, so a fresh socket cannot resume it (recovery under
// the same code is deferred to M6). A post-open drop is surfaced as a terminal failure.
package wsclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/sendarc/cli/internal/rendezvous"
)

const (
	// writeTimeout bounds a single frame write. Rendezvous frames are tiny, so a write
	// that cannot complete in this window means the socket is wedged.
	writeTimeout = 10 * time.Second
	// readLimit caps a single inbound frame. Server control frames and relayed caps are
	// small; this guards against a rogue server streaming unbounded data at the client.
	readLimit = 1 << 20
)

// BackoffOptions is the schedule for retrying the initial connect. Delays are
// base * factor^n, capped at max, with up to jitter extra to avoid synchronized retries.
type BackoffOptions struct {
	Retries int
	Base    time.Duration
	Max     time.Duration
	Factor  float64
	Jitter  float64
}

// DefaultBackoff mirrors the browser client's schedule (client.ts DEFAULT_BACKOFF).
var DefaultBackoff = BackoffOptions{
	Retries: 5,
	Base:    250 * time.Millisecond,
	Max:     4 * time.Second,
	Factor:  2,
	Jitter:  0.25,
}

// DialOptions configures how the client connects.
type DialOptions struct {
	// InsecureSkipVerify disables TLS certificate verification. It is meant for a
	// self-signed development certificate (e.g. mkcert) and must not be used otherwise.
	InsecureSkipVerify bool
	// Backoff overrides the initial-connect retry schedule. The zero value uses
	// DefaultBackoff.
	Backoff BackoffOptions
}

// Client is a live signaling connection. It implements rendezvous.Sink, writing each
// message as a WebSocket text frame. All writes happen on the goroutine that drives the
// session (Start plus the Run read loop), so there is never more than one concurrent
// writer; Close is the only method safe to call from another goroutine.
type Client struct {
	ws        *websocket.Conn
	closeOnce sync.Once
}

// Dial connects to the signaling endpoint at url, retrying the initial connect with
// backoff so a briefly-unreachable server (cold start, flaky network) does not fail the
// session before it begins.
func Dial(ctx context.Context, url string, opts DialOptions) (*Client, error) {
	b := opts.Backoff
	if b == (BackoffOptions{}) {
		b = DefaultBackoff
	}

	dialOpts := &websocket.DialOptions{}
	if opts.InsecureSkipVerify {
		dialOpts.HTTPClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // opt-in dev flag
			},
		}
	}

	var lastErr error
	for n := 0; ; n++ {
		ws, _, err := websocket.Dial(ctx, url, dialOpts)
		if err == nil {
			ws.SetReadLimit(readLimit)
			return &Client{ws: ws}, nil
		}
		lastErr = err
		if n >= b.Retries || ctx.Err() != nil {
			return nil, fmt.Errorf("wsclient: connect to %s failed after %d attempt(s): %w", url, n+1, lastErr)
		}
		select {
		case <-time.After(backoffDelay(b, n)):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func backoffDelay(b BackoffOptions, n int) time.Duration {
	d := float64(b.Base)
	for i := 0; i < n; i++ {
		d *= b.Factor
	}
	if d > float64(b.Max) {
		d = float64(b.Max)
	}
	return time.Duration(d * (1 + rand.Float64()*b.Jitter))
}

// Send writes one signaling message as a text frame, satisfying rendezvous.Sink.
func (c *Client) Send(m rendezvous.Message) error {
	data, err := rendezvous.MarshalMessage(m)
	if err != nil {
		return err
	}
	// A dedicated timeout context (not the session's) so a farewell bye written during
	// cancellation still gets a chance to flush.
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	return c.ws.Write(ctx, websocket.MessageText, data)
}

// Run reads inbound frames and dispatches each to onMessage until the socket closes or
// ctx is cancelled, then returns the terminating error. Closing the socket (Close) is the
// clean way to stop it.
func (c *Client) Run(ctx context.Context, onMessage func(rendezvous.Message)) error {
	for {
		typ, data, err := c.ws.Read(ctx)
		if err != nil {
			return err
		}
		if typ != websocket.MessageText {
			return errors.New("wsclient: expected a text frame")
		}
		msg, err := rendezvous.UnmarshalMessage(data)
		if err != nil {
			return fmt.Errorf("wsclient: malformed frame: %w", err)
		}
		onMessage(msg)
	}
}

// Close closes the socket. It is idempotent and safe to call from any goroutine, so it can
// unblock Run from a watcher when the session settles.
func (c *Client) Close() {
	c.closeOnce.Do(func() {
		_ = c.ws.Close(websocket.StatusNormalClosure, "")
	})
}

// Rendezvous dials the server and drives one handshake to completion: it wires the session
// to the socket, starts it, pumps inbound frames, and returns the session result. sopts
// carries the role and its inputs; its Transport is set here and any provided value is
// ignored.
func Rendezvous(ctx context.Context, url string, dopts DialOptions, sopts rendezvous.Options) (*rendezvous.Result, error) {
	client, err := Dial(ctx, url, dopts)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	sopts.Transport = client
	sess := rendezvous.New(sopts)

	// Close the socket once the handshake settles, so the read loop below unblocks.
	go func() {
		<-sess.Done()
		client.Close()
	}()

	sess.Start()
	if err := client.Run(ctx, sess.Handle); err != nil {
		// The read loop ended. If we were cancelled (Ctrl-C), abort with a best-effort
		// bye; otherwise the socket dropped mid-handshake — fail closed. Either is a
		// no-op if the session already settled (the normal close from the watcher).
		if ctx.Err() != nil {
			sess.Abort("cancelled")
		} else {
			sess.Fail(err)
		}
	}
	return sess.Result()
}
