package signal

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/coder/websocket"
)

const (
	// writeTimeout bounds a single socket write; a peer that can't accept a frame in
	// this window is treated as dead. It also bounds how long forwarding to a stuck
	// peer can stall the sender's read loop.
	writeTimeout = 10 * time.Second
	// sendBuffer is the per-peer outbound queue depth. Rendezvous traffic is a few
	// tiny control frames, so a shallow buffer is plenty; a full buffer means the
	// socket is wedged.
	sendBuffer = 16
)

type outboundFrame struct {
	typ  websocket.MessageType
	data []byte
}

// peer is one WebSocket connection and its place in a room. A single writer goroutine
// owns every write to ws; all other goroutines hand it frames through send. done is
// closed exactly once to unwind both the reader and the writer.
type peer struct {
	ws     *websocket.Conn
	hub    *Hub
	logger *slog.Logger

	room int    // -1 until the peer creates or joins a room
	role string // set on create/join

	send             chan outboundFrame
	queueMu          sync.Mutex
	queuedBytes      int64
	relayOpen        bool  // guarded by hub.mu
	relayCredit      int64 // guarded by hub.mu; bytes this peer may send
	relayRate        *tokenBucket
	relayControlRate *tokenBucket
	closeOnce        sync.Once
	done             chan struct{}
	farewell         []byte // final frame to flush before closing; set under closeOnce
	closed           chan struct{}
	graceful         bool // set when this peer sent a bye; makes teardown non-resumable
}

func newPeer(ws *websocket.Conn, h *Hub) *peer {
	return &peer{
		ws:               ws,
		hub:              h,
		logger:           h.logger,
		room:             -1,
		send:             make(chan outboundFrame, 16),
		relayRate:        newTokenBucket(int(h.cfg.RelayBurstBytes), float64(h.cfg.RelayBytesPerSec)),
		relayControlRate: newTokenBucket(128, 64),
		done:             make(chan struct{}),
		closed:           make(chan struct{}),
	}
}

// serve runs the connection: it starts the writer, reads and dispatches frames until
// the socket closes or a protocol error ends it, then tears the room down.
func (p *peer) serve(ctx context.Context) {
	p.ws.SetReadLimit(max(p.hub.cfg.MaxMessageBytes, p.hub.cfg.MaxRelayFrameBytes))
	msgLimiter := newTokenBucket(p.hub.cfg.MsgBurst, p.hub.cfg.MsgPerSec)

	go p.writeLoop(ctx)
	defer p.teardown()

	for {
		readCtx, cancel := context.WithTimeout(ctx, p.hub.cfg.IdleTimeout)
		typ, data, err := p.ws.Read(readCtx)
		cancel()
		if err != nil {
			p.logger.Warn("peer read ended", "err", err)
			return
		}
		switch typ {
		case websocket.MessageText:
			if int64(len(data)) > p.hub.cfg.MaxMessageBytes {
				p.fail(errBadMessage, "message too large")
				return
			}
			if !p.dispatch(data, msgLimiter) {
				return
			}
		case websocket.MessageBinary:
			if code := p.hub.forwardRelay(p, data); code != "" {
				p.fail(code, "relay frame refused")
				return
			}
		default:
			p.fail(errBadMessage, "unsupported frame type")
			return
		}
	}
}

// dispatch handles one inbound frame. It returns false when the connection should
// end. Only type (and room, for join) is ever parsed; forwardable payloads are
// relayed as the exact bytes received so the server stays blind to their contents.
func (p *peer) dispatch(data []byte, msgLimiter *tokenBucket) bool {
	var m clientMsg
	if err := json.Unmarshal(data, &m); err != nil || m.Type == "" {
		p.fail(errBadMessage, "invalid message")
		return false
	}
	if m.Type == typeRelayCredit {
		if !p.relayControlRate.allow() {
			p.fail(errRateLimited, "too many relay credit messages")
			return false
		}
	} else if !msgLimiter.allow() {
		p.fail(errRateLimited, "too many messages")
		return false
	}

	switch m.Type {
	case typeCreate:
		if p.room >= 0 {
			p.fail(errProtocol, "already in a room")
			return false
		}
		room := p.hub.createRoom(p)
		p.logger.Info("signal: room created", "room", room)
		p.enqueue(createdFrame(room))
		return true

	case typeJoin:
		if p.room >= 0 {
			p.fail(errProtocol, "already in a room")
			return false
		}
		if m.Room == nil {
			p.fail(errBadMessage, "join requires a room")
			return false
		}
		other, code := p.hub.join(p, *m.Room)
		if code != "" {
			p.fail(code, "")
			return false
		}
		p.logger.Info("signal: room paired", "room", p.room)
		p.enqueue(peerJoinedFrame(p.role))
		other.enqueue(peerJoinedFrame(other.role))
		return true

	case typeResume:
		if p.room >= 0 {
			p.fail(errProtocol, "already in a room")
			return false
		}
		if m.Room == nil {
			p.fail(errBadMessage, "resume requires a room")
			return false
		}
		other, code := p.hub.resume(p, *m.Room, m.Role)
		if code != "" {
			p.fail(code, "")
			return false
		}
		p.logger.Info("signal: room resumed", "room", p.room)
		p.enqueue(resumedFrame(p.room))
		if other != nil {
			other.enqueue(peerRejoinedFrame())
		}
		return true

	case typeBye:
		// A bye ends the session for both peers: mark this teardown non-resumable so the
		// partner is closed rather than left waiting for a reload.
		p.graceful = true
		if other := p.hub.partner(p); other != nil {
			other.enqueue(data)
		}
		p.close(nil)
		return false

	case typeRelayOpen:
		other, ready, code := p.hub.openRelay(p)
		if code != "" {
			p.fail(code, "relay unavailable")
			return false
		}
		if ready {
			p.enqueue(relayFrame(typeRelayReady))
			other.enqueue(relayFrame(typeRelayReady))
		} else {
			other.enqueue(relayFrame(typeRelayRequired))
		}
		return true

	case typeRelayCredit:
		sender, granted, code := p.hub.grantRelayCredit(p, m.Bytes)
		if code != "" {
			p.fail(code, "invalid relay credit")
			return false
		}
		if granted > 0 {
			sender.enqueue(creditFrame(granted))
		}
		return true

	default:
		if !forwardable[m.Type] {
			p.fail(errBadMessage, "unknown message type")
			return false
		}
		other := p.hub.partner(p)
		if other == nil {
			p.fail(errNotPaired, "not paired yet")
			return false
		}
		other.enqueue(data)
		return true
	}
}

// writeLoop is the sole writer of ws. It flushes queued frames until done is closed,
// then writes any farewell frame and closes the socket. Every exit path releases
// teardown: a write failure must still close p.closed or teardown blocks forever.
func (p *peer) writeLoop(ctx context.Context) {
	defer close(p.closed)
	for {
		select {
		case frame := <-p.send:
			p.releaseQueued(int64(len(frame.data)))
			if !p.rawWrite(ctx, frame.typ, frame.data) {
				p.close(nil)
				return
			}
		case <-p.done:
			if p.farewell != nil {
				p.rawWrite(ctx, websocket.MessageText, p.farewell)
			}
			_ = p.ws.Close(websocket.StatusNormalClosure, "")
			return
		}
	}
}

func (p *peer) rawWrite(ctx context.Context, typ websocket.MessageType, data []byte) bool {
	writeCtx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	if err := p.ws.Write(writeCtx, typ, data); err != nil {
		p.logger.Warn("peer write failed", "err", err)
		return false
	}
	return true
}

// enqueue hands a frame to this peer's writer. It blocks only until the buffer has
// room or the peer is closing, so a stalled partner cannot wedge the caller for
// longer than that partner's own write timeout.
func (p *peer) enqueue(data []byte) {
	if !p.tryEnqueue(websocket.MessageText, data) {
		p.fail(errRelayLimit, "outbound queue full")
	}
}

func (p *peer) tryEnqueue(typ websocket.MessageType, data []byte) bool {
	size := int64(len(data))
	p.queueMu.Lock()
	if size > p.hub.cfg.RelayQueueBytes-p.queuedBytes {
		p.queueMu.Unlock()
		return false
	}
	p.queuedBytes += size
	p.queueMu.Unlock()
	select {
	case p.send <- outboundFrame{typ: typ, data: data}:
		return true
	case <-p.done:
		p.releaseQueued(size)
		return false
	}
}

func (p *peer) releaseQueued(size int64) {
	p.queueMu.Lock()
	p.queuedBytes -= size
	p.queueMu.Unlock()
}

// close signals teardown, optionally flushing one final frame first. It is safe to
// call from any goroutine and any number of times; only the first call takes effect,
// so the farewell of the first caller wins.
func (p *peer) close(farewell []byte) {
	p.closeOnce.Do(func() {
		p.farewell = farewell
		close(p.done)
	})
}

// fail closes the connection with an error frame and counts it in the metrics.
func (p *peer) fail(code, msg string) {
	p.hub.recordError(code)
	p.close(errorFrame(code, msg))
}

// teardown detaches the peer from its room and notifies any remaining partner, then
// ensures this peer's socket is closed. A graceful bye tears the whole room down and
// closes the survivor; an unexpected drop only vacates this peer's slot, leaving the
// room lingering so the departed peer can reload and re-attach within the idle window.
func (p *peer) teardown() {
	if p.graceful {
		if other := p.hub.discard(p); other != nil {
			other.close(byeFrame("peer left"))
		}
	} else if other := p.hub.vacate(p); other != nil {
		other.enqueue(peerLeftFrame(true))
	}
	p.close(nil)
	// Wait for the writer to finish closing the socket so the goroutine cannot
	// outlive the connection.
	<-p.closed
}
