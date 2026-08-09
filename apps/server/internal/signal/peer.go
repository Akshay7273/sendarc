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
}

func newPeer(ws *websocket.Conn, h *Hub) *peer {
	return &peer{
		ws:               ws,
		hub:              h,
		logger:           h.logger,
		room:             -1,
		send:             make(chan outboundFrame, sendBuffer),
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
			return
		}
		switch typ {
		case websocket.MessageText:
			if int64(len(data)) > p.hub.cfg.MaxMessageBytes {
				p.close(errorFrame(errBadMessage, "message too large"))
				return
			}
			if !p.dispatch(data, msgLimiter) {
				return
			}
		case websocket.MessageBinary:
			if code := p.hub.forwardRelay(p, data); code != "" {
				p.close(errorFrame(code, "relay frame refused"))
				return
			}
		default:
			p.close(errorFrame(errBadMessage, "unsupported frame type"))
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
		p.close(errorFrame(errBadMessage, "invalid message"))
		return false
	}
	if m.Type == typeRelayCredit {
		if !p.relayControlRate.allow() {
			p.close(errorFrame(errRateLimited, "too many relay credit messages"))
			return false
		}
	} else if !msgLimiter.allow() {
		p.close(errorFrame(errRateLimited, "too many messages"))
		return false
	}

	switch m.Type {
	case typeCreate:
		if p.room >= 0 {
			p.close(errorFrame(errProtocol, "already in a room"))
			return false
		}
		room := p.hub.createRoom(p)
		p.logger.Info("signal: room created", "room", room)
		p.enqueue(createdFrame(room))
		return true

	case typeJoin:
		if p.room >= 0 {
			p.close(errorFrame(errProtocol, "already in a room"))
			return false
		}
		if m.Room == nil {
			p.close(errorFrame(errBadMessage, "join requires a room"))
			return false
		}
		other, code := p.hub.join(p, *m.Room)
		if code != "" {
			p.close(errorFrame(code, ""))
			return false
		}
		p.logger.Info("signal: room paired", "room", p.room)
		p.enqueue(peerJoinedFrame(p.role))
		other.enqueue(peerJoinedFrame(other.role))
		return true

	case typeBye:
		if other := p.hub.partner(p); other != nil {
			other.enqueue(data)
		}
		p.close(nil)
		return false

	case typeRelayOpen:
		other, ready, code := p.hub.openRelay(p)
		if code != "" {
			p.close(errorFrame(code, "relay unavailable"))
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
			p.close(errorFrame(code, "invalid relay credit"))
			return false
		}
		if granted > 0 {
			sender.enqueue(creditFrame(granted))
		}
		return true

	default:
		if !forwardable[m.Type] {
			p.close(errorFrame(errBadMessage, "unknown message type"))
			return false
		}
		other := p.hub.partner(p)
		if other == nil {
			p.close(errorFrame(errNotPaired, "not paired yet"))
			return false
		}
		other.enqueue(data)
		return true
	}
}

// writeLoop is the sole writer of ws. It flushes queued frames until done is closed,
// then writes any farewell frame and closes the socket.
func (p *peer) writeLoop(ctx context.Context) {
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
			close(p.closed)
			return
		}
	}
}

func (p *peer) rawWrite(ctx context.Context, typ websocket.MessageType, data []byte) bool {
	writeCtx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	return p.ws.Write(writeCtx, typ, data) == nil
}

// enqueue hands a frame to this peer's writer. It blocks only until the buffer has
// room or the peer is closing, so a stalled partner cannot wedge the caller for
// longer than that partner's own write timeout.
func (p *peer) enqueue(data []byte) {
	if !p.tryEnqueue(websocket.MessageText, data) {
		p.close(errorFrame(errRelayLimit, "outbound queue full"))
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
	default:
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

// teardown removes the peer from its room and notifies any remaining partner, then
// ensures this peer's socket is closed.
func (p *peer) teardown() {
	if other := p.hub.remove(p); other != nil {
		other.close(byeFrame("peer left"))
	}
	p.close(nil)
	// Wait for the writer to finish closing the socket so the goroutine cannot
	// outlive the connection.
	<-p.closed
}
