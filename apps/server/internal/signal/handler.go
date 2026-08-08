package signal

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/coder/websocket"
)

// Handler returns the HTTP handler for the signaling endpoint (mounted at /ws). It
// enforces the origin allowlist and per-IP connection rate limit before upgrading,
// then hands the socket to the hub. baseCtx bounds the lifetime of every accepted
// connection.
func (h *Hub) Handler(baseCtx context.Context) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.originAllowed(r) {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			h.logger.Warn("signal: rejected origin", "origin", r.Header.Get("Origin"))
			return
		}
		if !h.allowConnection(clientIP(r)) {
			http.Error(w, "too many connections", http.StatusTooManyRequests)
			return
		}

		// originAllowed above is our origin policy, so we disable the library's own
		// origin check to keep that policy in one place (and to admit native clients
		// that send no Origin header). Note: despite its name, this option governs
		// only the WebSocket Origin-header check — it has nothing to do with TLS,
		// which is terminated by http.Server before the request reaches here.
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true,
		})
		if err != nil {
			return // Accept has already written the failure
		}

		p := newPeer(ws, h)
		p.serve(baseCtx)
	})
}

// originAllowed applies the WSS origin policy. Native clients (no Origin header) are
// always allowed. Browser clients must match the configured allowlist, or — when the
// allowlist is empty — be same-origin with the request host.
func (h *Hub) originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // non-browser client (CLI); browsers always set Origin
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if len(h.cfg.AllowedOrigins) == 0 {
		return strings.EqualFold(u.Host, r.Host)
	}
	for _, allowed := range h.cfg.AllowedOrigins {
		if strings.EqualFold(origin, allowed) || strings.EqualFold(u.Host, allowed) {
			return true
		}
	}
	return false
}

// clientIP extracts the remote IP for per-IP rate limiting. It trusts only the direct
// socket peer — the server sits behind no header-setting proxy in its threat model,
// so forwarded-for headers are deliberately ignored (they are client-controlled).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
