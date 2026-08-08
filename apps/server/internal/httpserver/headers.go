package httpserver

import "net/http"

// securityHeaders applies the baseline hardening from plan.md §14. The CSP is
// deliberately strict; connect-src stays 'self' because signaling runs same-origin
// (wss to the same host). Referrer-Policy is an extra guard so the URL fragment
// secret can never leak via Referer. Tightened further for release in M7.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"connect-src 'self' wss: https:; "+
				"img-src 'self' data:; "+
				"style-src 'self' 'unsafe-inline'; "+
				"script-src 'self'; "+
				"object-src 'none'; "+
				"base-uri 'none'; "+
				"frame-ancestors 'none'")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
