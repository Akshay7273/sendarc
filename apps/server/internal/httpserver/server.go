// Package httpserver wires the HTTP surface for sendbeamd: health, security headers,
// and serving the web app — either from a built directory (prod) or by proxying the
// Vite dev server (dev). The signaling handler mounts on the same router.
package httpserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/sendbeam/server/internal/signal"
)

// Config controls how sendbeamd serves the web app and terminates TLS.
type Config struct {
	Addr      string // listen address, e.g. ":8443"
	TLSCert   string // path to TLS cert (PEM); empty => plain HTTP (dev/testing only)
	TLSKey    string // path to TLS key (PEM)
	WebDir    string // directory of the built web bundle to serve (prod)
	DevProxy  string // URL of the Vite dev server to proxy to (dev); overrides WebDir
	PublicURL string // public base URL for invite links (e.g. https://send.example.com/); empty = auto-detect from page

	Signal signal.Config // signaling limits + WSS origin allowlist
}

// ConfigFromEnv reads configuration from SENDBEAM_* environment variables with defaults.
func ConfigFromEnv() Config {
	return Config{
		Addr:      env("SENDBEAM_ADDR", ":8443"),
		TLSCert:   os.Getenv("SENDBEAM_TLS_CERT"),
		TLSKey:    os.Getenv("SENDBEAM_TLS_KEY"),
		WebDir:    os.Getenv("SENDBEAM_WEB_DIR"),
		DevProxy:  os.Getenv("SENDBEAM_WEB_DEV_PROXY"),
		PublicURL: os.Getenv("SENDBEAM_PUBLIC_URL"),
		Signal:    signal.ConfigFromEnv(),
	}
}

// Mode reports how the web app is being served, for logging.
func (c Config) Mode() string {
	switch {
	case c.DevProxy != "":
		return "dev-proxy"
	case c.WebDir != "":
		return "static"
	default:
		return "api-only"
	}
}

// Server wraps *http.Server with SendBeam's config so it can choose TLS vs plain HTTP.
type Server struct {
	http   *http.Server
	cfg    Config
	cancel context.CancelFunc
}

// New builds a Server with the SendBeam router and sensible timeouts.
func New(cfg Config, logger *slog.Logger) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())
	handler, err := router(ctx, cfg, logger)
	if err != nil {
		cancel()
		return nil, err
	}
	return &Server{
		cfg:    cfg,
		cancel: cancel,
		http: &http.Server{
			Addr:              cfg.Addr,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
			TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
			// No WriteTimeout: signaling/relay use long-lived streaming connections.
		},
	}, nil
}

// ListenAndServe serves over TLS when a cert/key are configured, else plain HTTP.
func (s *Server) ListenAndServe() error {
	if s.cfg.TLSCert != "" && s.cfg.TLSKey != "" {
		return s.http.ListenAndServeTLS(s.cfg.TLSCert, s.cfg.TLSKey)
	}
	return s.http.ListenAndServe()
}

// Shutdown gracefully stops the server and its background workers.
func (s *Server) Shutdown(ctx context.Context) error {
	s.cancel()
	return s.http.Shutdown(ctx)
}

func router(ctx context.Context, cfg Config, logger *slog.Logger) (http.Handler, error) {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(securityHeaders)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	r.Get("/config.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"publicUrl": cfg.PublicURL,
			"lanIp":     firstLanIP(),
		})
	})

	// Signaling endpoint: origin-checked WebSocket rendezvous.
	hub := signal.NewHub(ctx, cfg.Signal, logger)
	r.Handle("/ws", hub.Handler(ctx))
	r.Handle("/metrics", hub.MetricsHandler())

	// Web app: dev proxy takes precedence, then a static build dir.
	switch {
	case cfg.DevProxy != "":
		proxy, err := devProxy(cfg.DevProxy)
		if err != nil {
			return nil, err
		}
		r.Handle("/*", proxy)
	case cfg.WebDir != "":
		r.Handle("/*", spaFileServer(cfg.WebDir))
	default:
		logger.Warn("no web source configured; serving /healthz only")
	}

	return r, nil
}

// devProxy reverse-proxies everything (including Vite HMR websockets) to the dev server.
func devProxy(target string) (http.Handler, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid SENDBEAM_WEB_DEV_PROXY %q: %w", target, err)
	}
	return httputil.NewSingleHostReverseProxy(u), nil
}

// spaFileServer serves static files and falls back to index.html for client routes.
func spaFileServer(dir string) http.Handler {
	fs := http.FileServer(http.Dir(dir))
	index := strings.TrimRight(dir, "/") + "/index.html"
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		path := strings.TrimPrefix(req.URL.Path, "/")
		if path == "" {
			http.ServeFile(w, req, index)
			return
		}
		if _, err := os.Stat(dir + "/" + path); os.IsNotExist(err) {
			http.ServeFile(w, req, index) // SPA deep-link fallback
			return
		}
		fs.ServeHTTP(w, req)
	})
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// firstLanIP returns the first non-loopback IPv4 address, or "" if none is found.
func firstLanIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return ""
}
