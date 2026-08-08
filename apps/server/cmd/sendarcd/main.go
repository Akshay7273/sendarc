// Command sendarcd is the SendArc signaling + relay server. In M0 it serves the web
// bundle over TLS (or reverse-proxies the Vite dev server) and exposes /healthz.
// Signaling and relay are added in M1/M5.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sendarc/server/internal/httpserver"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg := httpserver.ConfigFromEnv()
	srv, err := httpserver.New(cfg, logger)
	if err != nil {
		logger.Error("failed to build server", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("sendarcd listening",
			"addr", cfg.Addr,
			"tls", cfg.TLSCert != "",
			"mode", cfg.Mode(),
		)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server exited", "err", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed", "err", err)
			os.Exit(1)
		}
	}
}
