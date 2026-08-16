# SendBeam — developer task runner
# Requires: go (~/.local/go/bin), pnpm (corepack), mkcert, just.
# PATH note: ~/.bashrc exports Go, ~/go/bin, and ~/.local/bin.

set shell := ["bash", "-uc"]

CERT_DIR := justfile_directory() + "/infra/certs"

# List available recipes
default:
    @just --list

# Install all JS + Go dependencies
install:
    pnpm install
    cd apps/server && go mod download

# Generate local TLS certs for https://localhost (idempotent)
certs:
    mkdir -p {{CERT_DIR}}
    cd {{CERT_DIR}} && mkcert -cert-file localhost.pem -key-file localhost-key.pem localhost 127.0.0.1 ::1
    @echo "Certs in {{CERT_DIR}}. If the browser distrusts them, run: mkcert -install (needs sudo)."

# Run web (Vite HMR) and Go server together for development
dev: certs
    #!/usr/bin/env bash
    set -uo pipefail
    ( cd apps/web && pnpm dev ) &
    WEB_PID=$!
    ( cd apps/server && SENDBEAM_TLS_CERT="{{CERT_DIR}}/localhost.pem" SENDBEAM_TLS_KEY="{{CERT_DIR}}/localhost-key.pem" SENDBEAM_WEB_DEV_PROXY="http://localhost:5173" go run ./cmd/sendbeamd ) &
    SRV_PID=$!
    trap "kill $WEB_PID $SRV_PID 2>/dev/null" EXIT INT TERM
    wait

# Build the web bundle and the Go server binary
build:
    pnpm -r build
    cd apps/server && go build -o ../../bin/sendbeamd ./cmd/sendbeamd

# Build and install the CLI into ~/.local/bin (on PATH), so it runs as `sendbeam`
install-cli:
    go build -o ~/.local/bin/sendbeam ./apps/cli/cmd/sendbeam

# Run the production-style server (serves the built web bundle over TLS)
serve: build certs
    cd apps/server && SENDBEAM_TLS_CERT="{{CERT_DIR}}/localhost.pem" SENDBEAM_TLS_KEY="{{CERT_DIR}}/localhost-key.pem" SENDBEAM_WEB_DIR="../web/dist" go run ./cmd/sendbeamd

# Lint everything
lint:
    pnpm -r lint
    for m in packages/wire packages/engine apps/server apps/cli; do ( cd "$m" && go vet ./... ) || exit 1; done
    if command -v golangci-lint >/dev/null; then for m in packages/wire packages/engine apps/server apps/cli; do ( cd "$m" && golangci-lint run ) || exit 1; done; else echo "golangci-lint not installed; ran go vet only"; fi

# Typecheck TS + Svelte
typecheck:
    pnpm -r typecheck

# Run all tests
test:
    pnpm -r test
    for m in packages/wire packages/engine apps/server apps/cli; do ( cd "$m" && go test ./... ) || exit 1; done

# Format
fmt:
    pnpm format
    for m in packages/wire packages/engine apps/server apps/cli; do ( cd "$m" && go fmt ./... ); done
