# agy — developer task runner
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
    ( cd apps/server && AGY_TLS_CERT="{{CERT_DIR}}/localhost.pem" AGY_TLS_KEY="{{CERT_DIR}}/localhost-key.pem" AGY_WEB_DEV_PROXY="http://localhost:5173" go run ./cmd/agyd ) &
    SRV_PID=$!
    trap "kill $WEB_PID $SRV_PID 2>/dev/null" EXIT INT TERM
    wait

# Build the web bundle and the Go server binary
build:
    pnpm --filter ./packages/... --filter ./apps/web build
    cd apps/server && go build -o ../../bin/agyd ./cmd/agyd

# Run the production-style server (serves the built web bundle over TLS)
serve: build certs
    cd apps/server && AGY_TLS_CERT="{{CERT_DIR}}/localhost.pem" AGY_TLS_KEY="{{CERT_DIR}}/localhost-key.pem" AGY_WEB_DIR="../web/dist" go run ./cmd/agyd

# Lint everything
lint:
    pnpm -r lint
    cd apps/server && go vet ./... && test -x "$(command -v golangci-lint)" && golangci-lint run || echo "golangci-lint not installed; ran go vet only"

# Typecheck TS + Svelte
typecheck:
    pnpm -r typecheck

# Run all tests
test:
    pnpm -r test
    cd apps/server && go test ./...

# Format
fmt:
    pnpm format
    cd apps/server && go fmt ./...
