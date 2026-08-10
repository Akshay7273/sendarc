# syntax=docker/dockerfile:1

# --- Stage 1: build the web bundle ------------------------------------------------
FROM node:22-alpine AS web
RUN corepack enable
WORKDIR /src
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY packages/protocol/package.json ./packages/protocol/
COPY apps/web/package.json ./apps/web/
RUN pnpm install --frozen-lockfile --ignore-scripts
COPY packages/protocol ./packages/protocol
COPY apps/web ./apps/web
RUN pnpm --filter @sendarc/protocol build && pnpm --filter @sendarc/web build

# --- Stage 2: build the server binary --------------------------------------------
FROM golang:1.24-alpine AS server
WORKDIR /src
COPY apps/server/go.mod apps/server/go.sum ./apps/server/
RUN cd apps/server && go mod download
COPY apps/server ./apps/server
RUN cd apps/server && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /sendarcd ./cmd/sendarcd

# --- Stage 3: runtime --------------------------------------------------------------
FROM alpine:3.21
RUN apk add --no-cache ca-certificates \
    && adduser -D -H -u 10001 sendarc
WORKDIR /srv
COPY --from=server /sendarcd /usr/local/bin/sendarcd
COPY --from=web /src/apps/web/dist /srv/web
USER sendarc
ENV SENDARC_ADDR=:8443 \
    SENDARC_WEB_DIR=/srv/web
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8443/healthz || exit 1
CMD ["sendarcd"]
