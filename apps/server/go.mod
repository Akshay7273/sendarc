module github.com/sendbeam/server

go 1.25.0

require github.com/go-chi/chi/v5 v5.3.1

require (
	github.com/coder/websocket v1.8.15
	github.com/sendbeam/wire v0.0.0
)

require (
	filippo.io/nistec v0.0.4 // indirect
	golang.org/x/sys v0.46.0 // indirect
)

replace github.com/sendbeam/wire => ../../packages/wire
