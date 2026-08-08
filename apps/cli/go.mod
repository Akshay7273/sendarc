module github.com/sendarc/cli

go 1.24.0

require (
	github.com/coder/websocket v1.8.15
	github.com/sendarc/wire v0.0.0
)

require (
	filippo.io/nistec v0.0.4 // indirect
	golang.org/x/sys v0.36.0 // indirect
)

// The wire crypto core is a sibling module in this repo. A local replace keeps it resolvable
// both under the go.work workspace and in standalone module builds (as CI runs each module).
replace github.com/sendarc/wire => ../../packages/wire
