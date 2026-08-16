// Package engine is SendBeam's shared, reusable transfer engine (v1.4-PR01).
//
// It is the single Go implementation of the connection and transfer pipeline that the CLI
// and the desktop client both consume: SPAKE2 rendezvous authentication, capability
// negotiation, authenticated WebRTC direct paths, the encrypted WebSocket relay, the
// adaptive connection supervisor, the transfer driver, durable receive journals and
// sender restart records, and sanitized diagnostics.
//
// The engine owns the protocol, transport, durability, and trust logic. It has no
// knowledge of flags, terminal UI, updaters, or any application presentation layer — the
// CLI in apps/cli and the future desktop client are thin hosts that drive it through the
// exported API of the packages in this module:
//
//   - rendezvous: blind rendezvous handshake (SPAKE2), capabilities, signaling messages.
//   - rtc: authenticated WebRTC peer + data channel.
//   - relay: encrypted WebSocket relay transport.
//   - supervisor: path state machine and direct/relay switching.
//   - transfer: end-to-end driver, sources, durable receive, sender restart state,
//     adaptive policy.
//   - diagnostics: sanitized failure/telemetry snapshots.
//   - wsclient: reconnecting signaling websocket client.
//
// Behavior is pinned by the moved CLI test suites plus the external public-API parity
// tests in ./parity, which drive full transfers and authenticated resumes with no engine
// internals and no CLI code. The engine depends only on github.com/sendbeam/wire (the
// crypto core) and third-party transport libraries.
package engine
