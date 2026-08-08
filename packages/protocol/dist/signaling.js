/**
 * Signaling protocol — JSON messages over the WebSocket (plan.md §6.1).
 *
 * The server is a blind forwarder + pairer: it acts on `create`/`join`/`relay_*`
 * and forwards `hs_*`/`sdp`/`ice` between paired sockets without inspecting bodies.
 * It never receives the invite secret S.
 */
export {};
//# sourceMappingURL=signaling.js.map