/**
 * Signaling protocol — JSON messages over the WebSocket (plan.md §6.1).
 *
 * The server is a blind forwarder + pairer: it acts on `create`/`join`/`relay_*`
 * and forwards `hs_*`/`sdp`/`ice` between paired sockets without inspecting bodies.
 * It never receives the invite secret S.
 */
export type Role = 'offerer' | 'joiner';
/** Client → server: register a rendezvous slot for this sid. */
export interface CreateMsg {
    type: 'create';
    sid: string;
}
/** Server → sender: rendezvous slot registered; waiting for a peer. */
export interface CreatedMsg {
    type: 'created';
    sid: string;
}
/** Client → server: ask to pair with an existing sid. */
export interface JoinMsg {
    type: 'join';
    sid: string;
}
/** Server → both: the two sockets are now paired. Carries this peer's role. */
export interface PeerJoinedMsg {
    type: 'peer-joined';
    role: Role;
}
/** Peer → peer (forwarded): ephemeral P-256 ECDH public key, base64url raw. */
export interface HsKeyMsg {
    type: 'hs_key';
    pub: string;
}
/** Peer → peer (forwarded): HMAC confirm over the handshake transcript. */
export interface HsConfirmMsg {
    type: 'hs_confirm';
    tag: string;
}
/**
 * Peer → peer (forwarded): SDP offer/answer with an HMAC binding it to the session.
 * `mac` = HMAC(k_auth, "sdp" | sid | seq | body); `seq` is monotonic per sender.
 */
export interface SdpMsg {
    type: 'sdp';
    sdp: string;
    seq: number;
    mac: string;
}
/** Peer → peer (forwarded): ICE candidate, authenticated like SdpMsg. */
export interface IceMsg {
    type: 'ice';
    cand: string;
    seq: number;
    mac: string;
}
/** Peer → server: request the relay transport (M5). */
export interface RelayOpenMsg {
    type: 'relay_open';
    sid: string;
}
/** Server → peer: byte-credit grant for relay flow control (M5). */
export interface CreditMsg {
    type: 'credit';
    bytes: number;
}
/** Any → any: graceful teardown. */
export interface ByeMsg {
    type: 'bye';
    reason: string;
}
/** Server → peer: protocol or limit error. */
export interface ErrorMsg {
    type: 'error';
    code: SignalErrorCode;
    msg: string;
}
export type SignalErrorCode = 'unknown_sid' | 'sid_taken' | 'already_paired' | 'peer_gone' | 'rate_limited' | 'too_large' | 'bad_message' | 'expired';
/** All JSON signaling messages (the binary `relay_data` frame is out-of-band). */
export type SignalMsg = CreateMsg | CreatedMsg | JoinMsg | PeerJoinedMsg | HsKeyMsg | HsConfirmMsg | SdpMsg | IceMsg | RelayOpenMsg | CreditMsg | ByeMsg | ErrorMsg;
export type SignalMsgType = SignalMsg['type'];
//# sourceMappingURL=signaling.d.ts.map