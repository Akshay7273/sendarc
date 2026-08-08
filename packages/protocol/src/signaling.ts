/**
 * Signaling protocol — JSON messages over the WebSocket (plan.md §6.1, M1 design §4).
 *
 * The server is a blind pairer + forwarder: it allocates a room number, links the two
 * sockets, and forwards `pake`/`confirm`/`caps`/`sdp`/`ice`/`bye` between them without
 * inspecting bodies. It never receives the invite words or any derived key.
 */

export type Role = 'offerer' | 'joiner';

/** Sender → server: ask for a room. The server allocates the number. */
export interface CreateMsg {
  type: 'create';
}

/** Server → sender: room allocated (smallest free number); waiting for a peer. */
export interface CreatedMsg {
  type: 'created';
  room: number;
}

/** Receiver → server: pair with an existing room. */
export interface JoinMsg {
  type: 'join';
  room: number;
}

/** Server → both: the two sockets are now paired. Carries this peer's role. */
export interface PeerJoinedMsg {
  type: 'peer-joined';
  role: Role;
}

/**
 * Peer → peer (forwarded): a SPAKE2 message element (RFC 9382). The offerer sends
 * `T = X + w·M`, the joiner sends `S = Y + w·N`, each as a base64url raw SEC1 point.
 */
export interface PakeMsg {
  type: 'pake';
  msg: string;
}

/**
 * Peer → peer (forwarded): the RFC 9382 key-confirmation MAC (base64url). The offerer
 * sends cA, the joiner sends cB. A mismatch fails the handshake closed.
 */
export interface ConfirmMsg {
  type: 'confirm';
  mac: string;
}

/**
 * Peer → peer (forwarded): an opaque AES-256-GCM frame (base64url). First use of the
 * transfer codec — carries the encrypted `caps` in M1.
 */
export interface CapsMsg {
  type: 'caps';
  frame: string;
}

/**
 * Peer → peer (forwarded): SDP offer/answer, authenticated by the session key (M2).
 * `mac` = HMAC(k_auth, "sdp" | room | seq | body); `seq` is monotonic per sender.
 */
export interface SdpMsg {
  type: 'sdp';
  sdp: string;
  seq: number;
  mac: string;
}

/** Peer → peer (forwarded): ICE candidate, authenticated like SdpMsg (M2). */
export interface IceMsg {
  type: 'ice';
  cand: string;
  seq: number;
  mac: string;
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

export type SignalErrorCode =
  | 'unknown_room'
  | 'room_taken'
  | 'already_paired'
  | 'peer_gone'
  | 'rate_limited'
  | 'too_large'
  | 'bad_message'
  | 'expired';

/** All JSON signaling messages. */
export type SignalMsg =
  | CreateMsg
  | CreatedMsg
  | JoinMsg
  | PeerJoinedMsg
  | PakeMsg
  | ConfirmMsg
  | CapsMsg
  | SdpMsg
  | IceMsg
  | ByeMsg
  | ErrorMsg;

export type SignalMsgType = SignalMsg['type'];
