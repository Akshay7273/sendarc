/**
 * Signaling protocol — JSON messages over the WebSocket.
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
 * transfer codec — carries the encrypted `caps` handshake payload.
 */
export interface CapsMsg {
  type: 'caps';
  frame: string;
}

/**
 * Peer → peer (forwarded): SDP offer/answer, authenticated by the session key.
 * `mac` = HMAC(k_auth, "sdp" | room | seq | body); `seq` is monotonic per sender.
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

/** Peer → server: opt into the encrypted WebSocket data path for the current room. */
export interface RelayOpenMsg {
  type: 'relay_open';
}

/** Server → peer: the partner requested relay; opt in so both sides switch together. */
export interface RelayRequiredMsg {
  type: 'relay_required';
}

/** Server → both: both peers opted in and binary relay frames may now flow. */
export interface RelayReadyMsg {
  type: 'relay_ready';
}

/** Peer → server: grant the partner more receive capacity after consuming relay bytes. */
export interface RelayCreditMsg {
  type: 'relay_credit';
  bytes: number;
}

/** Server → peer: bounded relay-send capacity granted by the receiving partner. */
export interface CreditMsg {
  type: 'credit';
  bytes: number;
}

/** Any → any: graceful teardown. */
export interface ByeMsg {
  type: 'bye';
  reason: string;
}

/**
 * Client → server: re-attach to a room whose partner is still present but from which
 * this peer's socket dropped (e.g. a reload). The server seats this peer back into the
 * vacated slot for `role`; the room and its number are unchanged. Only ever fills a
 * previously-occupied slot — fresh pairing still goes through {@link JoinMsg}.
 */
export interface ResumeMsg {
  type: 'resume';
  room: number;
  role: Role;
}

/** Server → client: a {@link ResumeMsg} was accepted; the partner state follows. */
export interface ResumedMsg {
  type: 'resumed';
  room: number;
}

/**
 * Server → the surviving peer: the partner's socket dropped. `resumable` reports whether
 * the room lingered for a re-attach (`true`; wait for {@link PeerRejoinedMsg}) or was torn
 * down (`false`, e.g. after a graceful bye or the last peer leaving — treat like `bye`).
 */
export interface PeerLeftMsg {
  type: 'peer_left';
  resumable: boolean;
}

/**
 * Server → the waiting peer: the partner re-attached via {@link ResumeMsg}. Both sides
 * must re-run the SPAKE2 handshake to build a fresh session; the reload discarded the old
 * key and AEAD counters, which must never be resumed (nonce-reuse hazard).
 */
export interface PeerRejoinedMsg {
  type: 'peer_rejoined';
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
  | 'room_full'
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
  | RelayOpenMsg
  | RelayRequiredMsg
  | RelayReadyMsg
  | RelayCreditMsg
  | CreditMsg
  | ByeMsg
  | ResumeMsg
  | ResumedMsg
  | PeerLeftMsg
  | PeerRejoinedMsg
  | ErrorMsg;

export type SignalMsgType = SignalMsg['type'];
