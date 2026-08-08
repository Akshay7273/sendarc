/**
 * WebRTC peer for the M2 transfer: brings up an `RTCDataChannel` between the two paired clients
 * over the already-authenticated signaling socket. Every SDP and ICE frame is signed and verified
 * with the SPAKE2-derived key (see {@link SignalAuthenticator}); an unverifiable frame is dropped,
 * so a malicious signaling server can pair sockets but cannot inject a peer or tamper with the
 * negotiation. The offerer creates the channel and the offer; the joiner answers. Both trickle ICE.
 *
 * Browser-only (needs `RTCPeerConnection`); not unit-tested — exercised by the e2e transfer.
 */

import type { IceMsg, Role, SdpMsg } from '@sendarc/protocol';
import type { SignalAuthenticator } from './authed-signaling.js';

/** A public STUN server is enough for the common NAT case; TURN relay is a later milestone. */
export const DEFAULT_ICE_SERVERS: RTCIceServer[] = [{ urls: 'stun:stun.l.google.com:19302' }];

export interface CreatePeerOptions {
  role: Role;
  auth: SignalAuthenticator;
  /** Sign-and-forward an outbound signaling frame over the adopted socket. */
  send: (msg: SdpMsg | IceMsg) => void;
  iceServers?: RTCIceServer[];
}

export interface Peer {
  /** Resolves with the data channel once it is open; rejects if negotiation fails. */
  readonly channel: Promise<RTCDataChannel>;
  /** Feed an inbound SDP/ICE frame (the orchestrator owns the socket's message routing). */
  accept(msg: SdpMsg | IceMsg): void;
  /**
   * Register the inbound data-frame handler. Frames that arrive between channel-open and this
   * call are buffered and flushed here, so the first blocks a fast sender emits are never lost.
   */
  onData(handler: (frame: ArrayBuffer) => void): void;
  /** Tear down the peer connection. Idempotent. */
  close(): void;
}

export function createPeer(opts: CreatePeerOptions): Peer {
  const pc = new RTCPeerConnection({ iceServers: opts.iceServers ?? DEFAULT_ICE_SERVERS });

  let resolveChannel!: (ch: RTCDataChannel) => void;
  let rejectChannel!: (err: Error) => void;
  const channel = new Promise<RTCDataChannel>((resolve, reject) => {
    resolveChannel = resolve;
    rejectChannel = reject;
  });
  let settled = false;

  // Remote ICE can arrive before the remote description is set (network reorder, or the peer
  // trickling early). Buffer such candidates and flush them once the description lands.
  const pendingRemoteIce: RTCIceCandidateInit[] = [];
  let remoteReady = false;

  // Inbound data frames received before the orchestrator registers its handler are buffered here.
  let dataHandler: ((frame: ArrayBuffer) => void) | undefined;
  const dataBuffer: ArrayBuffer[] = [];

  const fail = (err: Error): void => {
    if (settled) return;
    settled = true;
    rejectChannel(err);
    pc.close();
  };

  const wireChannel = (ch: RTCDataChannel): void => {
    ch.binaryType = 'arraybuffer';
    ch.onopen = () => {
      if (settled) return;
      settled = true;
      resolveChannel(ch);
    };
    ch.onmessage = (ev: MessageEvent) => {
      const frame = ev.data as ArrayBuffer;
      if (dataHandler) dataHandler(frame);
      else dataBuffer.push(frame);
    };
    ch.onerror = () => fail(new Error('data channel error'));
  };

  pc.onicecandidate = (ev) => {
    if (ev.candidate) void opts.auth.signIce(JSON.stringify(ev.candidate)).then(opts.send);
  };
  pc.onconnectionstatechange = () => {
    if (pc.connectionState === 'failed') fail(new Error('peer connection failed'));
  };

  if (opts.role === 'offerer') {
    wireChannel(pc.createDataChannel('sendarc', { ordered: true }));
    void (async () => {
      try {
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        opts.send(await opts.auth.signSdp(offer.sdp ?? ''));
      } catch (err) {
        fail(toError(err));
      }
    })();
  } else {
    pc.ondatachannel = (ev) => wireChannel(ev.channel);
  }

  const applyRemoteDescription = async (type: RTCSdpType, sdp: string): Promise<void> => {
    await pc.setRemoteDescription({ type, sdp });
    remoteReady = true;
    for (const cand of pendingRemoteIce) await pc.addIceCandidate(cand);
    pendingRemoteIce.length = 0;
  };

  const handle = async (msg: SdpMsg | IceMsg): Promise<void> => {
    const verdict = await opts.auth.verify(msg);
    if (!verdict.ok) return; // drop unverifiable frames
    if (msg.type === 'sdp') {
      if (opts.role === 'offerer') {
        await applyRemoteDescription('answer', msg.sdp);
      } else {
        await applyRemoteDescription('offer', msg.sdp);
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        opts.send(await opts.auth.signSdp(answer.sdp ?? ''));
      }
    } else {
      const cand: RTCIceCandidateInit = JSON.parse(msg.cand) as RTCIceCandidateInit;
      if (remoteReady) await pc.addIceCandidate(cand);
      else pendingRemoteIce.push(cand);
    }
  };

  return {
    channel,
    accept: (msg) => void handle(msg).catch(fail),
    onData: (handler) => {
      dataHandler = handler;
      for (const frame of dataBuffer) handler(frame);
      dataBuffer.length = 0;
    },
    close: () => {
      settled = true;
      pc.close();
    },
  };
}

function toError(err: unknown): Error {
  return err instanceof Error ? err : new Error(String(err));
}
