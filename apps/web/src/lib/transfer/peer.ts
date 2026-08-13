/**
 * WebRTC peer: brings up an `RTCDataChannel` between the two paired clients
 * over the already-authenticated signaling socket. Every SDP and ICE frame is signed and verified
 * with the SPAKE2-derived key (see {@link SignalAuthenticator}); an unverifiable frame is dropped,
 * so a malicious signaling server can pair sockets but cannot inject a peer or tamper with the
 * negotiation. The offerer creates the channel and the offer; the joiner answers. Both trickle ICE.
 *
 * Browser-only (needs `RTCPeerConnection`); not unit-tested — exercised by the e2e transfer.
 */

import type { IceMsg, Role, SdpMsg } from '@sendbeam/protocol';
import type { SignalAuthenticator } from './authed-signaling.js';
import { RecoveryController } from './recovery.js';

/** A public STUN server is sufficient for the common NAT case. */
export const DEFAULT_ICE_SERVERS: RTCIceServer[] = [{ urls: 'stun:stun.l.google.com:19302' }];

export interface CreatePeerOptions {
  role: Role;
  auth: SignalAuthenticator;
  /** Sign-and-forward an outbound signaling frame over the adopted socket. */
  send: (msg: SdpMsg | IceMsg) => void;
  iceServers?: RTCIceServer[];
  /**
   * Invoked as ICE gathering/connection state transitions occur. Primarily for diagnostics
   * and adaptive selection.
   */
  onIceState?: (state: ICEState) => void;
  /**
   * Invoked with true when an established direct path enters the transient-disconnected
   * recovery window (an ICE restart is under way) and false once it recovers to connected.
   * Used to expose a distinct "recovering connection" state.
   */
  onRecovering?: (recovering: boolean) => void;
  /**
   * Invoked when the recovery window elapses (or the ICE restart fails) without returning to
   * connected: the direct path is gone and the caller should fall back to the relay without
   * restarting transfer progress.
   */
  onRecoverFailed?: () => void;
  /**
   * Bounds the observation of a transient disconnect before recovery is declared failed.
   * Zero uses {@link DEFAULT_RECOVER_WINDOW_MS}.
   */
  recoverWindowMs?: number;
}

/** Default bound for observing a transient ICE disconnect before recovery fails over. */
export const DEFAULT_RECOVER_WINDOW_MS = 6_000;

/** A sanitized snapshot of a peer's ICE setup for diagnostics. */
export interface PeerDiagnostics {
  /** Milliseconds from createPeer to the data channel opening (0 if not yet open). */
  setupMs: number;
  /** Ordered ICE gathering-state history. */
  gatheringStates: RTCIceGatheringState[];
  /** Ordered ICE connection-state history. */
  connectionStates: RTCIceConnectionState[];
  /** Selected candidate pair type, e.g. "host"|"srflx"|"prflx"|"relay"; "" if none yet. */
  selectedPairType: string;
}

/** ICE gathering+connection state published to onIceState. */
export interface ICEState {
  gathering: RTCIceGatheringState;
  connection: RTCIceConnectionState;
  /** True once a server-reflexive/peer-reflexive/relay candidate has been gathered. */
  hasServerReflexive: boolean;
  /** True once any candidate (including host) has been gathered. */
  hasAnyCandidate: boolean;
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
  /** Register for an established channel becoming unusable. */
  onDisconnect(handler: (err: Error) => void): void;
  /** Sanitized ICE setup telemetry for diagnostics. */
  diagnostics(): PeerDiagnostics;
  /** Tear down the peer connection. Idempotent. */
  close(): void;
}
export function createPeer(opts: CreatePeerOptions): Peer {
  const pc = new RTCPeerConnection({ iceServers: opts.iceServers ?? DEFAULT_ICE_SERVERS });

  // ICE setup telemetry: gathering/connection history, setup timing, and the selected pair
  // type, exposed sanitized via diagnostics().
  const startedAt = performance.now();
  let connectedAt = 0;
  const gatheringStates: RTCIceGatheringState[] = [pc.iceGatheringState];
  const connectionStates: RTCIceConnectionState[] = [pc.iceConnectionState];
  let selectedPairType = '';
  let hasServerReflexive = false;
  let hasAnyCandidate = false;
  const publishIceState = (): void => {
    const lastGathering = gatheringStates[gatheringStates.length - 1]!;
    const lastConnection = connectionStates[connectionStates.length - 1]!;
    opts.onIceState?.({
      gathering: lastGathering,
      connection: lastConnection,
      hasServerReflexive,
      hasAnyCandidate,
    });
  };

  let resolveChannel!: (ch: RTCDataChannel) => void;
  let rejectChannel!: (err: Error) => void;
  const channel = new Promise<RTCDataChannel>((resolve, reject) => {
    resolveChannel = resolve;
    rejectChannel = reject;
  });
  let settled = false;
  let channelOpen = false;
  let closedByUser = false;
  let disconnectHandler: ((err: Error) => void) | undefined;
  let disconnectError: Error | undefined;

  // Recovery from a transient disconnect on an established direct path. The RecoveryController
  // owns the bounded observation window and the start/clear/fail state machine (see recovery.ts).
  const recovery = new RecoveryController({
    windowMs: opts.recoverWindowMs ?? DEFAULT_RECOVER_WINDOW_MS,
    callbacks: {
      onStart: () => opts.onRecovering?.(true),
      onRecover: () => opts.onRecovering?.(false),
      onFail: onRecoverFail,
    },
  });
  // onRecoverFail is referenced above ahead of its definition (the callback fires only later).
  function onRecoverFail(): void {
    opts.onRecoverFailed?.();
    disconnected(new Error('direct recovery failed'));
  }

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
      channelOpen = true;
      if (connectedAt === 0) connectedAt = performance.now();
      resolveChannel(ch);
    };
    ch.onmessage = (ev: MessageEvent) => {
      const frame = ev.data as ArrayBuffer;
      if (dataHandler) dataHandler(frame);
      else dataBuffer.push(frame);
    };
    ch.onerror = () => disconnected(new Error('data channel error'));
    ch.onclose = () => disconnected(new Error('data channel closed'));
  };

  const disconnected = (err: Error): void => {
    if (closedByUser || disconnectError) return;
    if (!channelOpen) {
      fail(err);
      return;
    }
    disconnectError = err;
    disconnectHandler?.(err);
  };

  pc.onicecandidate = (ev) => {
    if (ev.candidate) {
      // Candidate type is not exposed on the RTCIceCandidate typing; parse it from the SDP
      // candidate string ("... typ host|srflx|prflx|relay ...").
      hasAnyCandidate = true;
      const type = candidateType(ev.candidate.candidate);
      if (type === 'srflx' || type === 'prflx' || type === 'relay') hasServerReflexive = true;
      void opts.auth.signIce(JSON.stringify(ev.candidate)).then(opts.send);
    }
  };
  pc.onicegatheringstatechange = () => {
    gatheringStates.push(pc.iceGatheringState);
    publishIceState();
  };
  pc.oniceconnectionstatechange = () => {
    connectionStates.push(pc.iceConnectionState);
    const state = pc.iceConnectionState;
    if (state === 'connected' || state === 'completed') {
      void captureSelectedPairType();
    }
    publishIceState();
    // Recovery applies only to an established direct path (the channel already opened).
    // Before the channel opens, disconnected/failed continue to fail the peer outright.
    if (!channelOpen) return;
    if (state === 'disconnected') startRecovery();
    else if (state === 'connected' || state === 'completed') recovery.clear();
    else if (state === 'failed') recovery.fail();
  };
  pc.onconnectionstatechange = () => {
    if (pc.connectionState === 'failed') disconnected(new Error('peer connection failed'));
  };

  // Query getStats() for the selected candidate pair and record the local candidate's type
  // (e.g. host/srflx/prflx/relay). Best-effort: leaves "" if stats are unavailable.
  const captureSelectedPairType = async (): Promise<void> => {
    if (selectedPairType !== '') return;
    try {
      const stats = await pc.getStats();
      const candidates = new Map<string, string>();
      let pairLocal: string | undefined;
      for (const stat of stats.values()) {
        if (stat.type === 'candidate') {
          const c = stat as { id: string; candidateType?: string };
          candidates.set(stat.id, c.candidateType ?? '');
        } else if (stat.type === 'candidate-pair') {
          const p = stat as RTCIceCandidatePairStats;
          if (p.state === 'succeeded') pairLocal = p.localCandidateId;
        }
      }
      if (pairLocal) {
        const t = candidates.get(pairLocal);
        if (t) selectedPairType = t;
      }
    } catch {
      // getStats is optional; leave the pair type unset.
    }
  };

  if (opts.role === 'offerer') {
    wireChannel(pc.createDataChannel('sendbeam', { ordered: true }));
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

  // Restart ICE as the offerer: a fresh negotiation with restartIce() so the ICE credentials change
  // and the partners re-establish the transport, sent over signaling so the joiner answers while the
  // existing data channel (and the transfer progress) stays alive.
  const restartAsOfferer = async (): Promise<void> => {
    pc.restartIce();
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    opts.send(await opts.auth.signSdp(offer.sdp ?? ''));
  };

  // startRecovery begins the recovery window for a transient disconnect and has the offerer
  // issue an ICE restart over signaling; a restart failure fails recovery immediately.
  const startRecovery = (): void => {
    if (closedByUser) return;
    recovery.start();
    if (opts.role === 'offerer') {
      void restartAsOfferer().catch(() => recovery.fail());
    }
  };

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
    onDisconnect: (handler) => {
      disconnectHandler = handler;
      if (disconnectError) handler(disconnectError);
    },
    diagnostics: () => ({
      setupMs: connectedAt !== 0 ? connectedAt - startedAt : 0,
      gatheringStates: [...gatheringStates],
      connectionStates: [...connectionStates],
      selectedPairType,
    }),
    close: () => {
      closedByUser = true;
      settled = true;
      recovery.dispose();
      pc.close();
    },
  };
}

function toError(err: unknown): Error {
  return err instanceof Error ? err : new Error(String(err));
}

/**
 * Extract the ICE candidate type ("host" | "srflx" | "prflx" | "relay") from an SDP candidate
 * string, e.g. "candidate:842163049 1 udp 1677729535 192.0.2.1 57621 typ srflx raddr ...".
 * Returns "" if no type field is present.
 */
function candidateType(candidate: string): string {
  const m = /\btyp ([a-z]+)\b/.exec(candidate);
  return m ? m[1]! : '';
}
