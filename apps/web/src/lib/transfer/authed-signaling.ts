/**
 * Signs and verifies SDP/ICE signaling with the SPAKE2-derived k_auth (design authmac). The offerer
 * signs with KcA and verifies KcB; the joiner mirrors. `seq` is monotonic per sender across both
 * message kinds, and the verifier rejects any non-increasing seq to defeat replay and reorder. The
 * MAC rides as base64url in the message `mac` field.
 */

import {
  authKeys,
  signSignal,
  verifySignal,
  bytesToBase64url,
  base64urlToBytes,
  type IceMsg,
  type Role,
  type SdpMsg,
  type Spake2Output,
} from '@sendbeam/protocol';

export interface AuthKeyPair {
  sign: Uint8Array;
  verify: Uint8Array;
}

export type VerifyResult = { ok: true } | { ok: false; error: string };

export class SignalAuthenticator {
  private outSeq = 0;
  private inSeq = -1;

  constructor(
    private readonly room: number,
    private readonly keys: AuthKeyPair,
  ) {}

  static fromSession(role: Role, room: number, spake2: Spake2Output): SignalAuthenticator {
    return new SignalAuthenticator(room, authKeys(role, spake2));
  }

  async signSdp(sdp: string): Promise<SdpMsg> {
    const seq = this.outSeq++;
    const mac = await signSignal(this.keys.sign, 'sdp', this.room, seq, sdp);
    return { type: 'sdp', sdp, seq, mac: bytesToBase64url(mac) };
  }

  async signIce(cand: string): Promise<IceMsg> {
    const seq = this.outSeq++;
    const mac = await signSignal(this.keys.sign, 'ice', this.room, seq, cand);
    return { type: 'ice', cand, seq, mac: bytesToBase64url(mac) };
  }

  async verify(msg: SdpMsg | IceMsg): Promise<VerifyResult> {
    if (!Number.isInteger(msg.seq) || msg.seq <= this.inSeq) {
      return { ok: false, error: `non-increasing seq ${msg.seq}` };
    }
    let mac: Uint8Array;
    try {
      mac = base64urlToBytes(msg.mac);
    } catch {
      return { ok: false, error: 'malformed mac' };
    }
    const body = msg.type === 'sdp' ? msg.sdp : msg.cand;
    const ok = await verifySignal(this.keys.verify, msg.type, this.room, msg.seq, body, mac);
    if (!ok) return { ok: false, error: 'bad mac' };
    this.inSeq = msg.seq;
    return { ok: true };
  }
}
