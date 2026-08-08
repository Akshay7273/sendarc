import { describe, expect, it } from 'vitest';

import { RendezvousSession, type RendezvousPhase } from './rendezvous.js';
import type { Role, SignalMsg } from './signaling.js';
import { base64urlToBytes, bytesToBase64url, bytesToHex } from './bytes.js';

/**
 * A stand-in for the blind signaling server: it allocates a room, pairs the two peers,
 * and forwards `pake`/`confirm`/`caps` verbatim — exactly the envelope the real server
 * sees. Everything it is handed is recorded in {@link seen} so a test can assert the
 * word code never crosses it. A per-instance hook can tamper with forwarded frames.
 */
class MockHub {
  offerer?: RendezvousSession;
  joiner?: RendezvousSession;
  readonly seen: SignalMsg[] = [];

  constructor(
    private readonly room = 0,
    private readonly onForward: (msg: SignalMsg) => SignalMsg = (m) => m,
  ) {}

  sinkFor(role: Role): { send(msg: SignalMsg): void } {
    return { send: (msg) => this.route(role, msg) };
  }

  private route(from: Role, msg: SignalMsg): void {
    this.seen.push(msg);
    if (msg.type === 'create') {
      this.offerer!.handle({ type: 'created', room: this.room });
      return;
    }
    if (msg.type === 'join') {
      this.offerer!.handle({ type: 'peer-joined', role: 'offerer' });
      this.joiner!.handle({ type: 'peer-joined', role: 'joiner' });
      return;
    }
    const other = from === 'offerer' ? this.joiner! : this.offerer!;
    other.handle(this.onForward(msg));
  }
}

/** Wire an offerer/joiner pair to a hub; the joiner is given `code` out-of-band. */
function makePair(hub: MockHub, code: string, words = 'brave-otter') {
  const phases: RendezvousPhase[] = [];
  const offerer = new RendezvousSession({
    role: 'offerer',
    words,
    transport: hub.sinkFor('offerer'),
    onPhase: (p) => phases.push(p),
  });
  const joiner = new RendezvousSession({ role: 'joiner', code, transport: hub.sinkFor('joiner') });
  hub.offerer = offerer;
  hub.joiner = joiner;
  return { offerer, joiner, phases };
}

describe('RendezvousSession', () => {
  it('drives both peers to the same key and round-trips caps', async () => {
    const hub = new MockHub(0);
    const { offerer, joiner, phases } = makePair(hub, '0-brave-otter');
    offerer.start();
    joiner.start();

    const [ro, rj] = await Promise.all([offerer.done, joiner.done]);

    // Same handshake, same master key and directional keys on both ends.
    expect(bytesToHex(ro.master)).toBe(bytesToHex(rj.master));
    expect(bytesToHex(ro.keys.o2j.key)).toBe(bytesToHex(rj.keys.o2j.key));
    expect(bytesToHex(ro.keys.j2o.key)).toBe(bytesToHex(rj.keys.j2o.key));

    expect(ro.role).toBe('offerer');
    expect(rj.role).toBe('joiner');
    expect(ro.code).toBe('0-brave-otter');
    expect(rj.code).toBe('0-brave-otter');

    // Each side received the other's caps.
    expect(ro.remoteCaps).toEqual(rj.localCaps);
    expect(rj.remoteCaps).toEqual(ro.localCaps);

    // The caps exchange consumed counter 0 in each direction; the transfer continues at 1.
    expect(ro.sendCounter).toBe(1);
    expect(ro.recvCounter).toBe(1);

    expect(offerer.phase).toBe('established');
    expect(phases).toEqual([
      'allocating',
      'waiting',
      'handshaking',
      'confirming',
      'exchanging-caps',
      'established',
    ]);
  });

  it('fails closed when the codes disagree', async () => {
    const hub = new MockHub(0);
    // Offerer's words are brave-otter; the joiner types a wrong last word.
    const { offerer, joiner } = makePair(hub, '0-brave-tiger');
    offerer.start();
    joiner.start();

    await expect(offerer.done).rejects.toMatchObject({ code: 'confirmation_failed' });
    await expect(joiner.done).rejects.toMatchObject({ code: 'confirmation_failed' });
    expect(offerer.phase).toBe('failed');
  });

  it('rejects a tampered caps frame at the GCM check', async () => {
    // Corrupt every forwarded caps frame so both peers' opens fail.
    const hub = new MockHub(0, (msg) => {
      if (msg.type !== 'caps') return msg;
      const bytes = base64urlToBytes(msg.frame);
      bytes[bytes.length - 1] ^= 0xff; // flip a tag byte
      return { ...msg, frame: bytesToBase64url(bytes) };
    });
    const { offerer, joiner } = makePair(hub, '0-brave-otter');
    offerer.start();
    joiner.start();

    await expect(offerer.done).rejects.toMatchObject({ code: 'bad_peer_message' });
    await expect(joiner.done).rejects.toMatchObject({ code: 'bad_peer_message' });
  });

  it('never lets the word code reach the server', async () => {
    const hub = new MockHub(0);
    const { offerer, joiner } = makePair(hub, '0-brave-otter');
    offerer.start();
    joiner.start();
    await Promise.all([offerer.done, joiner.done]);

    const allowed = new Set(['create', 'join', 'pake', 'confirm', 'caps', 'bye']);
    for (const msg of hub.seen) {
      expect(allowed.has(msg.type)).toBe(true);
      const json = JSON.stringify(msg);
      expect(json).not.toContain('brave');
      expect(json).not.toContain('otter');
      expect(json).not.toContain('words');
      expect(json).not.toContain('code');
    }
  });
});
