import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { deriveTransferKeys } from './keyschedule.js';
import { TransferReceiver } from './transfer-receiver.js';
import { MemorySink, type Digest } from './transfer-ports.js';
import { bytesToHex, hexToBytes } from './bytes.js';

function nodeDigest(): Digest {
  const h = createHash('sha256');
  return { update: (b) => void h.update(b), hexDigest: () => h.digest('hex') };
}

interface Vector {
  description: string;
  master: string;
  blockSize: number;
  frameSize: number;
  window: number;
  keys: { o2j: { key: string; salt: string }; j2o: { key: string; salt: string } };
  file: { name: string; size: number; mime: string; hex: string; sha256: string };
  wireLog: Array<{ dir: 's2r' | 'r2s'; note: string; hex: string }>;
}

function loadVector(): Vector {
  const url = new URL('../../../docs/test-vectors/transfer.json', import.meta.url);
  return JSON.parse(readFileSync(fileURLToPath(url), 'utf8')) as Vector;
}

// SB-1146: cross-feed equivalence. The Go engine recorded a byte-exact wire log in
// transfer.json; replaying the s2r frames into the TypeScript receiver must produce
// byte-identical r2s replies, reconstruct the exact file bytes, and verify the same
// canonical SHA-256 that the Go side asserts.
describe('transfer vector cross-feed', () => {
  it('replays transfer.json through the TypeScript receiver', async () => {
    const v = loadVector();

    const master = hexToBytes(v.master);
    const keys = await deriveTransferKeys(master);
    const o2j = {
      key: hexToBytes(v.keys.o2j.key),
      salt: hexToBytes(v.keys.o2j.salt),
    };
    const j2o = {
      key: hexToBytes(v.keys.j2o.key),
      salt: hexToBytes(v.keys.j2o.salt),
    };

    // The recorded directional keys must derive from the recorded master —
    // evidence the Go and TS key schedules agree (parity check).
    expect(bytesToHex(keys.o2j.key)).toBe(v.keys.o2j.key);
    expect(bytesToHex(keys.o2j.salt)).toBe(v.keys.o2j.salt);
    expect(bytesToHex(keys.j2o.key)).toBe(v.keys.j2o.key);
    expect(bytesToHex(keys.j2o.salt)).toBe(v.keys.j2o.salt);

    const wantBytes = hexToBytes(v.file.hex);
    expect(wantBytes.length).toBe(v.file.size);
    const h = createHash('sha256');
    h.update(wantBytes);
    expect(h.digest('hex')).toBe(v.file.sha256);

    const sink = new MemorySink();
    const replies: string[] = [];
    const receiver = new TransferReceiver({
      send: (f) => void replies.push(bytesToHex(f)),
      sendDir: j2o,
      recvDir: o2j,
      sendCounterStart: 0,
      recvCounterStart: 0,
      createDigest: nodeDigest,
      sink,
    });

    for (const fr of v.wireLog) {
      if (fr.dir === 's2r') {
        await receiver.handle(hexToBytes(fr.hex));
      }
    }

    const wantReplies = v.wireLog.filter((f) => f.dir === 'r2s').map((f) => f.hex);
    expect(replies.length).toBe(wantReplies.length);
    for (let i = 0; i < replies.length; i++) {
      expect(replies[i]).toBe(wantReplies[i]);
    }

    expect([...sink.bytes()]).toEqual([...wantBytes]);
    const res = await receiver.done;
    expect(res.digest).toBe(v.file.sha256);
  });
});
