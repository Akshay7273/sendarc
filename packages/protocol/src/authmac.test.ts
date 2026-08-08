import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { hexToBytes, bytesToHex } from './bytes.js';
import { signSignal, verifySignal, signalMacInput, u32be } from './authmac.js';

function loadVectors<T>(name: string): T {
  const url = new URL(`../../../test-vectors/${name}`, import.meta.url);
  return JSON.parse(readFileSync(fileURLToPath(url), 'utf8')) as T;
}
interface V {
  authmac: {
    kAuthHex: string;
    type: 'sdp' | 'ice';
    room: number;
    seq: number;
    body: string;
    mac: string;
  };
}
const sa = loadVectors<V>('sendarc-crypto.json');

describe('authmac', () => {
  it('u32be encodes big-endian', () => {
    expect(bytesToHex(u32be(7))).toBe('00000007');
    expect(bytesToHex(u32be(0xffffffff))).toBe('ffffffff');
  });

  it('matches the committed cross-language vector', async () => {
    const { kAuthHex, type, room, seq, body } = sa.authmac;
    const mac = await signSignal(hexToBytes(kAuthHex), type, room, seq, body);
    expect(bytesToHex(mac)).toBe(sa.authmac.mac);
  });

  it('verifies a good MAC and rejects a tampered body', async () => {
    const k = hexToBytes(sa.authmac.kAuthHex);
    const mac = await signSignal(k, 'sdp', 7, 3, 'hello');
    expect(await verifySignal(k, 'sdp', 7, 3, 'hello', mac)).toBe(true);
    expect(await verifySignal(k, 'sdp', 7, 3, 'hell0', mac)).toBe(false);
    expect(await verifySignal(k, 'sdp', 7, 4, 'hello', mac)).toBe(false); // seq bound
    expect(await verifySignal(k, 'ice', 7, 3, 'hello', mac)).toBe(false); // type bound
    expect(await verifySignal(k, 'sdp', 8, 3, 'hello', mac)).toBe(false); // room bound
  });

  it('domain-separates from the M1 confirm MAC (type prefix present)', () => {
    const input = signalMacInput('sdp', 7, 3, 'x');
    expect(new TextDecoder().decode(input.slice(0, 4))).toBe('sdp:');
  });
});
