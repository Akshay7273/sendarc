import { describe, it, expect } from 'vitest';
import { parseIceServer, parseIceServers, toRTCIceServers } from './ice-servers.js';

describe('parseIceServer', () => {
  it('accepts valid STUN URLs', () => {
    expect(parseIceServer('stun:stun.example.com:3478')).toEqual({
      urls: ['stun:stun.example.com:3478'],
    });
  });

  it('rejects unknown schemes', () => {
    expect(() => parseIceServer('http://stun.example.com:3478')).toThrow(/unsupported scheme/);
  });

  it('rejects missing host or port', () => {
    expect(() => parseIceServer('stun:stun.example.com')).toThrow(/host:port/);
    expect(() => parseIceServer('stun:')).toThrow();
  });

  it('parses TURN credentials in opaque form', () => {
    expect(parseIceServer('turn:user:secret@turn.example.com:3478')).toEqual({
      urls: ['turn:user:secret@turn.example.com:3478'],
      username: 'user',
      credential: 'secret',
    });
  });
});

describe('parseIceServers', () => {
  it('folds multiple credential-less STUN URLs into one entry', () => {
    const entries = parseIceServers(['stun:stun1.example.com:3478', 'stun:stun2.example.com:3478']);
    expect(entries).toHaveLength(1);
    expect(entries[0]!.urls).toHaveLength(2);
  });

  it('keeps STUN and TURN distinct', () => {
    const entries = parseIceServers(['stun:stun.example.com:3478', 'turn:turn.example.com:3478']);
    expect(entries).toHaveLength(2);
  });

  it('skips blank entries', () => {
    expect(parseIceServers(['', ' ', 'stun:stun.example.com:3478'])).toHaveLength(1);
  });
});

describe('toRTCIceServers', () => {
  it('returns undefined for an empty list', () => {
    expect(toRTCIceServers([])).toBeUndefined();
  });

  it('maps entries to RTCIceServer', () => {
    const rtc = toRTCIceServers([
      { urls: ['stun:stun.example.com:3478'] },
      { urls: ['turn:turn.example.com:3478'], username: 'u', credential: 'p' },
    ])!;
    expect(rtc).toHaveLength(2);
    expect(rtc[0]!.urls).toEqual(['stun:stun.example.com:3478']);
    expect(rtc[1]!.username).toBe('u');
    expect(rtc[1]!.credential).toBe('p');
  });
});
