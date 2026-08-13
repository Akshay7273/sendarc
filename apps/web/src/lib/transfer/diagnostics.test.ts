import { describe, expect, it } from 'vitest';
import { sanitize, toJSON } from './diagnostics.js';

describe('sanitize() redaction', () => {
  it('redacts IPv4 with port', () => {
    const out = sanitize('peer at 203.0.113.7:3478 unreachable');
    expect(out).not.toContain('203.0.113.7');
    expect(out).toContain('<ip>');
  });

  it('redacts IPv6', () => {
    const out = sanitize('route via 2001:db8::1 failed');
    expect(out).not.toContain('2001:db8::1');
    expect(out).toContain('<ip>');
  });

  it('redacts credentials', () => {
    const out = sanitize('turn credential=supersecret123 failed');
    expect(out).not.toContain('supersecret123');
    expect(out).toContain('<redacted>');
  });

  it('redacts invite codes', () => {
    const out = sanitize('bad room 42-alpha-bravo');
    expect(out).not.toContain('42-alpha-bravo');
    expect(out).toContain('<code>');
  });

  it('keeps benign text', () => {
    const out = sanitize('direct path recovery failed; relay warmed as fallback');
    expect(out).toContain('direct path recovery failed');
  });
});

describe('toJSON()', () => {
  it('serializes a snapshot without leaking sensitive labels', () => {
    const json = toJSON({
      app: 'web',
      role: 'offerer',
      setupMs: 1200,
      selectedPath: 'direct',
      selectedPairType: 'srflx',
      paths: [{ state: 'active', kind: 'direct', setupMs: 1100, iceStates: ['new', 'connected'] }],
      failures: [{ code: 'CONNECTION', atMs: 900, message: 'transient disconnect observed' }],
      turnConfigured: true,
    });
    expect(json).toContain('"selectedPath":"direct"');
    expect(json).toContain('"turnConfigured":true');
    for (const banned of ['stun:', 'credential>', 'iceServers>', 'sdp']) {
      expect(json).not.toContain(banned);
    }
  });
});
