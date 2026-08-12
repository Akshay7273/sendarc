/** @vitest-environment jsdom */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { iceServers, loadConfig } from './config.js';

function mockConfig(body: unknown): void {
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue({
      ok: true,
      json: async () => body,
    }),
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('iceServers() runtime ICE config', () => {
  it('returns published STUN servers from /config.json', async () => {
    mockConfig({
      publicUrl: 'https://send.example.com',
      iceServers: [{ urls: ['stun:stun1.example.com:3478', 'stun:stun2.example.com:3478'] }],
    });
    await loadConfig();
    const servers = iceServers();
    expect(servers).toHaveLength(1);
    expect(servers![0]!.urls).toHaveLength(2);
  });

  it('maps TURN credentials into RTCIceServer', async () => {
    mockConfig({
      iceServers: [{ urls: ['turn:turn.example.com:3478'], username: 'u', credential: 'p' }],
    });
    await loadConfig();
    const servers = iceServers()!;
    expect(servers[0]!.username).toBe('u');
    expect(servers[0]!.credential).toBe('p');
  });

  it('returns undefined when the server publishes no ICE config', async () => {
    mockConfig({ publicUrl: 'https://send.example.com' });
    await loadConfig();
    expect(iceServers()).toBeUndefined();
  });

  it('drops malformed entries instead of throwing', async () => {
    mockConfig({ iceServers: [{ urls: ['://bad'] }, { urls: ['stun:stun.example.com:3478'] }] });
    await loadConfig();
    expect(iceServers()).toHaveLength(1);
  });

  it('keeps the last known config on a fetch failure', async () => {
    mockConfig({ iceServers: [{ urls: ['stun:stun.example.com:3478'] }] });
    await loadConfig();
    expect(iceServers()).toHaveLength(1);

    // A later refresh that fails must not clobber the known-good config.
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('network')));
    await loadConfig();
    expect(iceServers()).toHaveLength(1);
  });
});
