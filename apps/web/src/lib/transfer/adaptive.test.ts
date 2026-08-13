import { describe, expect, it } from 'vitest';
import {
  AdaptivePolicy,
  Connection,
  Gathering,
  DEFAULT_ESCALATION_MS,
  type AdaptiveEvent,
} from './adaptive.js';

/** Feed an event and return the decision (type convenience). */
function observe(policy: AdaptivePolicy, ev: AdaptiveEvent): string {
  return policy.observe(ev);
}

describe('AdaptivePolicy — direct/relay racing', () => {
  it('direct-wins: chooses direct when a server-reflexive hint appears and connects', () => {
    const p = new AdaptivePolicy();
    expect(
      observe(p, {
        gathering: Gathering.Gathering,
        connection: Connection.Checking,
        hasServerReflexive: true,
        hasAnyCandidate: true,
      }),
    ).toBe('continue');
    expect(
      observe(p, {
        connection: Connection.Connected,
        hasServerReflexive: true,
        hasAnyCandidate: true,
      }),
    ).toBe('direct-won');
    expect(p.scalableDirect()).toBe(true);
  });

  it('relay-wins (no candidates): warms relay when gathering completes with zero candidates', () => {
    const p = new AdaptivePolicy();
    expect(
      observe(p, {
        gathering: Gathering.Complete,
        hasServerReflexive: false,
        hasAnyCandidate: false,
      }),
    ).toBe('warm-relay');
  });

  it('host-only keeps direct in the race (loopback/LAN) instead of falling back immediately', () => {
    let now = 0;
    const p = new AdaptivePolicy({ escalationMs: 5000, now: () => now });
    expect(
      observe(p, {
        gathering: Gathering.Complete,
        hasServerReflexive: false,
        hasAnyCandidate: true,
      }),
    ).toBe('continue');
    now += 2000;
    expect(
      observe(p, {
        connection: Connection.Checking,
        hasServerReflexive: false,
        hasAnyCandidate: true,
      }),
    ).toBe('continue');
    expect(
      observe(p, {
        connection: Connection.Connected,
        hasServerReflexive: false,
        hasAnyCandidate: true,
      }),
    ).toBe('direct-won');
  });

  it('relay-wins (ICE failed): warms relay immediately on a failed connection regardless of hints', () => {
    const p = new AdaptivePolicy();
    expect(
      observe(p, {
        connection: Connection.Failed,
        hasServerReflexive: true,
        hasAnyCandidate: true,
      }),
    ).toBe('warm-relay');
  });

  it('both-ready: commits to direct-won on a connected outcome and stays settled', () => {
    const p = new AdaptivePolicy();
    observe(p, {
      connection: Connection.Checking,
      hasServerReflexive: true,
      hasAnyCandidate: true,
    });
    expect(
      observe(p, {
        connection: Connection.Connected,
        hasServerReflexive: true,
        hasAnyCandidate: true,
      }),
    ).toBe('direct-won');
    // A later failure must not flip a settled direct-won.
    expect(
      observe(p, {
        connection: Connection.Failed,
        hasServerReflexive: true,
        hasAnyCandidate: true,
      }),
    ).toBe('direct-won');
    expect(p.scalableDirect()).toBe(true);
  });

  it('late-direct: with a server-reflexive hint, no escalation deadline preempts a slow-but-healthy direct', () => {
    let now = 0;
    const p = new AdaptivePolicy({ escalationMs: 5000, now: () => now });
    expect(
      observe(p, {
        connection: Connection.Checking,
        hasServerReflexive: true,
        hasAnyCandidate: true,
      }),
    ).toBe('continue');
    now += 10_000_000;
    expect(
      observe(p, {
        gathering: Gathering.Gathering,
        hasServerReflexive: true,
        hasAnyCandidate: true,
      }),
    ).toBe('continue');
    expect(
      observe(p, {
        connection: Connection.Connected,
        hasServerReflexive: true,
        hasAnyCandidate: true,
      }),
    ).toBe('direct-won');
  });

  it('simultaneous-failure: no candidate + stalled-then-failed resolves to a relay warm', () => {
    let now = 0;
    const p = new AdaptivePolicy({ escalationMs: 2000, now: () => now });
    expect(
      observe(p, {
        connection: Connection.Checking,
        hasServerReflexive: false,
        hasAnyCandidate: false,
      }),
    ).toBe('continue');
    now += 3000;
    expect(
      observe(p, {
        connection: Connection.Failed,
        hasServerReflexive: false,
        hasAnyCandidate: false,
      }),
    ).toBe('warm-relay');
  });

  it('cancel-during-race: transient observations never settle on either path', () => {
    const p = new AdaptivePolicy({ escalationMs: DEFAULT_ESCALATION_MS });
    expect(
      observe(p, { gathering: Gathering.New, hasServerReflexive: false, hasAnyCandidate: false }),
    ).toBe('continue');
    expect(
      observe(p, {
        gathering: Gathering.Gathering,
        connection: Connection.Checking,
        hasServerReflexive: false,
        hasAnyCandidate: false,
      }),
    ).toBe('continue');
    expect(p.scalableDirect()).toBe(true);
  });

  it('bounded escalation: host-only direct stuck in checking eventually warms the relay', () => {
    let now = 0;
    const p = new AdaptivePolicy({ escalationMs: 2000, now: () => now });
    observe(p, { gathering: Gathering.Complete, hasServerReflexive: false, hasAnyCandidate: true });
    now += 1000;
    expect(
      observe(p, {
        connection: Connection.Checking,
        hasServerReflexive: false,
        hasAnyCandidate: true,
      }),
    ).toBe('continue');
    now += 3000;
    expect(
      observe(p, {
        connection: Connection.Checking,
        hasServerReflexive: false,
        hasAnyCandidate: true,
      }),
    ).toBe('warm-relay');
  });

  it('default escalation stays faster than the legacy ~8s blind timer', () => {
    expect(DEFAULT_ESCALATION_MS).toBeGreaterThan(0);
    expect(DEFAULT_ESCALATION_MS).toBeLessThan(8000);
  });
});
