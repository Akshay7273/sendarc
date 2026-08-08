import { describe, expect, it } from 'vitest';

import {
  codeFromHash,
  describeCaps,
  describeError,
  humanBytes,
  inviteLinkFor,
  phaseLabel,
  progressLabel,
  progressPercent,
  sasFingerprint,
} from './present.js';

describe('sasFingerprint', () => {
  it('matches the canonical cross-implementation vector', async () => {
    // master = 0,1,…,31. The Go CLI and a Python reference both derive "7948 2d83"; the
    // browser must agree, since the two humans read this value to each other out of band.
    const master = Uint8Array.from({ length: 32 }, (_, i) => i);
    expect(await sasFingerprint(master)).toBe('7948 2d83');
  });

  it('formats as two space-separated 16-bit hex groups', async () => {
    const fp = await sasFingerprint(new Uint8Array(32));
    expect(fp).toMatch(/^[0-9a-f]{4} [0-9a-f]{4}$/);
  });
});

describe('inviteLinkFor', () => {
  it('carries the code in the fragment', () => {
    expect(inviteLinkFor('https://send.example/', '3-brave-otter')).toBe(
      'https://send.example/#3-brave-otter',
    );
  });

  it('replaces an existing fragment and keeps the path', () => {
    expect(inviteLinkFor('https://send.example/app#stale', '5-lively-quail')).toBe(
      'https://send.example/app#5-lively-quail',
    );
  });
});

describe('codeFromHash', () => {
  it('strips the leading hash and trims', () => {
    expect(codeFromHash('#3-brave-otter')).toBe('3-brave-otter');
    expect(codeFromHash('  #7-lively-quail  ')).toBe('7-lively-quail');
  });

  it('returns empty for no fragment', () => {
    expect(codeFromHash('')).toBe('');
    expect(codeFromHash('#')).toBe('');
  });
});

describe('humanBytes', () => {
  it('uses IEC units on exact multiples and bytes otherwise', () => {
    expect(humanBytes(1 << 20)).toBe('1 MiB');
    expect(humanBytes(16 * 1024)).toBe('16 KiB');
    expect(humanBytes(1500)).toBe('1500 B');
    expect(humanBytes(0)).toBe('0 B');
  });
});

describe('describeCaps', () => {
  it('reads version, frame, and block sizes', () => {
    expect(
      describeCaps({
        version: '1',
        maxFrame: 16384,
        blockSize: 1 << 20,
        features: [],
        sinkHints: [],
      }),
    ).toBe('1 · 16 KiB frames · 1 MiB blocks');
  });
});

describe('describeError', () => {
  it('translates a confirmation failure into code-mismatch guidance', () => {
    expect(describeError({ code: 'confirmation_failed', message: 'x' })).toMatch(/did not match/i);
  });

  it('falls back to the message for unknown codes', () => {
    expect(describeError({ code: 'weird', message: 'something specific' })).toBe(
      'something specific',
    );
  });
});

describe('phaseLabel', () => {
  it('labels every known phase', () => {
    expect(phaseLabel('waiting')).toMatch(/waiting/i);
    expect(phaseLabel('established')).toBe('Connected');
  });
});

describe('progressPercent', () => {
  it('is 0 for zero total (avoids divide-by-zero)', () => {
    expect(progressPercent(0, 0)).toBe(0);
  });
  it('rounds down to an integer percent', () => {
    expect(progressPercent(1, 3)).toBe(33);
  });
  it('clamps to 100 when done exceeds total', () => {
    expect(progressPercent(10, 5)).toBe(100);
  });
});

describe('progressLabel', () => {
  it('formats done/total with percent', () => {
    // humanBytes renders IEC units only on exact power-of-two multiples: 1_572_864 = 1536·1024.
    expect(progressLabel(1_572_864, 4_194_304)).toBe('1536 KiB / 4 MiB (37%)');
  });
  it('shows 100% at completion', () => {
    expect(progressLabel(4_194_304, 4_194_304)).toBe('4 MiB / 4 MiB (100%)');
  });
});
