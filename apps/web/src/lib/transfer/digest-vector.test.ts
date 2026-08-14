import { describe, expect, it } from 'vitest';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { bytesToHex, sha256, type DigestState } from '@sendbeam/protocol';
import { createSha256DigestFactory } from './digest.js';

interface Scenario {
  name: string;
  prefixHex: string;
  suffixHex: string;
  prefixDigest: string;
  fullDigest: string;
}

const vectorUrl = new URL(
  '../../../../../docs/test-vectors/digest-checkpoint.json',
  import.meta.url,
);
const doc = JSON.parse(readFileSync(fileURLToPath(vectorUrl), 'utf8')) as {
  scenarios: Scenario[];
};

function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

describe('digest-checkpoint vector (V13-PR05)', () => {
  it('reproduces every scenario, including save/restore continuation', async () => {
    expect(doc.scenarios.length).toBeGreaterThan(0);
    const make = await createSha256DigestFactory();
    for (const s of doc.scenarios) {
      const prefix = fromHex(s.prefixHex);
      const suffix = fromHex(s.suffixHex);
      expect(bytesToHex(await sha256(prefix)), `${s.name} prefix digest`).toBe(s.prefixDigest);
      const whole = new Uint8Array(prefix.length + suffix.length);
      whole.set(prefix);
      whole.set(suffix, prefix.length);
      expect(bytesToHex(await sha256(whole)), `${s.name} full digest`).toBe(s.fullDigest);

      // Restore from the serialized state covering the prefix, then continue with the
      // suffix: must equal one-shot hashing of prefix+suffix.
      const live = make();
      live.update(prefix);
      const state = (live as unknown as DigestState).saveState();
      const restored = make.restore(state);
      restored.update(suffix);
      expect(await restored.hexDigest(), `${s.name} restored continuation`).toBe(s.fullDigest);
    }
  });
});
