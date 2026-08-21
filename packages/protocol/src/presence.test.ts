import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes } from './bytes.js';
import {
  DEFAULT_RENDEZVOUS_EPOCH_WINDOW_MS,
  deriveLanBeaconTag,
  derivePresenceProof,
  deriveRendezvousHandle,
  deriveRendezvousHandlesWithSkew,
  matchLanBeaconTag,
  verifyPresenceProof,
} from './presence.js';

interface PresenceVector {
  name: string;
  k_pair_hex: string;
  timestamp: string;
  epoch_index: number;
  rendezvous_handle: string;
  skew_handles: string[];
  presence_nonce_hex: string;
  presence_proof_hex: string;
  beacon_nonce_hex: string;
  beacon_tag_hex: string;
}

describe('Presence and LAN discovery cross-language vector validation (sendbeam/2)', () => {
  const vectorPath = resolve(__dirname, '../../wire/testdata/presence-vectors.json');
  const vectorContent = readFileSync(vectorPath, 'utf-8');
  const vectors: PresenceVector[] = JSON.parse(vectorContent);

  it('matches Go generated presence vector byte-for-byte', async () => {
    for (const vec of vectors) {
      const kPair = hexToBytes(vec.k_pair_hex);
      const presenceNonce = hexToBytes(vec.presence_nonce_hex);
      const beaconNonce = hexToBytes(vec.beacon_nonce_hex);

      // Derive rendezvous handle
      const handle = await deriveRendezvousHandle(kPair, vec.epoch_index);
      expect(handle).toBe(vec.rendezvous_handle);

      // Derive skew handles
      const date = new Date(vec.timestamp);
      const skewHandles = await deriveRendezvousHandlesWithSkew(
        kPair,
        date,
        DEFAULT_RENDEZVOUS_EPOCH_WINDOW_MS,
      );
      expect(skewHandles).toEqual(vec.skew_handles);

      // Presence proof
      const proof = await derivePresenceProof(kPair, handle, presenceNonce);
      expect(proof).toBe(vec.presence_proof_hex);
      expect(await verifyPresenceProof(kPair, handle, presenceNonce, proof)).toBe(true);

      // Blinded LAN beacon tag
      const tag = await deriveLanBeaconTag(kPair, beaconNonce, vec.epoch_index);
      expect(bytesToHex(tag)).toBe(vec.beacon_tag_hex);

      // Match beacon tag
      const matched = await matchLanBeaconTag(
        kPair,
        beaconNonce,
        tag,
        date.getTime(),
        date.getTime(),
        DEFAULT_RENDEZVOUS_EPOCH_WINDOW_MS,
      );
      expect(matched).toBe(true);
    }
  });

  it('rejects stale beacon tags and invalid proofs', async () => {
    const kPair = hexToBytes('8b4c642283597de370a8313836bcc86ca6718f0d71fa4f301134d3f049da2848');
    const nonce = hexToBytes('c83888c50dc690cbf88691633df49122');
    const now = Date.now();
    const tag = await deriveLanBeaconTag(
      kPair,
      nonce,
      Math.floor(now / DEFAULT_RENDEZVOUS_EPOCH_WINDOW_MS),
    );

    // Stale timestamp (> 2 windows)
    const staleTime = now + 4 * DEFAULT_RENDEZVOUS_EPOCH_WINDOW_MS;
    const matchedStale = await matchLanBeaconTag(kPair, nonce, tag, now, staleTime);
    expect(matchedStale).toBe(false);

    // Wrong proof
    const proofValid = await verifyPresenceProof(
      kPair,
      'handle-1',
      nonce,
      bytesToHex(new Uint8Array(32)),
    );
    expect(proofValid).toBe(false);
  });
});
