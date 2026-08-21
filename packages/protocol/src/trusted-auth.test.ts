import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes } from './bytes.js';
import { createDeviceIdentityFromSeed } from './identity.js';
import {
  createTrustedAuthConfirm,
  createTrustedAuthInit,
  createTrustedAuthResponse,
  deriveTrustedSessionKeys,
  DOMAIN_TRUSTED_CONFIRM_INIT,
  DOMAIN_TRUSTED_CONFIRM_RESP,
  verifyTrustedAuthConfirm,
  verifyTrustedAuthInit,
  verifyTrustedAuthResponse,
} from './trusted-auth.js';

interface TrustedVector {
  name: string;
  k_pair_hex: string;
  pair_cred_ref: string;
  init_seed_hex: string;
  init_device_id: string;
  init_pub_key_hex: string;
  init_ephem_pub_hex: string;
  init_nonce_hex: string;
  init_caps: string[];
  init_timestamp: string;
  init_sig_hex: string;
  init_auth_tag_hex: string;
  resp_seed_hex: string;
  resp_device_id: string;
  resp_pub_key_hex: string;
  resp_ephem_pub_hex: string;
  resp_nonce_hex: string;
  resp_caps: string[];
  resp_sig_hex: string;
  resp_auth_tag_hex: string;
  session_master_hex: string;
  i2r_key_hex: string;
  r2i_key_hex: string;
  init_confirm_tag: string;
  resp_confirm_tag: string;
}

describe('Trusted session cross-language vector validation (sendbeam/2)', () => {
  const vectorPath = resolve(__dirname, '../../wire/testdata/trusted-session-vectors.json');
  const vectorContent = readFileSync(vectorPath, 'utf-8');
  const vectors: TrustedVector[] = JSON.parse(vectorContent);

  it('matches Go generated trusted-session vector byte-for-byte', async () => {
    for (const vec of vectors) {
      const kPair = hexToBytes(vec.k_pair_hex);
      const initSeed = hexToBytes(vec.init_seed_hex);
      const respSeed = hexToBytes(vec.resp_seed_hex);

      const idInit = await createDeviceIdentityFromSeed(initSeed);
      const idResp = await createDeviceIdentityFromSeed(respSeed);

      expect(idInit.deviceId).toBe(vec.init_device_id);
      expect(bytesToHex(idInit.publicKey)).toBe(vec.init_pub_key_hex);
      expect(idResp.deviceId).toBe(vec.resp_device_id);
      expect(bytesToHex(idResp.publicKey)).toBe(vec.resp_pub_key_hex);

      const initEphem = hexToBytes(vec.init_ephem_pub_hex);
      const initNonce = hexToBytes(vec.init_nonce_hex);
      const respEphem = hexToBytes(vec.resp_ephem_pub_hex);
      const respNonce = hexToBytes(vec.resp_nonce_hex);

      // Create TrustedAuthInit and verify against vector
      const initMsg = await createTrustedAuthInit(
        idInit,
        idResp.deviceId,
        vec.pair_cred_ref,
        kPair,
        vec.init_caps,
        initEphem,
        initNonce,
        vec.init_timestamp,
      );
      expect(initMsg.signature).toBe(vec.init_sig_hex);
      expect(initMsg.auth_tag).toBe(vec.init_auth_tag_hex);

      // Verify TrustedAuthInit on responder side
      const verifiedInit = await verifyTrustedAuthInit(
        initMsg,
        kPair,
        idInit.publicKey,
        idResp.deviceId,
        vec.init_timestamp,
      );
      expect(bytesToHex(verifiedInit.ephemeralPub)).toBe(vec.init_ephem_pub_hex);
      expect(bytesToHex(verifiedInit.nonce)).toBe(vec.init_nonce_hex);

      // Create TrustedAuthResponse and verify against vector
      const respMsg = await createTrustedAuthResponse(
        idResp,
        initMsg,
        kPair,
        vec.resp_caps,
        respEphem,
        respNonce,
      );
      expect(respMsg.signature).toBe(vec.resp_sig_hex);
      expect(respMsg.auth_tag).toBe(vec.resp_auth_tag_hex);

      // Verify TrustedAuthResponse on initiator side
      const verifiedResp = await verifyTrustedAuthResponse(
        respMsg,
        initMsg,
        kPair,
        idResp.publicKey,
        idInit.deviceId,
      );
      expect(bytesToHex(verifiedResp.ephemeralPub)).toBe(vec.resp_ephem_pub_hex);
      expect(bytesToHex(verifiedResp.nonce)).toBe(vec.resp_nonce_hex);

      // Derive forward-secret session keys on both sides
      const keysAlice = await deriveTrustedSessionKeys(
        kPair,
        initEphem,
        verifiedResp.ephemeralPub,
        initNonce,
        verifiedResp.nonce,
        idInit.deviceId,
        idResp.deviceId,
        vec.init_caps,
        respMsg.capabilities || [],
      );

      const keysBob = await deriveTrustedSessionKeys(
        kPair,
        verifiedInit.ephemeralPub,
        respEphem,
        verifiedInit.nonce,
        respNonce,
        initMsg.initiator_device_id,
        idResp.deviceId,
        initMsg.capabilities,
        vec.resp_caps,
      );

      expect(bytesToHex(keysAlice.sessionMaster)).toBe(vec.session_master_hex);
      expect(bytesToHex(keysBob.sessionMaster)).toBe(vec.session_master_hex);
      expect(bytesToHex(keysAlice.initiatorToResponderKey)).toBe(vec.i2r_key_hex);
      expect(bytesToHex(keysBob.initiatorToResponderKey)).toBe(vec.i2r_key_hex);
      expect(bytesToHex(keysAlice.responderToInitiatorKey)).toBe(vec.r2i_key_hex);
      expect(bytesToHex(keysBob.responderToInitiatorKey)).toBe(vec.r2i_key_hex);

      // Confirmation tags
      const confInit = await createTrustedAuthConfirm(
        keysAlice.sessionMaster,
        DOMAIN_TRUSTED_CONFIRM_INIT,
        idInit.deviceId,
        true,
      );
      expect(confInit.auth_tag).toBe(vec.init_confirm_tag);
      await expect(
        verifyTrustedAuthConfirm(
          confInit,
          keysBob.sessionMaster,
          DOMAIN_TRUSTED_CONFIRM_INIT,
          idInit.deviceId,
        ),
      ).resolves.toBeUndefined();

      const confResp = await createTrustedAuthConfirm(
        keysBob.sessionMaster,
        DOMAIN_TRUSTED_CONFIRM_RESP,
        idResp.deviceId,
        true,
      );
      expect(confResp.auth_tag).toBe(vec.resp_confirm_tag);
      await expect(
        verifyTrustedAuthConfirm(
          confResp,
          keysAlice.sessionMaster,
          DOMAIN_TRUSTED_CONFIRM_RESP,
          idResp.deviceId,
        ),
      ).resolves.toBeUndefined();
    }
  });

  it('rejects expired timestamps, mismatched peers, forged signatures, and revoked peers', async () => {
    const kPair = hexToBytes('b578beac8f38df62b3f7f744ad47e6a6a6f17a7db6427e3949f981da8eb29b7d');
    const idInit = await createDeviceIdentityFromSeed(
      hexToBytes('34c86db8b3903e5dcf9582abb21e0340602f233b2e12b6e4de11afd585174a3a'),
    );
    const idResp = await createDeviceIdentityFromSeed(
      hexToBytes('4fb61397bb78ad872f082a4dda02286fc585e612b731664e9b9398d85a3e85df'),
    );

    const now = new Date('2026-08-21T12:00:00Z');
    const initMsg = await createTrustedAuthInit(
      idInit,
      idResp.deviceId,
      'cred-test',
      kPair,
      ['transfer.v1'],
      undefined,
      undefined,
      now,
    );

    // 1. Clock skew > 5 minutes
    const expiredDate = new Date('2026-08-21T11:50:00Z');
    await expect(
      verifyTrustedAuthInit(initMsg, kPair, idInit.publicKey, idResp.deviceId, expiredDate),
    ).rejects.toThrow(/timestamp outside acceptable skew window/);

    // 2. Peer mismatch
    await expect(
      verifyTrustedAuthInit(initMsg, kPair, idInit.publicKey, 'sb-dev-wrong', now),
    ).rejects.toThrow(/peer device ID mismatch/);

    // 3. Forged signature
    await expect(
      verifyTrustedAuthInit(
        { ...initMsg, signature: bytesToHex(new Uint8Array(64)) },
        kPair,
        idInit.publicKey,
        idResp.deviceId,
        now,
      ),
    ).rejects.toThrow(/signature verification failed/);

    // 4. Tampered auth tag
    await expect(
      verifyTrustedAuthInit(
        { ...initMsg, auth_tag: bytesToHex(new Uint8Array(32)) },
        kPair,
        idInit.publicKey,
        idResp.deviceId,
        now,
      ),
    ).rejects.toThrow(/MAC tag verification failed/);

    // 5. Revoked status in response
    const respRevoked = {
      type: 'trusted_auth_response' as const,
      protocol_version: 'sendbeam/2' as const,
      status: 'revoked' as const,
      responder_device_id: idResp.deviceId,
    };
    await expect(
      verifyTrustedAuthResponse(respRevoked, initMsg, kPair, idResp.publicKey, idInit.deviceId),
    ).rejects.toThrow(/trusted peer device is revoked/);
  });
});
