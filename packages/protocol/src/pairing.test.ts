import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes } from './bytes.js';
import { createDeviceIdentityFromSeed } from './identity.js';
import {
  computePairingConfirmTag,
  createPairingConfirm,
  createPairingRequest,
  createPairingResponse,
  derivePairCredential,
  verifyPairingConfirm,
  verifyPairingRequest,
  verifyPairingResponse,
  type PairingConfirm,
} from './pairing.js';

interface PairingVector {
  name: string;
  master_key_hex: string;
  req_seed_hex: string;
  req_device_id: string;
  req_pub_key_hex: string;
  req_name: string;
  req_caps: string[];
  req_nonce_hex: string;
  req_sig_hex: string;
  resp_seed_hex: string;
  resp_device_id: string;
  resp_pub_key_hex: string;
  resp_name: string;
  resp_caps: string[];
  resp_nonce_hex: string;
  resp_sig_hex: string;
  k_pair_hex: string;
  pair_cred_ref: string;
  req_confirm_tag: string;
  resp_confirm_tag: string;
}

describe('Pairing ceremony cross-language vector validation', () => {
  const vectorPath = resolve(__dirname, '../../wire/testdata/pairing-vectors.json');
  const vectorContent = readFileSync(vectorPath, 'utf-8');
  const vectors: PairingVector[] = JSON.parse(vectorContent);

  it('matches Go generated pairing vector byte-for-byte', async () => {
    for (const vec of vectors) {
      const masterKey = hexToBytes(vec.master_key_hex);
      const reqSeed = hexToBytes(vec.req_seed_hex);
      const respSeed = hexToBytes(vec.resp_seed_hex);

      const idReq = await createDeviceIdentityFromSeed(reqSeed);
      const idResp = await createDeviceIdentityFromSeed(respSeed);

      expect(idReq.deviceId).toBe(vec.req_device_id);
      expect(bytesToHex(idReq.publicKey)).toBe(vec.req_pub_key_hex);
      expect(idResp.deviceId).toBe(vec.resp_device_id);
      expect(bytesToHex(idResp.publicKey)).toBe(vec.resp_pub_key_hex);

      const reqNonce = hexToBytes(vec.req_nonce_hex);
      const respNonce = hexToBytes(vec.resp_nonce_hex);

      // Create request and check signature against vector
      const req = await createPairingRequest(
        idReq,
        vec.req_name,
        vec.req_caps,
        masterKey,
        reqNonce,
      );
      expect(req.signature).toBe(vec.req_sig_hex);

      // Verify request
      const verifiedReq = await verifyPairingRequest(req, masterKey);
      expect(bytesToHex(verifiedReq.publicKey)).toBe(vec.req_pub_key_hex);
      expect(bytesToHex(verifiedReq.nonce)).toBe(vec.req_nonce_hex);

      // Create response and check signature against vector
      const resp = await createPairingResponse(
        idResp,
        vec.resp_name,
        vec.resp_caps,
        masterKey,
        reqNonce,
        respNonce,
      );
      expect(resp.signature).toBe(vec.resp_sig_hex);

      // Verify response
      const verifiedResp = await verifyPairingResponse(resp, reqNonce, masterKey);
      expect(bytesToHex(verifiedResp.publicKey)).toBe(vec.resp_pub_key_hex);
      expect(bytesToHex(verifiedResp.nonce)).toBe(vec.resp_nonce_hex);

      // Derive k_pair from both sides
      const pairAlice = await derivePairCredential(
        masterKey,
        reqNonce,
        verifiedResp.nonce,
        idReq.publicKey,
        verifiedResp.publicKey,
      );
      const pairBob = await derivePairCredential(
        masterKey,
        verifiedReq.nonce,
        respNonce,
        verifiedReq.publicKey,
        idResp.publicKey,
      );

      expect(bytesToHex(pairAlice.kPair)).toBe(vec.k_pair_hex);
      expect(bytesToHex(pairBob.kPair)).toBe(vec.k_pair_hex);
      expect(pairAlice.credRef).toBe(vec.pair_cred_ref);
      expect(pairBob.credRef).toBe(vec.pair_cred_ref);

      // Confirmation tags
      const aliceConfirmTag = await computePairingConfirmTag(pairAlice.kPair, idResp.deviceId);
      expect(aliceConfirmTag).toBe(vec.req_confirm_tag);

      const bobConfirmTag = await computePairingConfirmTag(pairBob.kPair, idReq.deviceId);
      expect(bobConfirmTag).toBe(vec.resp_confirm_tag);
    }
  });

  it('rejects tampered signatures, rogue keys, and malformed tags', async () => {
    const masterKey = hexToBytes(
      '78cc244e0bf23d5adb622030d371798318dc624ab7656bec6866e822a5f92497',
    );
    const idA = await createDeviceIdentityFromSeed(
      hexToBytes('f86485bec02cb4501eab04a0167c7354e4232fc23f5c8761d8c730d429651f61'),
    );
    const idB = await createDeviceIdentityFromSeed(
      hexToBytes('980a6426b9cd61e3c5695cb915fa1e7f39f788508a4e2538a57766a8e4e9ebb1'),
    );

    const nonceA = hexToBytes('b9d81bca729d78625201c17a8b9909aca3880515d53176b967207713d1d0d725');
    const nonceB = hexToBytes('296b24ab56c4781c3569f10ad9ea4c773fb1b98652096e58cc236207dfef0ea4');

    const req = await createPairingRequest(idA, 'Alice', ['transfer.v1'], masterKey, nonceA);

    // Tampered device id
    await expect(
      verifyPairingRequest({ ...req, device_id: idB.deviceId }, masterKey),
    ).rejects.toThrow(/pairing device ID does not match public key/);

    // Tampered signature
    await expect(
      verifyPairingRequest({ ...req, signature: bytesToHex(new Uint8Array(64)) }, masterKey),
    ).rejects.toThrow(/pairing signature verification failed/);

    // Wrong master key
    const rogueMaster = new Uint8Array(32);
    await expect(verifyPairingRequest(req, rogueMaster)).rejects.toThrow(
      /pairing signature verification failed/,
    );

    // Response with wrong request nonce
    const resp = await createPairingResponse(
      idB,
      'Bob',
      ['transfer.v1'],
      masterKey,
      nonceA,
      nonceB,
    );
    const wrongNonce = new Uint8Array(32);
    await expect(verifyPairingResponse(resp, wrongNonce, masterKey)).rejects.toThrow(
      /pairing signature verification failed/,
    );

    // Confirm rejection
    const { kPair } = await derivePairCredential(
      masterKey,
      nonceA,
      nonceB,
      idA.publicKey,
      idB.publicKey,
    );
    const rejectedConfirm = await createPairingConfirm(kPair, idB.deviceId, false);
    await expect(verifyPairingConfirm(rejectedConfirm, kPair, idB.deviceId)).rejects.toThrow(
      /pairing ceremony was rejected by peer/,
    );

    // Tampered confirm auth tag
    const badTagConfirm: PairingConfirm = {
      type: 'pairing_confirm',
      status: 'accepted',
      auth_tag: bytesToHex(new Uint8Array(32)),
    };
    await expect(verifyPairingConfirm(badTagConfirm, kPair, idB.deviceId)).rejects.toThrow(
      /pairing confirmation authentication tag verification failed/,
    );
  });
});
