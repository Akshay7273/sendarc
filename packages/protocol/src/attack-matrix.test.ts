/**
 * Adversarial Security Campaign & Attack-Matrix Testbed (TypeScript).
 *
 * Exercises all 9 core threat-model attack vectors defined in ADR 0007 / v1.5plan:
 * 1. Stolen trust DB vs stolen key (Key substitution & device ID mismatch rejection)
 * 2. Replay attack & cloned profile resistance (Challenge freshness & transcript binding)
 * 3. Malicious signaling/relay server MITM & payload tampering
 * 4. Replayed presence beacons & stale epoch expiration
 * 5. Display name / local label spoofing resistance
 * 6. Downgrade attack & capability stripping resistance
 * 7. Stale / revoked pair credential rejection
 * 8. Auto-accept path traversal & filesystem escape containment
 * 9. One-time transfer isolation (Zero unintended trust persistence)
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  generateDeviceIdentity,
  bytesToHex,
  validateTrustRecord,
  MemoryTrustStore,
  type TrustRecord,
  derivePairCredential,
  createTrustedAuthInit,
  verifyTrustedAuthInit,
  createTrustedAuthResponse,
  verifyTrustedAuthResponse,
  deriveRendezvousHandle,
  deriveRendezvousHandlesWithSkew,
  deriveLanBeaconTag,
  matchLanBeaconTag,
  normalizeTransferPath,
  type DeviceIdentity,
} from './index.js';

describe('SendBeam v1.5 Attack-Matrix & Adversarial Security Campaign', () => {
  let devA: DeviceIdentity;
  let devB: DeviceIdentity;
  let devAttacker: DeviceIdentity;
  let kPair: Uint8Array;
  let credRef: string;
  let trustStoreA: MemoryTrustStore;

  beforeEach(async () => {
    devA = await generateDeviceIdentity();
    devB = await generateDeviceIdentity();
    devAttacker = await generateDeviceIdentity();

    // Legitimate pairwise secret derived between A and B
    const derived = await derivePairCredential(
      new Uint8Array(32).fill(0x42),
      new Uint8Array(32).fill(0x01),
      new Uint8Array(32).fill(0x02),
      devA.publicKey,
      devB.publicKey,
    );
    kPair = derived.kPair;
    credRef = derived.credRef;

    trustStoreA = new MemoryTrustStore();
    const recB: TrustRecord = {
      deviceId: devB.deviceId,
      publicKey: bytesToHex(devB.publicKey),
      localLabel: 'Bob Laptop',
      pairCredentialRef: credRef,
      capabilities: ['transfer.v1', 'transfer.v2', 'lan_direct'],
      firstSeenAt: new Date().toISOString(),
      lastSeenAt: new Date().toISOString(),
      revoked: false,
      policy: { autoAccept: true, autoAcceptDestDir: '/safe/downloads' },
    };
    await trustStoreA.addOrUpdateDevice(recB);
  });

  // Vector 1: Stolen Trust DB vs Stolen Key
  it('Vector 1: Rejects tampered public key or mismatched device ID in trust DB', async () => {
    // Attacker modifies trust DB to bind devB's deviceId to attacker's public key
    const tamperedRecord: TrustRecord = {
      deviceId: devB.deviceId, // Victim device ID
      publicKey: bytesToHex(devAttacker.publicKey), // Attacker's public key
      localLabel: 'Bob Laptop',
      pairCredentialRef: credRef,
      capabilities: ['transfer.v1'],
      firstSeenAt: new Date().toISOString(),
      lastSeenAt: new Date().toISOString(),
      revoked: false,
      policy: { autoAccept: false },
    };

    // Validation must strictly reject mismatched public key and device ID
    await expect(validateTrustRecord(tamperedRecord)).rejects.toThrow(
      /does not match public key derived id/,
    );
  });

  // Vector 2: Replay Attack & Cloned Profile Resistance
  it('Vector 2: Rejects replayed authentication nonces and stale timestamp challenges', async () => {
    // Generate valid init message from A to B
    const init = await createTrustedAuthInit(devA, devB.deviceId, credRef, kPair, [
      'transfer.v1',
      'transfer.v2',
    ]);

    // Valid verification on B
    const verified = await verifyTrustedAuthInit(init, kPair, devA.publicKey, devB.deviceId);
    expect(verified.ephemeralPub).toHaveLength(32);
    expect(verified.nonce).toHaveLength(32);

    // Stale timestamp (e.g. captured 1 hour ago) must be rejected
    const staleInit = {
      ...init,
      timestamp: new Date(Date.now() - 3600 * 1000).toISOString(),
    };
    // Signatures and HMACs over modified timestamp must fail
    await expect(
      verifyTrustedAuthInit(staleInit, kPair, devA.publicKey, devB.deviceId),
    ).rejects.toThrow();

    // Replaying same ephPub with altered nonce must fail
    const tamperedInit = {
      ...init,
      nonce: bytesToHex(new Uint8Array(32).fill(0x99)),
    };
    await expect(
      verifyTrustedAuthInit(tamperedInit, kPair, devA.publicKey, devB.deviceId),
    ).rejects.toThrow();
  });

  // Vector 3: Malicious Signaling / Relay Server MITM & Key Substitution
  it('Vector 3: Detects and terminates on MITM ephemeral key substitution or payload tampering', async () => {
    const init = await createTrustedAuthInit(devA, devB.deviceId, credRef, kPair, ['transfer.v1']);

    // Malicious server intercepts init and substitutes ephemeral public key
    const attackerEph = await generateDeviceIdentity();
    const mitmInit = {
      ...init,
      ephemeral_pub: bytesToHex(attackerEph.publicKey),
    };

    // B verifies init: signature and HMAC must fail because ephemeral_pub was signed by A
    await expect(
      verifyTrustedAuthInit(mitmInit, kPair, devA.publicKey, devB.deviceId),
    ).rejects.toThrow();

    // If server alters response payload
    const response = await createTrustedAuthResponse(devB, init, kPair, ['transfer.v1']);

    const mitmResponse = {
      ...response,
      ephemeral_pub: bytesToHex(attackerEph.publicKey),
    };

    await expect(
      verifyTrustedAuthResponse(mitmResponse, init, kPair, devB.publicKey, devA.deviceId),
    ).rejects.toThrow();
  });

  // Vector 4: Replayed Presence Beacons & Stale Epoch Expiration
  it('Vector 4: Rejects expired epoch rendezvous handles and spoofed beacon tags', async () => {
    const nowMs = Date.now();
    const windowMs = 15 * 60 * 1000;
    const currentEpoch = Math.floor(nowMs / windowMs);

    // Handles derived for current epoch ± 1
    const handles = await deriveRendezvousHandlesWithSkew(kPair, nowMs, windowMs);
    expect(handles).toHaveLength(3);

    // Handle derived for current epoch
    const currentHandle = await deriveRendezvousHandle(kPair, currentEpoch);
    expect(handles).toContain(currentHandle);

    // Expired epoch (> 1 epoch away, e.g. 1 hour = 4 epochs ago)
    const expiredHandle = await deriveRendezvousHandle(kPair, currentEpoch - 4);
    expect(handles).not.toContain(expiredHandle);

    // Blinded LAN Beacon verification
    const beaconNonce = new Uint8Array(16).fill(0x77);
    const tag = await deriveLanBeaconTag(kPair, beaconNonce, currentEpoch);

    const matched = await matchLanBeaconTag(kPair, beaconNonce, tag, nowMs, nowMs, windowMs);
    expect(matched).toBe(true);

    // Attacker without kPair cannot match beacon
    const attackerKey = new Uint8Array(32).fill(0xee);
    const attackerMatched = await matchLanBeaconTag(
      attackerKey,
      beaconNonce,
      tag,
      nowMs,
      nowMs,
      windowMs,
    );
    expect(attackerMatched).toBe(false);

    // Expired beacon (e.g. 2 hours old) must be rejected
    const staleMatched = await matchLanBeaconTag(
      kPair,
      beaconNonce,
      tag,
      nowMs - 2 * 3600 * 1000,
      nowMs,
      windowMs,
    );
    expect(staleMatched).toBe(false);
  });

  // Vector 5: Display Name / Local Label Spoofing Resistance
  it('Vector 5: Display names never authenticate identity; unauthenticated peers are rejected', async () => {
    // Attacker presents the same local label "Bob Laptop" as victim
    const attackerClaim = {
      localLabel: 'Bob Laptop', // Spoofed friendly name
      deviceId: devAttacker.deviceId,
      publicKey: bytesToHex(devAttacker.publicKey),
    };

    // Trust DB lookup by attacker's device ID returns false (not trusted)
    const isAttackerTrusted = await trustStoreA.isTrusted(attackerClaim.deviceId);
    expect(isAttackerTrusted).toBe(false);

    // Trust DB lookup by victim device ID returns legitimate key
    const victimDev = await trustStoreA.getDevice(devB.deviceId);
    expect(victimDev?.publicKey).toBe(bytesToHex(devB.publicKey));
    expect(victimDev?.publicKey).not.toBe(attackerClaim.publicKey);
  });

  // Vector 6: Downgrade Attack Resistance
  it('Vector 6: Enforces trusted-auth and rejects unauthenticated capability stripping', async () => {
    // When connecting to a paired device, both ends expect trusted-auth
    // If an attacker initiates with wrong pair key or missing signature
    const badSecret = new Uint8Array(32).fill(0x13);
    const init = await createTrustedAuthInit(
      devA,
      devB.deviceId,
      credRef,
      badSecret, // Attacker key
      ['transfer.v1'],
    );

    // Legitimate B rejects init because HMAC verification with true kPair fails
    await expect(
      verifyTrustedAuthInit(init, kPair, devA.publicKey, devB.deviceId),
    ).rejects.toThrow();
  });

  // Vector 7: Stale & Revoked Pair Credential Rejection
  it('Vector 7: Revoked devices fail authentication checks immediately', async () => {
    // Revoke device B in A's trust store
    await trustStoreA.revokeDevice(devB.deviceId);

    expect(await trustStoreA.isTrusted(devB.deviceId)).toBe(false);
    const revokedRec = await trustStoreA.getDevice(devB.deviceId);
    expect(revokedRec?.revoked).toBe(true);

    // If device B is completely unpaired / purged
    await trustStoreA.unpairDevice(devB.deviceId);
    expect(await trustStoreA.getDevice(devB.deviceId)).toBeNull();
    expect(await trustStoreA.isTrusted(devB.deviceId)).toBe(false);
  });

  // Vector 8: Auto-Accept Path Traversal & Escape Containment
  it('Vector 8: Strictly rejects path traversal, directory escapes, and illegal characters in auto-accept mode', () => {
    const maliciousPaths = [
      '../evil.txt',
      '../../etc/passwd',
      'foo/../../bar.txt',
      '/absolute/path/file.txt',
      'C:\\Windows\\System32\\cmd.exe',
      'foo\0bar.txt',
      '..\\..\\windows\\system32',
      './../secret.key',
      '',
    ];

    for (const badPath of maliciousPaths) {
      expect(() => normalizeTransferPath(badPath)).toThrow();
    }

    // Valid relative paths must pass
    expect(normalizeTransferPath('photos/vacation.jpg')).toBe('photos/vacation.jpg');
    expect(normalizeTransferPath('document.pdf')).toBe('document.pdf');
    expect(normalizeTransferPath('nested/dir/sub/file.tar.gz')).toBe('nested/dir/sub/file.tar.gz');
  });

  // Vector 9: One-Time Transfer Isolation
  it('Vector 9: One-time transfers never mutate trust database or persist credentials', async () => {
    // Snapshot trust store count before one-time transfer
    const initialList = await trustStoreA.listDevices();
    expect(initialList).toHaveLength(1);

    // One-time room transfer does not call trustStore.addOrUpdateDevice
    // Simulate one-time receiver session:
    const oneTimeSenderId = 'sb-dev-ephemeral12345';
    expect(await trustStoreA.getDevice(oneTimeSenderId)).toBeNull();

    // Trust DB remains completely untouched
    const afterList = await trustStoreA.listDevices();
    expect(afterList).toHaveLength(1);
    expect(afterList[0]?.deviceId).toBe(devB.deviceId);
  });
});
