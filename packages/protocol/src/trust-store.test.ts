import { describe, expect, it } from 'vitest';
import { bytesToHex } from './bytes.js';
import { generateDeviceIdentity } from './identity.js';
import {
  CAP_AUTO_ACCEPT,
  CAP_LAN_DIRECT,
  CAP_TRANSFER_V1,
  CAP_TRANSFER_V2,
  MemoryTrustStore,
  TrustRecord,
} from './trust-store.js';

describe('trust store & policy', () => {
  it('manages device trust lifecycle in memory store', async () => {
    const store = new MemoryTrustStore();
    const id = await generateDeviceIdentity();

    const record: TrustRecord = {
      deviceId: id.deviceId,
      publicKey: bytesToHex(id.publicKey),
      localLabel: 'MacBook Air',
      pairCredentialRef: 'cred-abc-123',
      capabilities: [CAP_TRANSFER_V1, CAP_TRANSFER_V2, CAP_LAN_DIRECT, CAP_AUTO_ACCEPT],
      firstSeenAt: new Date().toISOString(),
      lastSeenAt: new Date().toISOString(),
      revoked: false,
      policy: {
        autoAccept: true,
        autoAcceptDestDir: '/home/user/Downloads',
        maxFileSizeBytes: 1024 * 1024 * 1024,
      },
    };

    expect(await store.isTrusted(id.deviceId)).toBe(false);

    await store.addOrUpdateDevice(record);
    expect(await store.isTrusted(id.deviceId)).toBe(true);

    const fetched = await store.getDevice(id.deviceId);
    expect(fetched).not.toBeNull();
    expect(fetched?.localLabel).toBe('MacBook Air');
    expect(fetched?.policy.autoAccept).toBe(true);

    const list = await store.listDevices();
    expect(list.length).toBe(1);
    expect(list[0]?.deviceId).toBe(id.deviceId);

    // Update policy
    await store.updatePolicy(id.deviceId, {
      autoAccept: false,
      maxFileSizeBytes: 500 * 1024 * 1024,
    });
    const updated = await store.getDevice(id.deviceId);
    expect(updated?.policy.autoAccept).toBe(false);

    // Revocation
    await store.revokeDevice(id.deviceId);
    expect(await store.isTrusted(id.deviceId)).toBe(false);
    const revokedRecord = await store.getDevice(id.deviceId);
    expect(revokedRecord?.revoked).toBe(true);
    expect(revokedRecord?.revokedAt).toBeDefined();

    // Unpair (deletion)
    await store.unpairDevice(id.deviceId);
    expect(await store.getDevice(id.deviceId)).toBeNull();
    expect((await store.listDevices()).length).toBe(0);
  });

  it('rejects invalid trust records', async () => {
    const store = new MemoryTrustStore();
    const id = await generateDeviceIdentity();
    const otherId = await generateDeviceIdentity();

    // Mismatched device ID and public key
    const badRecord: TrustRecord = {
      deviceId: id.deviceId,
      publicKey: bytesToHex(otherId.publicKey),
      localLabel: 'Bad Peer',
      pairCredentialRef: 'cred-bad',
      capabilities: [],
      firstSeenAt: new Date().toISOString(),
      lastSeenAt: new Date().toISOString(),
      revoked: false,
      policy: {
        autoAccept: false,
      },
    };

    await expect(store.addOrUpdateDevice(badRecord)).rejects.toThrow();
  });
});
