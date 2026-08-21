import { describe, it, expect, beforeEach } from 'vitest';
import {
  listTrustedDevices,
  renameTrustedDevice,
  updateTrustedDevicePolicy,
  unpairTrustedDevice,
} from './devices.js';
import {
  generateDeviceIdentity,
  deriveDeviceId,
  formatFingerprint,
  bytesToHex,
} from '@sendbeam/protocol';

describe('Trusted Devices Frontend Bridge', () => {
  beforeEach(() => {
    // Ensure clean window mock
    if (typeof window !== 'undefined') {
      delete (window as unknown as Record<string, unknown>).go;
    }
  });

  it('lists fallback in-memory devices when not running in Wails', async () => {
    const list = await listTrustedDevices();
    expect(Array.isArray(list)).toBe(true);
  });

  it('interacts with mock desktop Wails DeviceService when available', async () => {
    const kp = await generateDeviceIdentity();
    const devId = await deriveDeviceId(kp.publicKey);
    const pubHex = bytesToHex(kp.publicKey);
    const fp = formatFingerprint(kp.publicKey);

    const mockDevices = [
      {
        deviceId: devId,
        localLabel: 'Work MacBook',
        fingerprint: fp,
        publicKey: pubHex,
        status: 'lan_direct' as const,
        revoked: false,
        lastSeenAt: new Date().toISOString(),
        firstSeenAt: new Date().toISOString(),
        capabilities: ['transfer.v1', 'lan_direct'],
        policy: { autoAccept: true, autoAcceptDestDir: '/home/user/Downloads' },
      },
    ];

    let renameCalledWith: [string, string] | null = null;
    let policyCalledWith: unknown = null;
    let unpairCalledWith: [string, boolean] | null = null;

    globalThis.window = {
      go: {
        engine: {
          DeviceService: {
            ListTrustedDevices: async () => mockDevices,
            RenameDevice: async (id: string, name: string) => {
              renameCalledWith = [id, name];
            },
            UpdateDevicePolicy: async (id: string, pol: unknown) => {
              policyCalledWith = pol;
            },
            UnpairDevice: async (id: string, purge: boolean) => {
              unpairCalledWith = [id, purge];
            },
            PairDevice: async () => mockDevices[0]!,
          },
        },
      },
    } as unknown as Window & typeof globalThis;

    const devs = await listTrustedDevices();
    expect(devs).toHaveLength(1);
    expect(devs[0]!.localLabel).toBe('Work MacBook');
    expect(devs[0]!.status).toBe('lan_direct');
    expect(devs[0]!.policy.autoAccept).toBe(true);

    await renameTrustedDevice(devId, 'Work Laptop Pro');
    expect(renameCalledWith).toEqual([devId, 'Work Laptop Pro']);

    await updateTrustedDevicePolicy(devId, { autoAccept: false });
    expect(policyCalledWith).toEqual({ autoAccept: false });

    await unpairTrustedDevice(devId, true);
    expect(unpairCalledWith).toEqual([devId, true]);
  });
});
