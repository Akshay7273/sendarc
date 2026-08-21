import {
  type TrustPolicy,
  MemoryTrustStore,
  formatFingerprint,
  hexToBytes,
} from '@sendbeam/protocol';
import type { TrustedDeviceUI } from './types.js';

declare global {
  interface Window {
    go?: {
      engine?: {
        DeviceService?: {
          ListTrustedDevices(): Promise<TrustedDeviceUI[]>;
          RenameDevice(deviceId: string, newLabel: string): Promise<void>;
          UpdateDevicePolicy(deviceId: string, policy: TrustPolicy): Promise<void>;
          UnpairDevice(deviceId: string, purge: boolean): Promise<void>;
          PairDevice(
            server: string,
            code: string,
            name: string,
            autoAccept: boolean,
            dest: string,
          ): Promise<TrustedDeviceUI>;
        };
      };
    };
    runtime?: {
      EventsOn(eventName: string, callback: (data: unknown) => void): () => void;
    };
  }
}

// Fallback in-memory trust store for browser and test environments
const fallbackStore = new MemoryTrustStore();

export function isDesktopApp(): boolean {
  return typeof window !== 'undefined' && !!window.go?.engine?.DeviceService;
}

export async function listTrustedDevices(): Promise<TrustedDeviceUI[]> {
  if (isDesktopApp() && window.go?.engine?.DeviceService) {
    return window.go.engine.DeviceService.ListTrustedDevices();
  }

  const records = await fallbackStore.listDevices();
  const now = Date.now();

  return records.map((r) => {
    let status: TrustedDeviceUI['status'] = 'offline';
    if (r.revoked) {
      status = 'revoked';
    } else {
      const seenTime = r.lastSeenAt ? new Date(r.lastSeenAt).getTime() : 0;
      if (now - seenTime < 15 * 60 * 1000) {
        status = 'online';
      }
    }

    let fp = '';
    try {
      fp = formatFingerprint(hexToBytes(r.publicKey));
    } catch {
      fp = r.deviceId.slice(0, 16);
    }

    return {
      deviceId: r.deviceId,
      localLabel: r.localLabel,
      fingerprint: fp,
      publicKey: r.publicKey,
      status,
      revoked: r.revoked,
      lastSeenAt: r.lastSeenAt || 'never',
      firstSeenAt: r.firstSeenAt,
      capabilities: r.capabilities || [],
      policy: r.policy || { autoAccept: false },
    };
  });
}

export async function renameTrustedDevice(deviceId: string, newLabel: string): Promise<void> {
  if (isDesktopApp() && window.go?.engine?.DeviceService) {
    return window.go.engine.DeviceService.RenameDevice(deviceId, newLabel);
  }

  const rec = await fallbackStore.getDevice(deviceId);
  if (!rec) throw new Error('device not found');
  rec.localLabel = newLabel.trim();
  await fallbackStore.addOrUpdateDevice(rec);
}

export async function updateTrustedDevicePolicy(
  deviceId: string,
  policy: TrustPolicy,
): Promise<void> {
  if (isDesktopApp() && window.go?.engine?.DeviceService) {
    return window.go.engine.DeviceService.UpdateDevicePolicy(deviceId, policy);
  }

  await fallbackStore.updatePolicy(deviceId, policy);
}

export async function unpairTrustedDevice(deviceId: string, purge: boolean): Promise<void> {
  if (isDesktopApp() && window.go?.engine?.DeviceService) {
    return window.go.engine.DeviceService.UnpairDevice(deviceId, purge);
  }

  if (purge) {
    await fallbackStore.unpairDevice(deviceId);
  } else {
    await fallbackStore.revokeDevice(deviceId);
  }
}

export async function pairTrustedDevice(
  server: string,
  code: string,
  name: string,
  autoAccept: boolean,
  dest: string,
): Promise<TrustedDeviceUI> {
  if (isDesktopApp() && window.go?.engine?.DeviceService) {
    return window.go.engine.DeviceService.PairDevice(server, code, name, autoAccept, dest);
  }

  throw new Error('Device pairing ceremony is currently enabled in native desktop mode.');
}
