import {
  type TrustPolicy,
  type TrustRecord,
  IndexedDBTrustStore,
  IndexedDBSecretStore,
  MemoryTrustStore,
  formatFingerprint,
  hexToBytes,
  isPersistentTrustSupported,
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

export { isPersistentTrustSupported };

export function isDesktopApp(): boolean {
  return typeof window !== 'undefined' && !!window.go?.engine?.DeviceService;
}

// Browser storage instances
let browserTrustStore: IndexedDBTrustStore | MemoryTrustStore | null = null;
let browserSecretStore: IndexedDBSecretStore | null = null;

function getBrowserStores() {
  if (!browserTrustStore) {
    if (typeof indexedDB !== 'undefined') {
      browserTrustStore = new IndexedDBTrustStore();
      browserSecretStore = new IndexedDBSecretStore();
    } else {
      browserTrustStore = new MemoryTrustStore();
    }
  }
  return { trustStore: browserTrustStore, secretStore: browserSecretStore };
}

export async function listTrustedDevices(): Promise<TrustedDeviceUI[]> {
  if (isDesktopApp() && window.go?.engine?.DeviceService) {
    return window.go.engine.DeviceService.ListTrustedDevices();
  }

  const { trustStore } = getBrowserStores();
  const records = await trustStore.listDevices();
  const now = Date.now();

  return records.map((r: TrustRecord) => {
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

  const { trustStore } = getBrowserStores();
  const rec = await trustStore.getDevice(deviceId);
  if (!rec) throw new Error('device not found');
  rec.localLabel = newLabel.trim();
  await trustStore.addOrUpdateDevice(rec);
}

export async function updateTrustedDevicePolicy(
  deviceId: string,
  policy: TrustPolicy,
): Promise<void> {
  if (isDesktopApp() && window.go?.engine?.DeviceService) {
    return window.go.engine.DeviceService.UpdateDevicePolicy(deviceId, policy);
  }

  const { trustStore } = getBrowserStores();
  await trustStore.updatePolicy(deviceId, policy);
}

export async function unpairTrustedDevice(deviceId: string, purge: boolean): Promise<void> {
  if (isDesktopApp() && window.go?.engine?.DeviceService) {
    return window.go.engine.DeviceService.UnpairDevice(deviceId, purge);
  }

  const { trustStore, secretStore } = getBrowserStores();
  if (purge) {
    await trustStore.unpairDevice(deviceId);
    if (secretStore) {
      await secretStore.deletePairSecret(deviceId);
    }
  } else {
    await trustStore.revokeDevice(deviceId);
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

  const supported = await isPersistentTrustSupported();
  if (!supported) {
    throw new Error(
      'Persistent device pairing requires WebCrypto and IndexedDB storage, which are unavailable in this context.',
    );
  }

  throw new Error(
    'Interactive browser pairing requires active signaling. Use SendBeam desktop or CLI for background mesh connections.',
  );
}
