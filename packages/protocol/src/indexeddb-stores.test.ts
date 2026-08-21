import { describe, it, expect, beforeEach } from 'vitest';
import { IndexedDBTrustStore } from './indexeddb-trust-store.js';
import { IndexedDBSecretStore } from './indexeddb-secret-store.js';
import { getOrCreateBrowserIdentity } from './browser-identity.js';
import { isPersistentTrustSupported } from './capability.js';
import { generateDeviceIdentity, deriveDeviceId, bytesToHex } from './index.js';
import type { TrustRecord } from './trust-store.js';

// Minimal in-memory IndexedDB mock for unit testing
class MemoryObjectStore {
  constructor(public data = new Map<string, unknown>()) {}
  get(key: string) {
    const req: Record<string, unknown> = {
      result: this.data.get(key),
      onsuccess: null,
      onerror: null,
    };
    queueMicrotask(() => (req.onsuccess as ((ev?: unknown) => void) | null)?.());
    return req;
  }
  getAll() {
    const req: Record<string, unknown> = {
      result: Array.from(this.data.values()),
      onsuccess: null,
      onerror: null,
    };
    queueMicrotask(() => (req.onsuccess as ((ev?: unknown) => void) | null)?.());
    return req;
  }
  put(value: unknown, key?: string) {
    const k = key || (value as { deviceId?: string })?.deviceId || 'default';
    this.data.set(k, value);
  }
  delete(key: string) {
    this.data.delete(key);
  }
  clear() {
    this.data.clear();
  }
}

class MemoryDatabase {
  stores = new Map<string, MemoryObjectStore>();
  objectStoreNames = {
    contains: (name: string) => this.stores.has(name),
  };
  createObjectStore(name: string) {
    const store = new MemoryObjectStore();
    this.stores.set(name, store);
    return store;
  }
  transaction(storeNames: string[], _mode: string) {
    void _mode;
    const firstStore = this.stores.get(storeNames[0]!) || this.createObjectStore(storeNames[0]!);
    const tx: Record<string, unknown> = {
      objectStore: (_name: string) => {
        void _name;
        return firstStore;
      },
      oncomplete: null,
      onerror: null,
      abort: () => {},
    };
    queueMicrotask(() => (tx.oncomplete as ((ev?: unknown) => void) | null)?.());
    return tx;
  }
  close() {}
}

class MemoryIDBFactory {
  databases = new Map<string, MemoryDatabase>();
  open(name: string, _version?: number) {
    void _version;
    let db = this.databases.get(name);
    let isNew = false;
    if (!db) {
      db = new MemoryDatabase();
      this.databases.set(name, db);
      isNew = true;
    }
    const req: Record<string, unknown> = {
      result: db,
      onsuccess: null,
      onerror: null,
      onupgradeneeded: null,
    };
    queueMicrotask(() => {
      if (isNew) {
        (req.onupgradeneeded as ((ev?: unknown) => void) | null)?.();
      }
      (req.onsuccess as ((ev?: unknown) => void) | null)?.();
    });
    return req;
  }
  deleteDatabase(name: string) {
    this.databases.delete(name);
    const req: Record<string, unknown> = { onsuccess: null, onerror: null };
    queueMicrotask(() => (req.onsuccess as ((ev?: unknown) => void) | null)?.());
    return req;
  }
}

describe('IndexedDB Trust & Secret Stores and Capability Probing', () => {
  let fakeIdb: MemoryIDBFactory;

  beforeEach(() => {
    fakeIdb = new MemoryIDBFactory();
  });

  it('probes persistent trust capability accurately', async () => {
    const supported = await isPersistentTrustSupported(fakeIdb);
    expect(supported).toBe(true);

    // Unsupported when idb is null
    const unsupported = await isPersistentTrustSupported(null);
    expect(unsupported).toBe(false);
  });

  it('stores, queries, updates, revokes, and clears trust records in IndexedDB', async () => {
    const trustStore = new IndexedDBTrustStore(fakeIdb as unknown as IDBFactory);

    const kp = await generateDeviceIdentity();
    const devId = await deriveDeviceId(kp.publicKey);
    const pubHex = bytesToHex(kp.publicKey);

    const record: TrustRecord = {
      deviceId: devId,
      publicKey: pubHex,
      localLabel: 'Work MacBook Pro',
      pairCredentialRef: 'cred-12345',
      capabilities: ['transfer.v1', 'lan_direct'],
      firstSeenAt: new Date().toISOString(),
      lastSeenAt: new Date().toISOString(),
      revoked: false,
      policy: { autoAccept: false },
    };

    await trustStore.addOrUpdateDevice(record);

    const retrieved = await trustStore.getDevice(devId);
    expect(retrieved).not.toBeNull();
    expect(retrieved?.localLabel).toBe('Work MacBook Pro');
    expect(await trustStore.isTrusted(devId)).toBe(true);

    // Update policy
    await trustStore.updatePolicy(devId, { autoAccept: true, maxFileSizeBytes: 5000 });
    const updated = await trustStore.getDevice(devId);
    expect(updated?.policy.autoAccept).toBe(true);

    // Revoke device
    await trustStore.revokeDevice(devId);
    expect(await trustStore.isTrusted(devId)).toBe(false);
    const revokedRec = await trustStore.getDevice(devId);
    expect(revokedRec?.revoked).toBe(true);

    // List devices
    const list = await trustStore.listDevices();
    expect(list).toHaveLength(1);

    // Unpair device
    await trustStore.unpairDevice(devId);
    expect(await trustStore.getDevice(devId)).toBeNull();

    // Clear store
    await trustStore.addOrUpdateDevice(record);
    await trustStore.clear();
    expect(await trustStore.listDevices()).toHaveLength(0);
  });

  it('stores, retrieves, deletes, and clears pair secrets in IndexedDB', async () => {
    const secretStore = new IndexedDBSecretStore(fakeIdb as unknown as IDBFactory);

    const kp = await generateDeviceIdentity();
    const devId = await deriveDeviceId(kp.publicKey);
    const testSecret = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

    await secretStore.setPairSecret(devId, testSecret);
    const resolved = await secretStore.getPairSecret(devId);
    expect(resolved).toEqual(testSecret);

    const viaResolver = await secretStore.resolvePairSecret(devId, 'ref-1');
    expect(viaResolver).toEqual(testSecret);

    await secretStore.deletePairSecret(devId);
    expect(await secretStore.getPairSecret(devId)).toBeNull();

    await secretStore.setPairSecret(devId, testSecret);
    await secretStore.clear();
    expect(await secretStore.getPairSecret(devId)).toBeNull();
  });

  it('generates and persists browser node identity deterministically', async () => {
    const id1 = await getOrCreateBrowserIdentity(fakeIdb as unknown as IDBFactory);
    expect(id1.deviceId.startsWith('sb-dev-')).toBe(true);

    // Second call should return the exact same identity
    const id2 = await getOrCreateBrowserIdentity(fakeIdb as unknown as IDBFactory);
    expect(id2.deviceId).toBe(id1.deviceId);
    expect(bytesToHex(id2.publicKey)).toBe(bytesToHex(id1.publicKey));
    expect(bytesToHex(id2.privateKey)).toBe(bytesToHex(id1.privateKey));
  });
});
