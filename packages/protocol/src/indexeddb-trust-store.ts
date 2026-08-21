/**
 * Persistent TrustStore implementation over IndexedDB.
 *
 * Implements the TrustStore contract (getDevice, listDevices, addOrUpdateDevice,
 * revokeDevice, unpairDevice, isTrusted, updateLastSeen, updatePolicy, clear)
 * backed by the browser's IndexedDB storage.
 */

import {
  type TrustPolicy,
  type TrustRecord,
  type TrustStore,
  validateTrustRecord,
} from './trust-store.js';

export const TRUST_DB_NAME = 'sendbeam-trust';
export const TRUST_DEVICES_STORE = 'trusted_devices';

export class IndexedDBTrustStore implements TrustStore {
  private readonly customIdb: IDBFactory | undefined;
  private dbPromise: Promise<IDBDatabase> | undefined;

  constructor(customIdb?: IDBFactory) {
    this.customIdb = customIdb;
  }

  private getDb(): Promise<IDBDatabase> {
    if (!this.dbPromise) {
      this.dbPromise = new Promise((resolve, reject) => {
        const idb = this.customIdb ?? (globalThis as { indexedDB?: IDBFactory }).indexedDB;
        if (!idb) {
          reject(new Error('IndexedDB is unavailable in this environment'));
          return;
        }

        const req = idb.open(TRUST_DB_NAME, 1);
        req.onupgradeneeded = () => {
          const db = req.result;
          if (!db.objectStoreNames.contains(TRUST_DEVICES_STORE)) {
            db.createObjectStore(TRUST_DEVICES_STORE, { keyPath: 'deviceId' });
          }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error ?? new Error('failed to open trust database'));
      });
    }
    return this.dbPromise;
  }

  async getDevice(deviceId: string): Promise<TrustRecord | null> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([TRUST_DEVICES_STORE], 'readonly');
      const req = tx.objectStore(TRUST_DEVICES_STORE).get(deviceId);
      req.onsuccess = () => {
        if (!req.result) {
          resolve(null);
        } else {
          resolve(req.result as TrustRecord);
        }
      };
      req.onerror = () => reject(req.error ?? new Error(`getDevice ${deviceId} failed`));
    });
  }

  async listDevices(): Promise<TrustRecord[]> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([TRUST_DEVICES_STORE], 'readonly');
      const req = tx.objectStore(TRUST_DEVICES_STORE).getAll();
      req.onsuccess = () => {
        resolve((req.result as TrustRecord[]) || []);
      };
      req.onerror = () => reject(req.error ?? new Error('listDevices failed'));
    });
  }

  async addOrUpdateDevice(record: TrustRecord): Promise<void> {
    await validateTrustRecord(record);
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([TRUST_DEVICES_STORE], 'readwrite');
      tx.objectStore(TRUST_DEVICES_STORE).put(JSON.parse(JSON.stringify(record)));
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error(`put device ${record.deviceId} failed`));
      tx.onabort = () => reject(new Error('addOrUpdateDevice transaction aborted'));
    });
  }

  async revokeDevice(deviceId: string): Promise<void> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([TRUST_DEVICES_STORE], 'readwrite');
      const store = tx.objectStore(TRUST_DEVICES_STORE);
      const req = store.get(deviceId);
      req.onsuccess = () => {
        const rec = req.result as TrustRecord | undefined;
        if (!rec) {
          tx.abort();
          reject(new Error(`device not found: ${deviceId}`));
          return;
        }
        rec.revoked = true;
        rec.revokedAt = new Date().toISOString();
        store.put(rec);
      };
      req.onerror = () => {
        tx.abort();
        reject(req.error ?? new Error(`revokeDevice ${deviceId} read failed`));
      };
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error(`revokeDevice ${deviceId} failed`));
    });
  }

  async unpairDevice(deviceId: string): Promise<void> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([TRUST_DEVICES_STORE], 'readwrite');
      tx.objectStore(TRUST_DEVICES_STORE).delete(deviceId);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error(`unpairDevice ${deviceId} failed`));
    });
  }

  async isTrusted(deviceId: string): Promise<boolean> {
    const dev = await this.getDevice(deviceId);
    return dev !== null && !dev.revoked;
  }

  async updateLastSeen(deviceId: string, seenAt?: string): Promise<void> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([TRUST_DEVICES_STORE], 'readwrite');
      const store = tx.objectStore(TRUST_DEVICES_STORE);
      const req = store.get(deviceId);
      req.onsuccess = () => {
        const rec = req.result as TrustRecord | undefined;
        if (!rec) {
          tx.abort();
          reject(new Error(`device not found: ${deviceId}`));
          return;
        }
        rec.lastSeenAt = seenAt || new Date().toISOString();
        store.put(rec);
      };
      req.onerror = () => {
        tx.abort();
        reject(req.error ?? new Error(`updateLastSeen ${deviceId} read failed`));
      };
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error(`updateLastSeen ${deviceId} failed`));
    });
  }

  async updatePolicy(deviceId: string, policy: TrustPolicy): Promise<void> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([TRUST_DEVICES_STORE], 'readwrite');
      const store = tx.objectStore(TRUST_DEVICES_STORE);
      const req = store.get(deviceId);
      req.onsuccess = async () => {
        const rec = req.result as TrustRecord | undefined;
        if (!rec) {
          tx.abort();
          reject(new Error(`device not found: ${deviceId}`));
          return;
        }
        rec.policy = JSON.parse(JSON.stringify(policy)) as TrustPolicy;
        try {
          await validateTrustRecord(rec);
          store.put(rec);
        } catch (valErr) {
          tx.abort();
          reject(valErr);
        }
      };
      req.onerror = () => {
        tx.abort();
        reject(req.error ?? new Error(`updatePolicy ${deviceId} read failed`));
      };
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error(`updatePolicy ${deviceId} failed`));
    });
  }

  async clear(): Promise<void> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([TRUST_DEVICES_STORE], 'readwrite');
      tx.objectStore(TRUST_DEVICES_STORE).clear();
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error('clear trust store failed'));
    });
  }
}
