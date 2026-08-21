/**
 * Browser secret storage for trusted pairing secrets (k_pair) backed by IndexedDB.
 *
 * Stores raw pair-specific secret keys (k_pair) encrypted / partitioned under
 * the browser origin's IndexedDB. Clearing site data predictably revokes all
 * stored pair credentials.
 */

import { bytesToHex, hexToBytes } from './bytes.js';

export const SECRETS_DB_NAME = 'sendbeam-secrets';
export const SECRETS_STORE_NAME = 'pair_secrets';

export interface SecretResolver {
  getPairSecret(deviceId: string): Promise<Uint8Array | null>;
  resolvePairSecret(deviceId: string, credentialRef: string): Promise<Uint8Array | null>;
}

export class IndexedDBSecretStore implements SecretResolver {
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

        const req = idb.open(SECRETS_DB_NAME, 1);
        req.onupgradeneeded = () => {
          const db = req.result;
          if (!db.objectStoreNames.contains(SECRETS_STORE_NAME)) {
            db.createObjectStore(SECRETS_STORE_NAME);
          }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error ?? new Error('failed to open secrets database'));
      });
    }
    return this.dbPromise;
  }

  async getPairSecret(deviceId: string): Promise<Uint8Array | null> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([SECRETS_STORE_NAME], 'readonly');
      const req = tx.objectStore(SECRETS_STORE_NAME).get(deviceId);
      req.onsuccess = () => {
        const val = req.result as string | undefined;
        if (!val) {
          resolve(null);
        } else {
          try {
            resolve(hexToBytes(val));
          } catch {
            resolve(null);
          }
        }
      };
      req.onerror = () => reject(req.error ?? new Error(`getPairSecret for ${deviceId} failed`));
    });
  }

  async setPairSecret(deviceId: string, secret: Uint8Array): Promise<void> {
    const db = await this.getDb();
    const hex = bytesToHex(secret);
    return new Promise((resolve, reject) => {
      const tx = db.transaction([SECRETS_STORE_NAME], 'readwrite');
      tx.objectStore(SECRETS_STORE_NAME).put(hex, deviceIDKey(deviceId));
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error(`setPairSecret for ${deviceId} failed`));
    });
  }

  async deletePairSecret(deviceId: string): Promise<void> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([SECRETS_STORE_NAME], 'readwrite');
      tx.objectStore(SECRETS_STORE_NAME).delete(deviceIDKey(deviceId));
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error(`deletePairSecret for ${deviceId} failed`));
    });
  }

  async resolvePairSecret(deviceId: string, _credentialRef: string): Promise<Uint8Array | null> {
    void _credentialRef;
    return this.getPairSecret(deviceId);
  }

  async clear(): Promise<void> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([SECRETS_STORE_NAME], 'readwrite');
      tx.objectStore(SECRETS_STORE_NAME).clear();
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error('clear secrets store failed'));
    });
  }
}

function deviceIDKey(deviceId: string): string {
  return deviceId.trim();
}
