/**
 * Browser device identity management backed by IndexedDB.
 *
 * Automatically generates and persists an Ed25519 cryptographic DeviceIdentity
 * for the browser origin. Clearing site data removes the local identity seed.
 */

import { bytesToHex, hexToBytes } from './bytes.js';
import {
  type DeviceIdentity,
  createDeviceIdentityFromSeed,
  generateDeviceIdentity,
} from './identity.js';

export const IDENTITY_DB_NAME = 'sendbeam-identity';
export const IDENTITY_STORE_NAME = 'node_identity';
const PRIMARY_IDENTITY_KEY = 'primary_device_identity';

export async function getOrCreateBrowserIdentity(customIdb?: IDBFactory): Promise<DeviceIdentity> {
  const idb = customIdb ?? (globalThis as { indexedDB?: IDBFactory }).indexedDB;
  if (!idb) {
    // If IndexedDB is not available, generate ephemeral in-memory identity
    return generateDeviceIdentity();
  }

  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const req = idb.open(IDENTITY_DB_NAME, 1);
    req.onupgradeneeded = () => {
      const dbInstance = req.result;
      if (!dbInstance.objectStoreNames.contains(IDENTITY_STORE_NAME)) {
        dbInstance.createObjectStore(IDENTITY_STORE_NAME);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('failed to open identity db'));
  });

  // Check if identity seed exists
  const existingSeedHex = await new Promise<string | undefined>((resolve, reject) => {
    const tx = db.transaction([IDENTITY_STORE_NAME], 'readonly');
    const req = tx.objectStore(IDENTITY_STORE_NAME).get(PRIMARY_IDENTITY_KEY);
    req.onsuccess = () => resolve(req.result as string | undefined);
    req.onerror = () => reject(req.error ?? new Error('read identity failed'));
  });

  if (existingSeedHex && existingSeedHex.length === 64) {
    try {
      const seed = hexToBytes(existingSeedHex);
      return await createDeviceIdentityFromSeed(seed);
    } catch {
      // In case of corruption, generate fresh below
    }
  }

  // Generate fresh identity
  const fresh = await generateDeviceIdentity();
  const seedHex = bytesToHex(fresh.privateKey);

  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction([IDENTITY_STORE_NAME], 'readwrite');
    tx.objectStore(IDENTITY_STORE_NAME).put(seedHex, PRIMARY_IDENTITY_KEY);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error('save identity failed'));
  });

  return fresh;
}
