/**
 * Browser capability detection and persistent trust safety gating.
 *
 * Implements strict capability probing for persistent device trust. Probes for:
 * - Functional WebCrypto subtle API (ed25519 or key derivation / HMAC)
 * - Functional IndexedDB storage
 *
 * Returns false cleanly in insecure or restricted environments (e.g. non-HTTPS,
 * disabled storage, private browsing without IDB). Never fakes persistence via
 * unsafe plaintext localStorage or insecure cookies.
 */

export async function isPersistentTrustSupported(customIdb?: unknown): Promise<boolean> {
  // 1. Check WebCrypto subtle availability
  const subtle = globalThis.crypto?.subtle;
  if (!subtle || typeof subtle.digest !== 'function' || typeof subtle.importKey !== 'function') {
    return false;
  }

  // 2. Check IndexedDB availability
  const idb = (customIdb ?? (globalThis as { indexedDB?: IDBFactory }).indexedDB) as
    IDBFactory | undefined;
  if (!idb || typeof idb.open !== 'function') {
    return false;
  }

  // 3. Probe IndexedDB read/write in a transient probe database
  const probeDbName = 'sendbeam-probe-storage';
  try {
    const isWorking = await new Promise<boolean>((resolve) => {
      const timeout = setTimeout(() => resolve(false), 1000);
      try {
        const req = idb.open(probeDbName, 1);
        req.onupgradeneeded = () => {
          try {
            req.result.createObjectStore('probe');
          } catch {
            // Ignore upgrade errors handled by onerror
          }
        };
        req.onsuccess = () => {
          clearTimeout(timeout);
          const db = req.result;
          try {
            const tx = db.transaction(['probe'], 'readwrite');
            tx.objectStore('probe').put('probe-val', 'probe-key');
            tx.oncomplete = () => {
              db.close();
              try {
                idb.deleteDatabase(probeDbName);
              } catch {
                // Best effort cleanup
              }
              resolve(true);
            };
            tx.onerror = () => {
              db.close();
              resolve(false);
            };
          } catch {
            db.close();
            resolve(false);
          }
        };
        req.onerror = () => {
          clearTimeout(timeout);
          resolve(false);
        };
      } catch {
        clearTimeout(timeout);
        resolve(false);
      }
    });

    return isWorking;
  } catch {
    return false;
  }
}
