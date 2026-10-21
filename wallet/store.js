// Credential store in IndexedDB. Holder keys are stored as non-extractable CryptoKeys:
// the browser can sign with them, but script can never read the private key out.
const DB = "vc-lab-wallet";
const STORE = "credentials";

function open() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE, { keyPath: "id" });
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function tx(mode, fn) {
  const db = await open();
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE, mode);
    const result = fn(t.objectStore(STORE));
    t.oncomplete = () => { db.close(); resolve(result.result ?? result); };
    t.onerror = () => { db.close(); reject(t.error); };
  });
}

export const all = async () => (await tx("readonly", (s) => s.getAll())).sort((a, b) => b.issuedAt - a.issuedAt);
export const put = (record) => tx("readwrite", (s) => s.put(record));
export const remove = (id) => tx("readwrite", (s) => s.delete(id));

// Ask the browser not to evict the wallet's data under storage pressure (Safari may still clear it).
export async function persist() {
  try { return await navigator.storage?.persist?.(); } catch { return false; }
}
