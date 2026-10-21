// Minimal async key-value store with per-entry expiry. The servers only use this interface, so the
// same handler code runs on Node (memoryStore) and on Cloudflare (Durable Object storage, see deploy/).

export function memoryStore() {
  const map = new Map();
  return {
    async get(key) {
      const e = map.get(key);
      if (!e) return undefined;
      if (e.exp && e.exp < Date.now()) { map.delete(key); return undefined; }
      return structuredClone(e.v);
    },
    async put(key, value, ttlMs = 0) { map.set(key, { v: structuredClone(value), exp: ttlMs ? Date.now() + ttlMs : 0 }); },
    async delete(key) { map.delete(key); },
  };
}

// Read-and-delete, for single-use values (codes, tokens, nonces).
export async function take(store, key) {
  const v = await store.get(key);
  if (v !== undefined) await store.delete(key);
  return v;
}
