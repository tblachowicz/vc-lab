// lib/kv.js store interface on Durable Object storage, with an hourly alarm that deletes expired entries.
const SWEEP_EVERY = 3600 * 1000;

export function doStore(storage) {
  return {
    async get(key) {
      const e = await storage.get(key);
      if (!e) return undefined;
      if (e.exp && e.exp < Date.now()) { await storage.delete(key); return undefined; }
      return e.v;
    },
    async put(key, value, ttlMs = 0) {
      await storage.put(key, { v: value, exp: ttlMs ? Date.now() + ttlMs : 0 });
      if (ttlMs && !(await storage.getAlarm())) await storage.setAlarm(Date.now() + SWEEP_EVERY);
    },
    delete: (key) => storage.delete(key),
  };
}

// Call from the Durable Object's alarm() handler.
export async function sweep(storage) {
  const now = Date.now();
  let pending = false;
  for (const [key, e] of await storage.list()) {
    if (!e?.exp) continue;
    if (e.exp < now) await storage.delete(key);
    else pending = true;
  }
  if (pending) await storage.setAlarm(now + SWEEP_EVERY);
}
