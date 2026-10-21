// Base64url and hashing helpers. Runs unchanged in browsers and Node 20+ (global WebCrypto, btoa/atob).

export const te = new TextEncoder();
export const td = new TextDecoder();

const toBytes = (x) =>
  typeof x === "string" ? te.encode(x)
    : x instanceof Uint8Array ? x
      : ArrayBuffer.isView(x) ? new Uint8Array(x.buffer, x.byteOffset, x.byteLength)
        : new Uint8Array(x);

export function b64uEncode(x) {
  let s = "";
  for (const b of toBytes(x)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64uDecode(str) {
  if (!/^[A-Za-z0-9_-]*$/.test(str)) throw new Error("Not base64url");
  let s = str.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export const b64uJson = (obj) => b64uEncode(JSON.stringify(obj));
export const parseB64uJson = (str) => JSON.parse(td.decode(b64uDecode(str)));

export const randomB64u = (bytes = 32) => b64uEncode(crypto.getRandomValues(new Uint8Array(bytes)));

// SHA-256 over the ASCII bytes of a string, base64url-encoded (SD-JWT digests, sd_hash).
export async function sha256B64u(str) {
  return b64uEncode(await crypto.subtle.digest("SHA-256", te.encode(str)));
}
