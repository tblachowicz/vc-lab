// Compact JWS with ES256 on WebCrypto. WebCrypto's ECDSA output is already the raw r‖s form JWS uses.
import { b64uDecode, b64uEncode, b64uJson, parseB64uJson, sha256B64u, te } from "./b64.js";

const ES256 = { name: "ECDSA", namedCurve: "P-256" };
const SIGN = { name: "ECDSA", hash: "SHA-256" };

// The private key stays non-extractable unless asked; WebCrypto always lets the public key be exported.
export function generateKeyPair({ extractable = false } = {}) {
  return crypto.subtle.generateKey(ES256, extractable, ["sign", "verify"]);
}

export async function exportPublicJwk(publicKey) {
  const { kty, crv, x, y } = await crypto.subtle.exportKey("jwk", publicKey);
  return { kty, crv, x, y };
}

export function importPublicJwk(jwk) {
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.x || !jwk.y || jwk.d) throw new Error("Expected a public P-256 JWK");
  return crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, ES256, true, ["verify"]);
}

export function importPrivateJwk(jwk) {
  return crypto.subtle.importKey("jwk", jwk, ES256, false, ["sign"]);
}

// RFC 7638 thumbprint, used as the issuer's `kid`.
export function jwkThumbprint({ crv, kty, x, y }) {
  return sha256B64u(JSON.stringify({ crv, kty, x, y }));
}

export async function signJwt(header, payload, privateKey) {
  const input = `${b64uJson({ ...header, alg: "ES256" })}.${b64uJson(payload)}`;
  const sig = await crypto.subtle.sign(SIGN, privateKey, te.encode(input));
  return `${input}.${b64uEncode(sig)}`;
}

export function decodeJwt(jwt) {
  const parts = String(jwt).split(".");
  if (parts.length !== 3) throw new Error("A JWT has three dot-separated parts");
  return { header: parseB64uJson(parts[0]), payload: parseB64uJson(parts[1]), input: `${parts[0]}.${parts[1]}`, signature: b64uDecode(parts[2]) };
}

// Verifies the signature only; claim checks (aud, nonce, exp…) are the caller's job.
export async function verifyJwt(jwt, key) {
  const d = decodeJwt(jwt);
  if (d.header.alg !== "ES256") throw new Error(`Unsupported alg ${d.header.alg}`);
  const publicKey = key instanceof CryptoKey ? key : await importPublicJwk(key);
  const ok = await crypto.subtle.verify(SIGN, publicKey, d.signature, te.encode(d.input));
  if (!ok) throw new Error("Signature does not verify");
  return d;
}
