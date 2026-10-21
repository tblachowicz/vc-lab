// SD-JWT (RFC 9901) for flat, top-level claims, plus Key Binding JWTs as used by SD-JWT VC and OpenID4VP.
import { b64uJson, parseB64uJson, randomB64u, sha256B64u } from "./b64.js";
import { decodeJwt, signJwt, verifyJwt } from "./jose.js";

export async function makeDisclosure(name, value) {
  const disclosure = b64uJson([randomB64u(16), name, value]);
  return { name, value, disclosure, digest: await sha256B64u(disclosure) };
}

// Issue `jwt~d1~d2~…~`. Every claim in `sdClaims` becomes selectively disclosable.
export async function issue({ header, payload, sdClaims, privateKey }) {
  const disclosures = await Promise.all(Object.entries(sdClaims).map(([k, v]) => makeDisclosure(k, v)));
  const body = { ...payload, _sd: disclosures.map((d) => d.digest).sort(), _sd_alg: "sha-256" };
  const jwt = await signJwt(header, body, privateKey);
  return { sdJwt: `${jwt}~${disclosures.map((d) => d.disclosure).join("~")}~`, jwt, disclosures, payload: body };
}

// Split a serialized SD-JWT or SD-JWT+KB. A trailing "~" means no KB-JWT.
export function split(serialized) {
  const parts = String(serialized).split("~");
  if (parts.length < 2) throw new Error("Not an SD-JWT: no ~ separator");
  const jwt = parts[0];
  const kbJwt = parts[parts.length - 1] || null;
  const disclosures = parts.slice(1, -1);
  if (disclosures.some((d) => !d)) throw new Error("Empty disclosure");
  return { jwt, disclosures, kbJwt };
}

export function decodeDisclosure(disclosure) {
  const arr = parseB64uJson(disclosure);
  if (!Array.isArray(arr) || arr.length !== 3 || typeof arr[1] !== "string") throw new Error("Only object-property disclosures [salt, name, value] are supported");
  return { salt: arr[0], name: arr[1], value: arr[2] };
}

// Match each disclosure to a digest in the payload's _sd array and rebuild the disclosed claims.
export async function resolveClaims(payload, disclosures) {
  if ((payload._sd_alg || "sha-256") !== "sha-256") throw new Error(`Unsupported _sd_alg ${payload._sd_alg}`);
  const sd = new Set(payload._sd || []);
  const seen = new Set();
  const claims = {};
  const details = [];
  for (const disclosure of disclosures) {
    const digest = await sha256B64u(disclosure);
    if (!sd.has(digest)) throw new Error(`Disclosure ${disclosure.slice(0, 12)}… has no matching digest in _sd`);
    if (seen.has(digest)) throw new Error("The same disclosure appears twice");
    seen.add(digest);
    const { salt, name, value } = decodeDisclosure(disclosure);
    if (name in claims || name in payload) throw new Error(`Claim ${name} disclosed twice`);
    claims[name] = value;
    details.push({ name, value, salt, digest, disclosure });
  }
  return { claims, details };
}

// sd_hash covers the issuer JWT and the chosen disclosures, i.e. everything before the KB-JWT.
export const sdHash = (presentationWithoutKb) => sha256B64u(presentationWithoutKb);

// Build an SD-JWT+KB that reveals only `reveal` (claim names) and is bound to aud + nonce.
export async function present({ sdJwt, reveal, holderKey, aud, nonce, iat = Math.floor(Date.now() / 1000) }) {
  const { jwt, disclosures } = split(sdJwt);
  const chosen = disclosures.filter((d) => reveal.includes(decodeDisclosure(d).name));
  const withoutKb = `${jwt}~${chosen.map((d) => `${d}~`).join("")}`;
  const kbPayload = { iat, aud, nonce, sd_hash: await sdHash(withoutKb) };
  const kbJwt = await signJwt({ typ: "kb+jwt" }, kbPayload, holderKey);
  return { presentation: withoutKb + kbJwt, kbPayload, disclosed: chosen.map(decodeDisclosure) };
}

// Verify a KB-JWT against the holder key in cnf.jwk and the expected aud/nonce. Returns the individual checks.
export async function verifyKeyBinding({ presentation, cnfJwk, aud, nonce, maxAgeSeconds = 300, now = Math.floor(Date.now() / 1000) }) {
  const { kbJwt } = split(presentation);
  if (!kbJwt) throw new Error("Presentation has no Key Binding JWT");
  const { header, payload } = decodeJwt(kbJwt);
  let signatureOk = true;
  try { await verifyJwt(kbJwt, cnfJwk); } catch { signatureOk = false; }
  const withoutKb = presentation.slice(0, presentation.length - kbJwt.length);
  return {
    header, payload,
    checks: {
      typ: header.typ === "kb+jwt",
      signature: signatureOk,
      aud: payload.aud === aud,
      nonce: payload.nonce === nonce,
      iat: typeof payload.iat === "number" && payload.iat <= now + 60 && now - payload.iat <= maxAgeSeconds,
      sd_hash: payload.sd_hash === (await sdHash(withoutKb)),
    },
  };
}
