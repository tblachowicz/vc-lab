// Verifier (OpenID4VP 1.0): unsigned request with the redirect_uri Client Identifier Prefix,
// DCQL query, Response Mode direct_post, response_code returned to the browser that started the flow.
import { randomB64u } from "../lib/b64.js";
import { CLAIMS, FORMAT, VCT, claimLabel } from "../lib/contact.js";
import { decodeJwt, verifyJwt } from "../lib/jose.js";
import { cors, error, json, readForm, route } from "../lib/http.js";
import { resolveClaims, split, verifyKeyBinding } from "../lib/sdjwt.js";

const TTL = 10 * 60 * 1000;
const QUERY_ID = "contact";

export function createVerifier({ verifierUrl, walletUrl, trustedIssuers, fetchImpl = fetch }) {
  const responseUri = `${verifierUrl}/response`;
  const clientId = `redirect_uri:${responseUri}`;
  const txs = new Map(); // state -> transaction

  const sweep = () => { const now = Date.now(); for (const [k, t] of txs) if (now - t.created > TTL) txs.delete(k); };

  const routes = {
    "POST /api/requests": async (req) => {
      const body = await req.json().catch(() => null);
      const known = CLAIMS.map((c) => c.name);
      const claims = Array.isArray(body?.claims) ? [...new Set(body.claims)].filter((c) => known.includes(c)) : [];
      if (!claims.length) return error(400, "invalid_request", "Pick at least one claim to request");
      sweep();
      const state = randomB64u(16);
      const nonce = randomB64u(16);
      const dcqlQuery = {
        credentials: [{ id: QUERY_ID, format: FORMAT, meta: { vct_values: [VCT] }, claims: claims.map((name) => ({ path: [name] })) }],
      };
      const request = {
        response_type: "vp_token",
        client_id: clientId,
        response_mode: "direct_post",
        response_uri: responseUri,
        nonce,
        state,
        dcql_query: dcqlQuery,
        client_metadata: { vp_formats_supported: { [FORMAT]: { "sd-jwt_alg_values": ["ES256"], "kb-jwt_alg_values": ["ES256"] } } },
      };
      const params = new URLSearchParams();
      for (const [k, v] of Object.entries(request)) params.set(k, typeof v === "string" ? v : JSON.stringify(v));
      txs.set(state, { state, nonce, claims, status: "pending", created: Date.now(), request });
      return json({ id: state, wallet_url: `${walletUrl}/authorize?${params}`, request });
    },

    "GET /api/requests/:id": (req, { id }) => {
      const tx = txs.get(id);
      if (!tx) return error(404, "not_found", "Unknown or expired request");
      if (tx.status === "pending") return json({ status: "pending", claims: tx.claims, request: tx.request });
      // The result is released only to whoever holds the response_code the wallet was redirected with.
      if (new URL(req.url).searchParams.get("response_code") !== tx.responseCode) return error(403, "access_denied", "Wrong or missing response_code");
      const { status, claims, request, result, steps, wallet_error } = tx;
      return json({ status, claims, request, result, steps, wallet_error });
    },

    // Response URI: the wallet POSTs here (application/x-www-form-urlencoded).
    "POST /response": async (req) => {
      const form = await readForm(req);
      const tx = txs.get(form.get("state"));
      if (!tx) return cors(error(400, "invalid_request", "Unknown or expired state"));
      if (tx.status !== "pending") return cors(error(400, "invalid_request", "This request was already answered"));
      tx.responseCode = randomB64u(16);
      const redirect = { redirect_uri: `${verifierUrl}/#response_code=${tx.responseCode}` };

      if (form.get("error")) {
        tx.status = "declined";
        tx.wallet_error = { error: form.get("error"), error_description: form.get("error_description") || "" };
        tx.steps = [];
        return cors(json(redirect));
      }
      const { ok, steps, claims } = await verifyResponse(tx, form.get("vp_token"));
      tx.status = ok ? "verified" : "rejected";
      tx.steps = steps;
      tx.result = ok ? claims : null;
      return cors(json(redirect));
    },
  };

  async function verifyResponse(tx, vpTokenRaw) {
    const steps = [];
    const step = (title, who, desc) => { const s = { title, who, desc, rows: [], status: "ok" }; steps.push(s); return s; };
    const check = (s, label, value, ok) => { s.rows.push([label, value, ok]); if (ok === false) s.status = "bad"; return ok !== false; };
    const done = (claims = null) => ({ ok: steps.every((s) => s.status === "ok"), steps, claims });

    // 1. Shape of the response
    const s1 = step("Read the response", "verifier", "The wallet POSTed vp_token and state to the response URI. vp_token is a JSON object keyed by the DCQL credential query id.");
    check(s1, "state", tx.state, true);
    let presentation;
    try {
      const vpToken = JSON.parse(vpTokenRaw || "");
      const list = vpToken?.[QUERY_ID];
      check(s1, `vp_token.${QUERY_ID}`, Array.isArray(list) ? `${list.length} presentation` : "missing", Array.isArray(list) && list.length === 1);
      presentation = list?.[0];
      if (typeof presentation !== "string") return done();
      const { disclosures, kbJwt } = split(presentation);
      check(s1, "format", `SD-JWT with ${disclosures.length} disclosure${disclosures.length === 1 ? "" : "s"}${kbJwt ? " + KB-JWT" : ""}`, !!kbJwt);
      s1.code = { label: "Show vp_token", text: JSON.stringify(vpToken, null, 2) };
    } catch (e) {
      check(s1, "vp_token", e.message, false);
      return done();
    }
    if (s1.status !== "ok") return done();

    // 2. Issuer signature
    const { jwt, disclosures } = split(presentation);
    const s2 = step("Check the issuer's signature", "verifier", "The issuer-signed JWT must come from an issuer this verifier trusts, signed with a key published in its JWT VC Issuer Metadata.");
    let payload;
    try {
      const decoded = decodeJwt(jwt);
      payload = decoded.payload;
      check(s2, "typ", decoded.header.typ, decoded.header.typ === "dc+sd-jwt");
      const trusted = trustedIssuers.includes(payload.iss);
      check(s2, "iss", payload.iss, trusted ? true : false);
      if (!trusted) return done();
      const keys = await issuerKeys(payload.iss);
      const key = keys.find((k) => k.kid === decoded.header.kid);
      check(s2, "kid", decoded.header.kid ? `${decoded.header.kid.slice(0, 16)}…` : "missing", !!key);
      if (!key) return done();
      let sigOk = true;
      try { await verifyJwt(jwt, key); } catch { sigOk = false; }
      check(s2, "signature", sigOk ? "valid (ES256)" : "invalid", sigOk);
      check(s2, "vct", payload.vct, payload.vct === VCT);
      const now = Math.floor(Date.now() / 1000);
      check(s2, "exp", payload.exp ? new Date(payload.exp * 1000).toISOString().slice(0, 10) : "none", !payload.exp || payload.exp > now);
      s2.code = { label: "Show issuer-signed payload", text: JSON.stringify(payload, null, 2) };
    } catch (e) {
      check(s2, "error", e.message, false);
    }
    if (s2.status !== "ok") return done();

    // 3. Disclosures
    const s3 = step("Match the disclosures", "verifier", "Each disclosure is hashed and must match a digest in the signed _sd array. Only requested claims should be disclosed.");
    let claims;
    try {
      const resolved = await resolveClaims(payload, disclosures);
      claims = resolved.claims;
      for (const d of resolved.details) check(s3, claimLabel(d.name), d.value, tx.claims.includes(d.name) ? true : "not requested");
      for (const name of tx.claims) if (!(name in claims)) check(s3, claimLabel(name), "requested but not disclosed", false);
      const extra = Object.keys(claims).filter((n) => !tx.claims.includes(n));
      if (extra.length) check(s3, "over-disclosure", extra.map(claimLabel).join(", "), false);
      check(s3, "hidden", `${(payload._sd?.length || 0) - resolved.details.length} digest(s) left undisclosed`, "info");
    } catch (e) {
      check(s3, "error", e.message, false);
    }
    if (s3.status !== "ok") return done();

    // 4. Key binding
    const s4 = step("Check key binding", "verifier", "The KB-JWT proves the presenter holds the key in cnf.jwk, and ties this presentation to this request's nonce and to this verifier.");
    try {
      const kb = await verifyKeyBinding({ presentation, cnfJwk: payload.cnf?.jwk, aud: clientId, nonce: tx.nonce });
      check(s4, "typ", kb.header.typ, kb.checks.typ);
      check(s4, "signature", kb.checks.signature ? "valid, by the cnf.jwk key" : "invalid", kb.checks.signature);
      check(s4, "aud", kb.payload.aud, kb.checks.aud);
      check(s4, "nonce", kb.payload.nonce, kb.checks.nonce);
      check(s4, "iat", kb.payload.iat ? new Date(kb.payload.iat * 1000).toISOString().slice(11, 19) + " UTC" : "missing", kb.checks.iat);
      check(s4, "sd_hash", `${String(kb.payload.sd_hash).slice(0, 16)}…`, kb.checks.sd_hash);
      s4.code = { label: "Show KB-JWT payload", text: JSON.stringify(kb.payload, null, 2) };
    } catch (e) {
      check(s4, "error", e.message, false);
    }
    return done(claims);
  }

  // JWT VC Issuer Metadata: /.well-known/jwt-vc-issuer is inserted between host and path.
  const keyCache = new Map();
  async function issuerKeys(iss) {
    if (keyCache.has(iss)) return keyCache.get(iss);
    const u = new URL(iss);
    const res = await fetchImpl(`${u.origin}/.well-known/jwt-vc-issuer${u.pathname === "/" ? "" : u.pathname}`);
    if (!res.ok) throw new Error(`Issuer metadata returned HTTP ${res.status}`);
    const meta = await res.json();
    if (meta.issuer !== iss) throw new Error("Issuer metadata names a different issuer");
    const keys = meta.jwks?.keys || [];
    keyCache.set(iss, keys);
    return keys;
  }

  return { handle: (req) => route(routes, req) };
}
