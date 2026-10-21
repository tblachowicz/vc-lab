// Credential Issuer + Authorization Server (OpenID4VCI 1.0, pre-authorized code flow).
// A fetch-style handler: takes a Request, returns a Response, or null to let the host serve static files.
import { randomB64u } from "../lib/b64.js";
import { CLAIMS, CONFIG_ID, FORMAT, PRE_AUTH_GRANT, VCT } from "../lib/contact.js";
import { decodeJwt, exportPublicJwk, importPublicJwk, jwkThumbprint, verifyJwt } from "../lib/jose.js";
import { issue } from "../lib/sdjwt.js";
import { cors, error, json, readForm, route } from "../lib/http.js";
import { memoryStore, take } from "../lib/kv.js";

const TTL = 5 * 60 * 1000;
const OFFER_TTL = 24 * 3600 * 1000; // offers stay readable for a day so the issuer page can show their log
const CREDENTIAL_LIFETIME = 365 * 24 * 3600;

export async function createIssuer({ issuerUrl, walletUrl, signingKey, store = memoryStore() }) {
  const publicJwk = await exportPublicJwk(signingKey.publicKey);
  const kid = await jwkThumbprint(publicJwk);

  // State, all with expiry. Codes, tokens and nonces are single-use.
  //   offer:<id> -> { claims, code, events[] }   code:<code> -> offerId
  //   token:<access token> -> offerId             nonce:<c_nonce> -> true
  async function log(id, step, detail = {}) {
    const offer = await store.get(`offer:${id}`);
    if (!offer) return;
    offer.events.push({ at: Date.now(), step, ...detail });
    await store.put(`offer:${id}`, offer, OFFER_TTL);
  }

  const issuerMetadata = {
    credential_issuer: issuerUrl,
    credential_endpoint: `${issuerUrl}/credential`,
    nonce_endpoint: `${issuerUrl}/nonce`,
    display: [{ name: "VC Lab Issuer", locale: "en" }],
    credential_configurations_supported: {
      [CONFIG_ID]: {
        format: FORMAT,
        vct: VCT,
        cryptographic_binding_methods_supported: ["jwk"],
        credential_signing_alg_values_supported: ["ES256"],
        proof_types_supported: { jwt: { proof_signing_alg_values_supported: ["ES256"] } },
        credential_metadata: {
          display: [{ name: "Contact card", locale: "en", background_color: "#0f5c55", text_color: "#ffffff" }],
          claims: CLAIMS.map((c) => ({ path: [c.name], display: [{ name: c.label, locale: "en" }] })),
        },
      },
    },
  };

  const asMetadata = {
    issuer: issuerUrl,
    token_endpoint: `${issuerUrl}/token`,
    grant_types_supported: [PRE_AUTH_GRANT],
    "pre-authorized_grant_anonymous_access_supported": true,
  };

  const routes = {
    // --- Issuer UI API ---
    "POST /api/offers": async (req) => {
      const body = await req.json().catch(() => null);
      const claims = {};
      for (const { name, label } of CLAIMS) {
        const v = typeof body?.[name] === "string" ? body[name].trim() : "";
        if (!v) return error(400, "invalid_request", `${label} is required`);
        if (v.length > 200) return error(400, "invalid_request", `${label} is too long`);
        claims[name] = v;
      }
      const id = randomB64u(12);
      const code = randomB64u(24);
      const offerUri = `${issuerUrl}/offers/${id}`;
      await store.put(`offer:${id}`, { claims, code, events: [{ at: Date.now(), step: "offer_created", offer_uri: offerUri }] }, OFFER_TTL);
      await store.put(`code:${code}`, id, TTL);
      const credentialOffer = offerJson(code);
      const walletLink = `${walletUrl}/offer?credential_offer_uri=${encodeURIComponent(offerUri)}`;
      return json({ id, offer_uri: offerUri, wallet_link: walletLink, credential_offer: credentialOffer });
    },

    "GET /api/offers/:id/events": async (req, { id }) => {
      const offer = await store.get(`offer:${id}`);
      if (!offer) return error(404, "not_found", "Unknown offer");
      return json({ claims: offer.claims, events: offer.events });
    },

    // --- OpenID4VCI endpoints called by the wallet ---
    "GET /offers/:id": async (req, { id }) => {
      const offer = await store.get(`offer:${id}`);
      if (!offer || (await store.get(`code:${offer.code}`)) === undefined) return cors(error(404, "not_found", "Unknown, used or expired credential offer"));
      await log(id, "offer_fetched");
      return cors(json(offerJson(offer.code)));
    },

    "GET /.well-known/openid-credential-issuer": () => cors(json(issuerMetadata)),
    "GET /.well-known/oauth-authorization-server": () => cors(json(asMetadata)),
    // SD-JWT VC issuer key discovery (JWT VC Issuer Metadata)
    "GET /.well-known/jwt-vc-issuer": () => cors(json({ issuer: issuerUrl, jwks: { keys: [{ ...publicJwk, kid, use: "sig", alg: "ES256" }] } })),

    "POST /token": async (req) => {
      const form = await readForm(req);
      if (form.get("grant_type") !== PRE_AUTH_GRANT) return cors(error(400, "unsupported_grant_type", "Only the pre-authorized code grant is supported"));
      const id = await take(store, `code:${form.get("pre-authorized_code")}`);
      if (id === undefined) return cors(error(400, "invalid_grant", "Unknown, used or expired pre-authorized code"));
      const accessToken = randomB64u(32);
      await store.put(`token:${accessToken}`, id, TTL);
      await log(id, "token_issued");
      return cors(json({ access_token: accessToken, token_type: "Bearer", expires_in: TTL / 1000 }, { "Cache-Control": "no-store" }));
    },

    "POST /nonce": async () => {
      const cNonce = randomB64u(24);
      await store.put(`nonce:${cNonce}`, true, TTL);
      return cors(json({ c_nonce: cNonce }, { "Cache-Control": "no-store" }));
    },

    "POST /credential": async (req) => {
      const tokenKey = `token:${(req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "")}`;
      const offerId = await store.get(tokenKey);
      const offer = offerId === undefined ? undefined : await store.get(`offer:${offerId}`);
      if (!offer) return cors(error(401, "invalid_token", "Missing or expired access token", { "WWW-Authenticate": 'Bearer error="invalid_token"' }));
      const body = await req.json().catch(() => null);
      if (body?.credential_configuration_id !== CONFIG_ID) return cors(error(400, "invalid_credential_request", `credential_configuration_id must be ${CONFIG_ID}`));
      const proofs = body?.proofs?.jwt;
      if (!Array.isArray(proofs) || proofs.length !== 1) return cors(error(400, "invalid_proof", "Send exactly one proof in proofs.jwt"));

      // Proof of possession of the holder key (OpenID4VCI 1.0 Appendix F.1)
      let holderJwk;
      try {
        const { header, payload } = decodeJwt(proofs[0]);
        if (header.typ !== "openid4vci-proof+jwt") throw new Error("typ must be openid4vci-proof+jwt");
        if (!header.jwk) throw new Error("The proof header must carry the holder key as jwk");
        await importPublicJwk(header.jwk);
        await verifyJwt(proofs[0], header.jwk);
        if (payload.aud !== issuerUrl) throw new Error(`aud must be ${issuerUrl}`);
        const now = Math.floor(Date.now() / 1000);
        if (typeof payload.iat !== "number" || Math.abs(now - payload.iat) > 300) throw new Error("iat is missing or not recent");
        if (!(await take(store, `nonce:${payload.nonce}`))) throw Object.assign(new Error("c_nonce is unknown, used or expired"), { code: "invalid_nonce" });
        holderJwk = { kty: header.jwk.kty, crv: header.jwk.crv, x: header.jwk.x, y: header.jwk.y };
        await log(offerId, "proof_verified", { holder_key: holderJwk });
      } catch (e) {
        await log(offerId, "proof_rejected", { reason: e.message });
        return cors(error(400, e.code || "invalid_proof", e.message));
      }

      await store.delete(tokenKey); // one credential per offer
      const now = Math.floor(Date.now() / 1000);
      const { sdJwt, disclosures } = await issue({
        header: { typ: "dc+sd-jwt", kid },
        payload: { iss: issuerUrl, iat: now, exp: now + CREDENTIAL_LIFETIME, vct: VCT, cnf: { jwk: holderJwk } },
        sdClaims: offer.claims,
        privateKey: signingKey.privateKey,
      });
      await log(offerId, "credential_issued", { disclosures: disclosures.map(({ name, digest }) => ({ name, digest })) });
      return cors(json({ credentials: [{ credential: sdJwt }] }, { "Cache-Control": "no-store" }));
    },
  };

  function offerJson(code) {
    return {
      credential_issuer: issuerUrl,
      credential_configuration_ids: [CONFIG_ID],
      grants: { [PRE_AUTH_GRANT]: { "pre-authorized_code": code } },
    };
  }

  return { handle: (req) => route(routes, req) };
}
