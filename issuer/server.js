// Credential Issuer + Authorization Server (OpenID4VCI 1.0, pre-authorized code flow).
// A fetch-style handler: takes a Request, returns a Response, or null to let the host serve static files.
import { randomB64u } from "../lib/b64.js";
import { CLAIMS, CONFIG_ID, FORMAT, PRE_AUTH_GRANT, VCT } from "../lib/contact.js";
import { decodeJwt, exportPublicJwk, importPublicJwk, jwkThumbprint, verifyJwt } from "../lib/jose.js";
import { issue } from "../lib/sdjwt.js";
import { cors, error, json, readForm, route } from "../lib/http.js";

const TTL = 5 * 60 * 1000;
const CREDENTIAL_LIFETIME = 365 * 24 * 3600;

export async function createIssuer({ issuerUrl, walletUrl, signingKey }) {
  const publicJwk = await exportPublicJwk(signingKey.publicKey);
  const kid = await jwkThumbprint(publicJwk);

  // In-memory state. Each entry expires after TTL; codes, tokens and nonces are single-use.
  const offers = new Map();   // offerId -> { claims, code, events[], created }
  const codes = new Map();    // pre-authorized code -> offerId
  const tokens = new Map();   // access token -> { offerId, expires }
  const nonces = new Map();   // c_nonce -> expires

  const log = (offer, step, detail = {}) => offer?.events.push({ at: Date.now(), step, ...detail });
  const sweep = () => {
    const now = Date.now();
    for (const [k, o] of offers) if (now - o.created > 24 * 3600 * 1000) { offers.delete(k); codes.delete(o.code); }
    for (const [k, t] of tokens) if (t.expires < now) tokens.delete(k);
    for (const [k, exp] of nonces) if (exp < now) nonces.delete(k);
  };

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
      sweep();
      const id = randomB64u(12);
      const code = randomB64u(24);
      const offer = { claims, code, events: [], created: Date.now() };
      offers.set(id, offer);
      codes.set(code, id);
      const credentialOffer = offerJson(code);
      const offerUri = `${issuerUrl}/offers/${id}`;
      const walletLink = `${walletUrl}/offer?credential_offer_uri=${encodeURIComponent(offerUri)}`;
      log(offer, "offer_created", { offer_uri: offerUri });
      return json({ id, offer_uri: offerUri, wallet_link: walletLink, credential_offer: credentialOffer });
    },

    "GET /api/offers/:id/events": (req, { id }) => {
      const offer = offers.get(id);
      if (!offer) return error(404, "not_found", "Unknown offer");
      return json({ claims: offer.claims, events: offer.events });
    },

    // --- OpenID4VCI endpoints called by the wallet ---
    "GET /offers/:id": (req, { id }) => {
      const offer = offers.get(id);
      if (!offer) return error(404, "not_found", "Unknown or expired credential offer");
      log(offer, "offer_fetched");
      return cors(json(offerJson(offer.code)));
    },

    "GET /.well-known/openid-credential-issuer": () => cors(json(issuerMetadata)),
    "GET /.well-known/oauth-authorization-server": () => cors(json(asMetadata)),
    // SD-JWT VC issuer key discovery (JWT VC Issuer Metadata)
    "GET /.well-known/jwt-vc-issuer": () => cors(json({ issuer: issuerUrl, jwks: { keys: [{ ...publicJwk, kid, use: "sig", alg: "ES256" }] } })),

    "POST /token": async (req) => {
      const form = await readForm(req);
      if (form.get("grant_type") !== PRE_AUTH_GRANT) return cors(error(400, "unsupported_grant_type", "Only the pre-authorized code grant is supported"));
      const code = form.get("pre-authorized_code");
      const id = codes.get(code);
      const offer = offers.get(id);
      if (!offer || Date.now() - offer.created > TTL) return cors(error(400, "invalid_grant", "Unknown, used or expired pre-authorized code"));
      codes.delete(code); // single use
      const accessToken = randomB64u(32);
      tokens.set(accessToken, { offerId: id, expires: Date.now() + TTL });
      log(offer, "token_issued");
      return cors(json({ access_token: accessToken, token_type: "Bearer", expires_in: TTL / 1000 }, { "Cache-Control": "no-store" }));
    },

    "POST /nonce": () => {
      const cNonce = randomB64u(24);
      nonces.set(cNonce, Date.now() + TTL);
      return cors(json({ c_nonce: cNonce }, { "Cache-Control": "no-store" }));
    },

    "POST /credential": async (req) => {
      const auth = req.headers.get("authorization") || "";
      const token = tokens.get(auth.replace(/^Bearer\s+/i, ""));
      if (!token || token.expires < Date.now()) return cors(error(401, "invalid_token", "Missing or expired access token", { "WWW-Authenticate": 'Bearer error="invalid_token"' }));
      const offer = offers.get(token.offerId);
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
        const exp = nonces.get(payload.nonce);
        if (!exp || exp < Date.now()) throw Object.assign(new Error("c_nonce is unknown, used or expired"), { code: "invalid_nonce" });
        nonces.delete(payload.nonce);
        holderJwk = { kty: header.jwk.kty, crv: header.jwk.crv, x: header.jwk.x, y: header.jwk.y };
        log(offer, "proof_verified", { holder_key: holderJwk });
      } catch (e) {
        log(offer, "proof_rejected", { reason: e.message });
        return cors(error(400, e.code || "invalid_proof", e.message));
      }

      tokens.delete(auth.replace(/^Bearer\s+/i, "")); // one credential per offer
      const now = Math.floor(Date.now() / 1000);
      const { sdJwt, disclosures } = await issue({
        header: { typ: "dc+sd-jwt", kid },
        payload: { iss: issuerUrl, iat: now, exp: now + CREDENTIAL_LIFETIME, vct: VCT, cnf: { jwk: holderJwk } },
        sdClaims: offer.claims,
        privateKey: signingKey.privateKey,
      });
      log(offer, "credential_issued", { disclosures: disclosures.map(({ name, digest }) => ({ name, digest })) });
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
