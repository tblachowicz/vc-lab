// Cross-checks lib/sdjwt.js against an independent implementation (OpenWallet Foundation @sd-jwt), in both directions.
import { test } from "node:test";
import assert from "node:assert/strict";
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import { ES256, digest, generateSalt } from "@sd-jwt/crypto-nodejs";
import { VCT } from "../lib/contact.js";
import { exportPublicJwk, generateKeyPair, verifyJwt } from "../lib/jose.js";
import { issue, present, resolveClaims, split, verifyKeyBinding } from "../lib/sdjwt.js";

const claims = { name: "Ada Lovelace", email: "ada@example.com", phone_number: "+44 20 7946 0018" };
const aud = "redirect_uri:https://verifier.example/response";
const nonce = "n-0S6_WzA2Mj";

test("our issuance and presentation verify with @sd-jwt", async () => {
  const issuer = await generateKeyPair();
  const holder = await generateKeyPair();
  const issuerJwk = await exportPublicJwk(issuer.publicKey);
  const holderJwk = await exportPublicJwk(holder.publicKey);
  const now = Math.floor(Date.now() / 1000);
  const { sdJwt } = await issue({
    header: { typ: "dc+sd-jwt" },
    payload: { iss: "https://issuer.example", iat: now, exp: now + 3600, vct: VCT, cnf: { jwk: holderJwk } },
    sdClaims: claims,
    privateKey: issuer.privateKey,
  });
  const { presentation } = await present({ sdJwt, reveal: ["name", "email"], holderKey: holder.privateKey, aud, nonce });

  const sd = new SDJwtVcInstance({
    hasher: digest,
    hashAlg: "sha-256",
    verifier: await ES256.getVerifier(issuerJwk),
    kbVerifier: async (data, sig, payload) => (await ES256.getVerifier(payload.cnf.jwk))(data, sig),
  });
  const result = await sd.verify(presentation, { keyBindingNonce: nonce, expectedKeyBindingAudience: aud, requiredClaimKeys: ["name", "email"] });
  assert.equal(result.payload.name, claims.name);
  assert.equal(result.payload.email, claims.email);
  assert.equal(result.payload.phone_number, undefined, "withheld claim stays hidden");
  assert.ok(result.kb, "key binding was checked");
});

test("@sd-jwt issuance and presentation verify with our code", async () => {
  const issuerKeys = await ES256.generateKeyPair();
  const holderKeys = await ES256.generateKeyPair();
  const sd = new SDJwtVcInstance({
    hasher: digest,
    hashAlg: "sha-256",
    saltGenerator: generateSalt,
    signer: await ES256.getSigner(issuerKeys.privateKey),
    signAlg: "ES256",
    kbSigner: await ES256.getSigner(holderKeys.privateKey),
    kbSignAlg: "ES256",
  });
  const now = Math.floor(Date.now() / 1000);
  const { d, ...holderPublic } = holderKeys.publicKey;
  const credential = await sd.issue({ iss: "https://issuer.example", iat: now, vct: VCT, cnf: { jwk: holderPublic }, ...claims }, { _sd: ["name", "email", "phone_number"] });
  const presentation = await sd.present(credential, { email: true }, { kb: { payload: { iat: now, aud, nonce } } });

  const { jwt, disclosures } = split(presentation);
  const { payload } = await verifyJwt(jwt, issuerKeys.publicKey);
  const resolved = await resolveClaims(payload, disclosures);
  assert.deepEqual(resolved.claims, { email: claims.email });
  const kb = await verifyKeyBinding({ presentation, cnfJwk: payload.cnf.jwk, aud, nonce });
  assert.ok(Object.values(kb.checks).every(Boolean), JSON.stringify(kb.checks));
});

