// Protocol-level test of the full flow against the real issuer and verifier handlers, with the wallet's
// side done in Node (same lib code the browser wallet uses). Run: node --test
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { start } from "../scripts/serve.js";
import { CONFIG_ID, PRE_AUTH_GRANT } from "../lib/contact.js";
import { exportPublicJwk, generateKeyPair, signJwt } from "../lib/jose.js";
import { decodeDisclosure, present, split } from "../lib/sdjwt.js";

const urls = { homeUrl: "http://localhost:4100", issuerUrl: "http://localhost:4101", walletUrl: "http://localhost:4102", verifierUrl: "http://localhost:4103" };
const post = (url, body, headers = {}) => fetch(url, { method: "POST", body, headers });
const postJson = (url, obj, headers = {}) => post(url, JSON.stringify(obj), { "Content-Type": "application/json", ...headers });
const form = (obj) => ({ body: new URLSearchParams(obj).toString(), headers: { "Content-Type": "application/x-www-form-urlencoded" } });

async function issueCredential(claims) {
  const offerRes = await (await postJson(`${urls.issuerUrl}/api/offers`, claims)).json();
  const offer = await (await fetch(new URL(offerRes.wallet_link).searchParams.get("credential_offer_uri"))).json();
  const meta = await (await fetch(`${offer.credential_issuer}/.well-known/openid-credential-issuer`)).json();
  const as = await (await fetch(`${offer.credential_issuer}/.well-known/oauth-authorization-server`)).json();
  const f = form({ grant_type: PRE_AUTH_GRANT, "pre-authorized_code": offer.grants[PRE_AUTH_GRANT]["pre-authorized_code"] });
  const token = await (await post(as.token_endpoint, f.body, f.headers)).json();
  const { c_nonce } = await (await post(meta.nonce_endpoint)).json();
  const holder = await generateKeyPair();
  const proof = await signJwt({ typ: "openid4vci-proof+jwt", jwk: await exportPublicJwk(holder.publicKey) }, { aud: offer.credential_issuer, iat: Math.floor(Date.now() / 1000), nonce: c_nonce }, holder.privateKey);
  const res = await postJson(meta.credential_endpoint, { credential_configuration_id: CONFIG_ID, proofs: { jwt: [proof] } }, { Authorization: `Bearer ${token.access_token}` });
  return { status: res.status, body: await res.json(), holder, offer, token, meta, proof };
}

test("issue, present selected claims, verify", async (t) => {
  const lab = await start({ ...urls, keyFile: join(await mkdtemp(join(tmpdir(), "vclab-")), "k.json") });
  t.after(() => lab.close());
  const claims = { name: "Ada Lovelace", email: "ada@example.com", phone_number: "+44 20 7946 0000" };

  const issued = await issueCredential(claims);
  assert.equal(issued.status, 200, JSON.stringify(issued.body));
  const sdJwt = issued.body.credentials[0].credential;
  assert.deepEqual(split(sdJwt).disclosures.map((d) => decodeDisclosure(d).name).sort(), ["email", "name", "phone_number"]);

  await t.test("pre-authorized code and nonce are single-use", async () => {
    const f = form({ grant_type: PRE_AUTH_GRANT, "pre-authorized_code": issued.offer.grants[PRE_AUTH_GRANT]["pre-authorized_code"] });
    assert.equal((await post(`${urls.issuerUrl}/token`, f.body, f.headers)).status, 400);
    const again = await postJson(issued.meta.credential_endpoint, { credential_configuration_id: CONFIG_ID, proofs: { jwt: [issued.proof] } }, { Authorization: `Bearer ${issued.token.access_token}` });
    assert.equal(again.status, 401);
  });

  // Verifier asks for name + email only
  const req = await (await postJson(`${urls.verifierUrl}/api/requests`, { claims: ["name", "email"] })).json();
  const p = new URL(req.wallet_url).searchParams;
  assert.equal(p.get("client_id"), `redirect_uri:${urls.verifierUrl}/response`);
  const { presentation } = await present({ sdJwt, reveal: ["name", "email"], holderKey: issued.holder.privateKey, aud: p.get("client_id"), nonce: p.get("nonce") });
  const f = form({ vp_token: JSON.stringify({ contact: [presentation] }), state: p.get("state") });
  const { redirect_uri } = await (await post(p.get("response_uri"), f.body, f.headers)).json();
  const code = new URL(redirect_uri).hash.split("=")[1];

  assert.equal((await fetch(`${urls.verifierUrl}/api/requests/${req.id}`)).status, 403, "result needs the response_code");
  const result = await (await fetch(`${urls.verifierUrl}/api/requests/${req.id}?response_code=${code}`)).json();
  assert.equal(result.status, "verified", JSON.stringify(result.steps, null, 1));
  assert.deepEqual(result.result, { name: "Ada Lovelace", email: "ada@example.com" });

  await t.test("over-disclosure, wrong nonce and replay are rejected", async () => {
    for (const [label, opts] of [["over-disclosure", { reveal: ["name", "email", "phone_number"] }], ["wrong nonce", { nonce: "nope" }]]) {
      const r = await (await postJson(`${urls.verifierUrl}/api/requests`, { claims: ["name", "email"] })).json();
      const q = new URL(r.wallet_url).searchParams;
      const pres = (await present({ sdJwt, reveal: ["name", "email"], holderKey: issued.holder.privateKey, aud: q.get("client_id"), nonce: q.get("nonce"), ...opts })).presentation;
      const ff = form({ vp_token: JSON.stringify({ contact: [pres] }), state: q.get("state") });
      const { redirect_uri: ru } = await (await post(q.get("response_uri"), ff.body, ff.headers)).json();
      const out = await (await fetch(`${urls.verifierUrl}/api/requests/${r.id}?response_code=${new URL(ru).hash.split("=")[1]}`)).json();
      assert.equal(out.status, "rejected", label);
    }
    const replay = await post(p.get("response_uri"), f.body, f.headers);
    assert.equal(replay.status, 400, "a state can be answered once");
  });

  await t.test("a stolen credential fails key binding", async () => {
    const thief = await generateKeyPair();
    const r = await (await postJson(`${urls.verifierUrl}/api/requests`, { claims: ["email"] })).json();
    const q = new URL(r.wallet_url).searchParams;
    const pres = (await present({ sdJwt, reveal: ["email"], holderKey: thief.privateKey, aud: q.get("client_id"), nonce: q.get("nonce") })).presentation;
    const ff = form({ vp_token: JSON.stringify({ contact: [pres] }), state: q.get("state") });
    const { redirect_uri: ru } = await (await post(q.get("response_uri"), ff.body, ff.headers)).json();
    const out = await (await fetch(`${urls.verifierUrl}/api/requests/${r.id}?response_code=${new URL(ru).hash.split("=")[1]}`)).json();
    assert.equal(out.status, "rejected");
  });

  await t.test("decline is reported", async () => {
    const r = await (await postJson(`${urls.verifierUrl}/api/requests`, { claims: ["name"] })).json();
    const q = new URL(r.wallet_url).searchParams;
    const ff = form({ error: "access_denied", error_description: "The user declined", state: q.get("state") });
    const { redirect_uri: ru } = await (await post(q.get("response_uri"), ff.body, ff.headers)).json();
    const out = await (await fetch(`${urls.verifierUrl}/api/requests/${r.id}?response_code=${new URL(ru).hash.split("=")[1]}`)).json();
    assert.equal(out.status, "declined");
  });
});
