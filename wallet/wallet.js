// Web wallet: OpenID4VCI client (pre-authorized code) and OpenID4VP responder (DCQL, direct_post).
// Routes: ./ (credentials), ./offer (credential offer endpoint), ./authorize (authorization endpoint).
import { $, fetchJson, h, kv, labBar, pretty, raw, renderTrace, short } from "./ui/lab.js";
import { PRE_AUTH_GRANT, claimLabel } from "./lib/contact.js";
import { match, validateQuery } from "./lib/dcql.js";
import { decodeJwt, exportPublicJwk, generateKeyPair, jwkThumbprint, signJwt, verifyJwt } from "./lib/jose.js";
import { decodeDisclosure, present, resolveClaims, split } from "./lib/sdjwt.js";
import * as store from "./store.js";

const screen = $("#screen");
const traceEl = $("#trace");
const params = new URLSearchParams(location.search);
const page = location.pathname.split("/").pop().replace(/\.html$/, "");
const now = () => Math.floor(Date.now() / 1000);
let lab = {};

// /.well-known/<name> goes between the host and any path of the identifier (RFC 8414 style).
function wellKnown(base, name) {
  const u = new URL(base);
  const path = u.pathname === "/" ? "" : u.pathname.replace(/\/$/, "");
  return `${u.origin}/.well-known/${name}${path}`;
}

function startTrace(eyebrow, heading, steps) {
  const t = { eyebrow, heading, state: "run", steps: steps.map((s) => ({ ...s })) };
  t.set = (i, patch) => { Object.assign(t.steps[i], patch); renderTrace(traceEl, t); };
  t.finish = (state, heading) => { t.state = state; t.heading = heading; renderTrace(traceEl, t); };
  t.fail = (e) => {
    const i = t.steps.findIndex((s) => s.status !== "ok");
    if (i >= 0 && t.steps[i].status !== "bad") t.set(i, { status: "bad", rows: [...(t.steps[i].rows || []), ["error", e.message, false]] });
  };
  traceEl.hidden = false;
  renderTrace(traceEl, t);
  return t;
}

const checker = () => {
  const rows = [];
  let ok = true;
  return { rows, add: (k, v, pass) => { rows.push([k, v, pass]); if (pass === false) ok = false; return pass !== false; }, get ok() { return ok; } };
};

const safeColor = (c, fallback) => (/^#[0-9a-f]{3,8}$/i.test(c || "") ? c : fallback);
const fmtDate = (s) => new Date(s * 1000).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });

function notice(kind, strong, text) {
  return h("p", { class: `notice ${kind}` }, h("strong", {}, strong), text ? ` ${text}` : null);
}

function working(text) {
  screen.replaceChildren(h("section", { class: "panel" }, h("div", { class: "panel-bd" }, h("p", { class: "hint" }, text))));
}

// ---------- credential card ----------

function card(rec, { preview = false, actions = false, values = true } = {}) {
  const labels = rec.claimLabels || {};
  const names = preview ? Object.keys(labels) : Object.keys(rec.claims);
  const el = h("article", { class: "vc-card", style: `--card-bg:${safeColor(rec.display?.bg, "#0f5c55")};--card-fg:${safeColor(rec.display?.fg, "#ffffff")}` },
    h("div", { class: "vc-top" },
      h("div", {}, h("div", { class: "vc-name" }, rec.display?.name || "Credential"), h("div", { class: "vc-issuer" }, rec.issuerName || new URL(rec.issuer).host))),
    h("dl", { class: "vc-claims" }, names.map((n) => h("div", {}, h("dt", {}, labels[n] || claimLabel(n)), h("dd", {}, values ? rec.claims[n] : "Filled in by the issuer")))),
    !preview ? h("div", { class: "vc-meta" }, `Issued ${new Date(rec.issuedAt).toLocaleDateString()}${rec.exp ? ` · expires ${fmtDate(rec.exp)}` : ""}`) : null);
  if (!actions) return el;

  const details = h("div", { class: "panel", hidden: true });
  const detailsBtn = h("button", { class: "btn btn-quiet btn-small", type: "button", "aria-expanded": "false" }, "Details");
  detailsBtn.addEventListener("click", async () => {
    const open = details.hidden;
    details.hidden = !open;
    detailsBtn.setAttribute("aria-expanded", String(open));
    if (open && !details.childElementCount) details.append(await detailsView(rec));
  });
  const removeBtn = h("button", { class: "btn btn-quiet btn-small", type: "button" }, "Remove");
  let armed = null;
  removeBtn.addEventListener("click", async () => {
    if (!armed) {
      removeBtn.textContent = "Confirm remove";
      removeBtn.className = "btn btn-danger btn-small";
      armed = setTimeout(() => { armed = null; removeBtn.textContent = "Remove"; removeBtn.className = "btn btn-quiet btn-small"; }, 4000);
      return;
    }
    clearTimeout(armed);
    await store.remove(rec.id);
    home();
  });
  return h("div", { style: "display:grid;gap:10px" }, el, h("div", { class: "vc-actions" }, detailsBtn, removeBtn), details);
}

async function detailsView(rec) {
  const { jwt, disclosures } = split(rec.sdJwt);
  const { header, payload } = decodeJwt(jwt);
  return h("div", { class: "panel-bd" },
    kv([
      ["format", rec.format],
      ["vct", payload.vct],
      ["iss", payload.iss],
      ["kid", short(header.kid || "none", 10)],
      ["holder key", `P-256, thumbprint ${short(await jwkThumbprint(rec.holderJwk), 8)}`],
      ["private key", rec.holderKey?.privateKey?.extractable === false ? "non-extractable" : "extractable"],
      ["disclosures", `${disclosures.length}, digests in _sd: ${payload._sd?.length || 0}`],
    ]),
    raw("Issuer-signed JWT payload", pretty(payload)),
    raw("Disclosures", disclosures.map((d) => { const x = decodeDisclosure(d); return `${x.name}: ${JSON.stringify(x.value)}\n  salt ${x.salt}\n  ${d}`; }).join("\n\n"), { wrap: true }),
    raw("Raw SD-JWT", rec.sdJwt.replaceAll("~", "~\n"), { wrap: true }));
}

// ---------- home ----------

async function home() {
  traceEl.hidden = true;
  let creds = [];
  try { creds = await store.all(); } catch (e) {
    screen.replaceChildren(notice("bad", "This browser won't let the wallet store anything.", `${e.message}. Private browsing can cause this.`));
    return;
  }
  const hd = h("div", { class: "screen-hd" }, h("h2", {}, "Your credentials"), h("span", { class: "eyebrow" }, `${creds.length} stored`));
  if (!creds.length) {
    screen.replaceChildren(hd, h("section", { class: "panel empty" },
      h("p", {}, "No credentials yet. Issue a contact card from the issuer and it lands here."),
      lab.issuer ? h("a", { class: "btn btn-primary", href: `${lab.issuer}/` }, "Get one from the issuer") : null));
    return;
  }
  screen.replaceChildren(hd, ...creds.map((c) => card(c, { actions: true })));
}

// ---------- receiving a credential (OpenID4VCI) ----------

const OFFER_STEPS = [
  { who: "wallet", title: "Receive the offer", desc: "The issuer sent you here with credential_offer_uri. The wallet fetches the offer it points to." },
  { who: "wallet", title: "Read the issuer's metadata", desc: "From the issuer's .well-known documents: its endpoints, the credential configuration and how to display it." },
  { who: "wallet", title: "Ask for your consent", desc: "Nothing has been requested from the issuer yet. You decide whether to accept the credential." },
  { who: "wallet", title: "Get an access token", desc: "The wallet exchanges the pre-authorized code from the offer at the token endpoint." },
  { who: "wallet", title: "Prove possession of a new key", desc: "The wallet makes a fresh P-256 key pair for this credential, fetches a c_nonce and signs a proof JWT for the issuer." },
  { who: "issuer", title: "Receive the credential", desc: "The credential endpoint returns the SD-JWT VC, bound to the key from the proof." },
  { who: "wallet", title: "Check and store it", desc: "The wallet verifies the issuer's signature and every disclosure before saving the credential and its key in this browser." },
];

async function offerFlow() {
  const t = startTrace("Receive a credential · OpenID4VCI", "Receiving a credential", OFFER_STEPS);
  let offer, meta, as, config, configId;
  try {
    working("Reading the offer…");
    if (params.get("credential_offer")) offer = JSON.parse(params.get("credential_offer"));
    else if (params.get("credential_offer_uri")) offer = await fetchJson(params.get("credential_offer_uri"));
    else throw new Error("The link has neither credential_offer nor credential_offer_uri.");
    const grant = offer.grants?.[PRE_AUTH_GRANT];
    t.set(0, {
      status: grant ? "ok" : "bad",
      rows: [["credential_issuer", offer.credential_issuer], ["configurations", (offer.credential_configuration_ids || []).join(", ")], ["grant", grant ? "pre-authorized_code" : "none supported", !!grant]],
      code: { label: "Show credential offer", text: pretty(offer) },
    });
    if (!grant) throw new Error("This wallet only supports the pre-authorized code grant.");
    if (grant.tx_code) throw new Error("This offer needs a transaction code (PIN), which this wallet doesn't support yet.");

    meta = await fetchJson(wellKnown(offer.credential_issuer, "openid-credential-issuer"));
    as = await fetchJson(wellKnown(meta.authorization_servers?.[0] || offer.credential_issuer, "oauth-authorization-server"));
    configId = offer.credential_configuration_ids?.[0];
    config = meta.credential_configurations_supported?.[configId];
    const c = checker();
    c.add("credential_issuer", meta.credential_issuer, meta.credential_issuer === offer.credential_issuer);
    c.add("token_endpoint", as.token_endpoint || "missing", !!as.token_endpoint);
    c.add("nonce_endpoint", meta.nonce_endpoint || "missing", !!meta.nonce_endpoint);
    c.add("credential_endpoint", meta.credential_endpoint);
    c.add("format", config?.format || "unknown", config?.format === "dc+sd-jwt");
    c.add("vct", config?.vct || "unknown");
    c.add("proof type", config?.proof_types_supported?.jwt?.proof_signing_alg_values_supported?.includes("ES256") ? "jwt, ES256" : "unsupported", !!config?.proof_types_supported?.jwt?.proof_signing_alg_values_supported?.includes("ES256"));
    t.set(1, { status: c.ok ? "ok" : "bad", rows: c.rows, code: { label: "Show issuer metadata", text: pretty(meta) } });
    if (!c.ok) throw new Error("The issuer's metadata doesn't match what this wallet supports.");
  } catch (e) {
    return offerFailed(t, e);
  }

  const display = config.credential_metadata?.display?.[0] || {};
  const issuerHost = new URL(offer.credential_issuer).host;
  const preview = {
    issuer: offer.credential_issuer,
    issuerName: meta.display?.[0]?.name || issuerHost,
    display: { name: display.name || configId, bg: display.background_color, fg: display.text_color },
    claimLabels: Object.fromEntries((config.credential_metadata?.claims || []).filter((x) => x.path?.length === 1).map((x) => [x.path[0], x.display?.[0]?.name || x.path[0]])),
    claims: {},
  };
  t.set(2, { status: "run" });
  if (!(await askToAccept(preview, issuerHost))) {
    t.set(2, { status: "bad", rows: [["your answer", "declined", "info"]] });
    t.finish("bad", "You turned down the credential");
    screen.replaceChildren(notice("", "Nothing was added.", "The issuer was never asked for the credential."), h("a", { class: "btn btn-quiet", href: "./" }, "Go to your credentials"));
    return;
  }
  t.set(2, { status: "ok", rows: [["your answer", "accepted"]] });
  working("Adding the credential…");

  try {
    const tokenForm = new URLSearchParams({ grant_type: PRE_AUTH_GRANT, "pre-authorized_code": offer.grants[PRE_AUTH_GRANT]["pre-authorized_code"] });
    const token = await fetchJson(as.token_endpoint, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: tokenForm });
    t.set(3, { status: "ok", rows: [["grant_type", "pre-authorized_code"], ["token_type", token.token_type], ["expires_in", `${token.expires_in} s`]] });

    const keyPair = await generateKeyPair();
    const jwk = await exportPublicJwk(keyPair.publicKey);
    const makeProof = async () => {
      const { c_nonce } = await fetchJson(meta.nonce_endpoint, { method: "POST" });
      const header = { typ: "openid4vci-proof+jwt", jwk };
      const payload = { aud: offer.credential_issuer, iat: now(), nonce: c_nonce };
      return { jwt: await signJwt(header, payload, keyPair.privateKey), header: { alg: "ES256", ...header }, payload };
    };
    let proof = await makeProof();
    t.set(4, {
      status: "ok",
      rows: [["key", "new P-256, non-extractable"], ["thumbprint", short(await jwkThumbprint(jwk), 10)], ["c_nonce", short(proof.payload.nonce, 8)], ["aud", proof.payload.aud]],
      code: { label: "Show proof JWT", text: pretty({ header: proof.header, payload: proof.payload }) },
    });

    const askForCredential = (p) => fetchJson(meta.credential_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token.access_token}` },
      body: JSON.stringify({ credential_configuration_id: configId, proofs: { jwt: [p.jwt] } }),
    });
    let res;
    try { res = await askForCredential(proof); } catch (e) {
      if (e.body?.error !== "invalid_nonce") throw e;
      proof = await makeProof(); // the nonce expired between steps: get a fresh one and retry once
      res = await askForCredential(proof);
    }
    const sdJwt = res.credentials?.[0]?.credential;
    if (typeof sdJwt !== "string") throw new Error("The credential response has no credential in it.");
    const parts = split(sdJwt);
    t.set(5, {
      status: "ok",
      rows: [["format", "dc+sd-jwt"], ["issuer-signed JWT", `${parts.jwt.length} characters`], ["disclosures", String(parts.disclosures.length)]],
      code: { label: "Show raw SD-JWT", text: sdJwt.replaceAll("~", "~\n"), wrap: true },
    });

    const checked = await checkCredential(sdJwt, { issuer: offer.credential_issuer, vct: config.vct, jwk });
    t.set(6, { status: checked.ok ? "ok" : "bad", rows: checked.rows, code: checked.payload ? { label: "Show decoded payload", text: pretty(checked.payload) } : null });
    if (!checked.ok) throw new Error("The credential failed a check, so the wallet didn't store it.");

    const record = { ...preview, id: crypto.randomUUID(), format: "dc+sd-jwt", vct: checked.payload.vct, sdJwt, claims: checked.claims, holderKey: keyPair, holderJwk: jwk, issuedAt: Date.now(), exp: checked.payload.exp };
    await store.put(record);
    store.persist();
    t.finish("ok", "Credential stored in your wallet");
    screen.replaceChildren(notice("ok", "Added to your wallet.", `Issued by ${preview.issuerName}.`), card(record), h("a", { class: "btn btn-primary", href: "./" }, "Go to your credentials"));
  } catch (e) {
    offerFailed(t, e);
  }
}

function askToAccept(preview, host) {
  return new Promise((resolve) => {
    screen.replaceChildren(h("section", { class: "panel" }, h("div", { class: "panel-bd" },
      h("div", { class: "who-asks" }, h("div", { class: "avatar", "aria-hidden": "true" }, preview.issuerName[0].toUpperCase()),
        h("div", {}, h("strong", {}, preview.issuerName), h("span", { class: "hint" }, `${host} wants to give you a credential`))),
      card(preview, { preview: true, values: false }),
      h("p", { class: "hint" }, "Each detail is stored as a separate disclosure, so you can later share just one of them."),
      h("div", { class: "row" },
        h("button", { class: "btn btn-quiet", type: "button", onclick: () => resolve(false) }, "Cancel"),
        h("button", { class: "btn btn-primary", type: "button", id: "accept", onclick: () => resolve(true) }, "Add to wallet")))));
  });
}

async function checkCredential(sdJwt, { issuer, vct, jwk }) {
  const c = checker();
  let payload = null, claims = {};
  try {
    const { jwt, disclosures } = split(sdJwt);
    const decoded = decodeJwt(jwt);
    payload = decoded.payload;
    c.add("typ", decoded.header.typ, decoded.header.typ === "dc+sd-jwt");
    c.add("iss", payload.iss, payload.iss === issuer);
    c.add("vct", payload.vct, payload.vct === vct);
    let keys = [];
    try {
      const m = await fetchJson(wellKnown(payload.iss, "jwt-vc-issuer"));
      if (m.issuer === payload.iss) keys = m.jwks?.keys || [];
    } catch { /* reported below */ }
    const key = keys.find((k) => k.kid === decoded.header.kid);
    let sigOk = false;
    if (key) { try { await verifyJwt(jwt, key); sigOk = true; } catch { /* invalid */ } }
    c.add("signature", sigOk ? "valid, key from jwt-vc-issuer" : key ? "invalid" : "issuer key not found", sigOk);
    const resolved = await resolveClaims(payload, disclosures);
    claims = resolved.claims;
    c.add("disclosures", `${resolved.details.length} matched digests in _sd`, resolved.details.length === disclosures.length);
    const cnf = payload.cnf?.jwk;
    c.add("cnf.jwk", cnf && cnf.x === jwk.x && cnf.y === jwk.y ? "this credential's new key" : "a different key", !!cnf && cnf.x === jwk.x && cnf.y === jwk.y);
    c.add("exp", payload.exp ? fmtDate(payload.exp) : "none", !payload.exp || payload.exp > now());
  } catch (e) {
    c.add("error", e.message, false);
  }
  return { ok: c.ok, rows: c.rows, payload, claims };
}

function offerFailed(t, e) {
  t.fail(e);
  t.finish("bad", "Couldn't add the credential");
  screen.replaceChildren(notice("bad", "Couldn't add the credential.", e.message), h("a", { class: "btn btn-quiet", href: "./" }, "Go to your credentials"));
}

// ---------- sharing a credential (OpenID4VP) ----------

const AUTH_STEPS = [
  { who: "wallet", title: "Read the request", desc: "The verifier sent you here with an OpenID4VP authorization request. It is unsigned, so the verifier is identified only by its response URI (client_id prefix redirect_uri:)." },
  { who: "wallet", title: "Match the DCQL query", desc: "The wallet looks for stored credentials with the requested format, type and claims." },
  { who: "wallet", title: "Ask for your consent", desc: "You see exactly which details would be shared. Nothing leaves the wallet unless you agree." },
  { who: "wallet", title: "Build the presentation", desc: "Only the disclosures for the requested claims go in. A Key Binding JWT, signed with the credential's key, ties them to this verifier and this request's nonce." },
  { who: "wallet", title: "Send it to the verifier", desc: "The wallet POSTs vp_token and state to the response URI (response mode direct_post), then follows the redirect the verifier returns." },
];

async function authorizeFlow() {
  const t = startTrace("Share a credential · OpenID4VP", "Answering a request", AUTH_STEPS);
  const req = Object.fromEntries(params);
  let dcql, responseUri;
  try {
    if (req.request_uri) throw new Error("Signed requests (request_uri) aren't supported by this wallet yet.");
    const c = checker();
    c.add("response_type", req.response_type || "missing", req.response_type === "vp_token");
    c.add("response_mode", req.response_mode || "missing", req.response_mode === "direct_post");
    try { responseUri = new URL(req.response_uri); } catch { responseUri = null; }
    const local = responseUri && ["localhost", "127.0.0.1"].includes(responseUri.hostname);
    c.add("response_uri", req.response_uri || "missing", !!responseUri && (responseUri.protocol === "https:" || local));
    c.add("client_id", req.client_id || "missing", req.client_id === `redirect_uri:${req.response_uri}`);
    c.add("nonce", req.nonce ? short(req.nonce, 8) : "missing", !!req.nonce);
    c.add("state", req.state ? short(req.state, 8) : "missing", !!req.state);
    try {
      dcql = validateQuery(JSON.parse(req.dcql_query || "null"));
      if (dcql.credentials.length !== 1) throw new Error("This wallet answers one credential query at a time");
      c.add("dcql_query", `1 credential query: ${dcql.credentials[0].id}`, true);
    } catch (e) { c.add("dcql_query", e.message, false); }
    let cm = {};
    try { cm = req.client_metadata ? JSON.parse(req.client_metadata) : {}; } catch { c.add("client_metadata", "not valid JSON", false); }
    const fmt = cm.vp_formats_supported?.["dc+sd-jwt"];
    c.add("vp_formats_supported", fmt ? `dc+sd-jwt, KB-JWT ${(fmt["kb-jwt_alg_values"] || ["any"]).join("/")}` : "not given", fmt ? !fmt["kb-jwt_alg_values"] || fmt["kb-jwt_alg_values"].includes("ES256") : "info");
    t.set(0, { status: c.ok ? "ok" : "bad", rows: c.rows, code: { label: "Show request", text: pretty({ ...req, dcql_query: dcql || req.dcql_query, client_metadata: cm }) } });
    if (!c.ok) throw new Error("The request is malformed, so the wallet won't answer it.");
  } catch (e) {
    t.fail(e);
    t.finish("bad", "Couldn't read the request");
    screen.replaceChildren(notice("bad", "This request can't be answered.", e.message), h("a", { class: "btn btn-quiet", href: "./" }, "Go to your credentials"));
    return;
  }

  let creds = [];
  try { creds = await store.all(); } catch { /* treated as empty */ }
  const q = match(dcql, creds)[0];
  const requested = q.query.claims ? q.requested : null; // no claims = the whole credential
  t.set(1, {
    status: q.matches.length ? "ok" : "bad",
    rows: [["query id", q.id], ["format", q.query.format], ["vct_values", (q.query.meta?.vct_values || ["any"]).join(", ")], ["claims", requested ? requested.map(claimLabel).join(", ") : "all"], ["matches", `${q.matches.length} of ${creds.length} stored`, q.matches.length > 0]],
  });

  t.set(2, { status: "run" });
  const answer = await askToShare({ host: responseUri.host, responseUri: req.response_uri, matches: q.matches, requested });
  if (!answer) {
    t.set(2, { status: "bad", rows: [["your answer", q.matches.length ? "declined" : "declined, no matching credential", "info"]] });
    return respond(t, req, new URLSearchParams({ error: "access_denied", error_description: "The user declined to share a credential", state: req.state }), 4, false);
  }
  const cred = answer;
  const reveal = requested || Object.keys(cred.claims);
  const withheld = Object.keys(cred.claims).filter((n) => !reveal.includes(n));
  t.set(2, { status: "ok", rows: [["shared", reveal.map(claimLabel).join(", ")], ["kept private", withheld.length ? withheld.map(claimLabel).join(", ") : "nothing"]] });
  working("Sending…");

  try {
    const { presentation, kbPayload, disclosed } = await present({ sdJwt: cred.sdJwt, reveal, holderKey: cred.holderKey.privateKey, aud: req.client_id, nonce: req.nonce });
    const vpToken = { [q.id]: [presentation] };
    t.set(3, {
      status: "ok",
      rows: [["disclosures", disclosed.map((d) => claimLabel(d.name)).join(", ")], ["left out", `${withheld.length} disclosure${withheld.length === 1 ? "" : "s"}`], ["KB-JWT aud", kbPayload.aud], ["KB-JWT nonce", short(kbPayload.nonce, 8)], ["sd_hash", short(kbPayload.sd_hash, 8)]],
      code: { label: "Show vp_token and KB-JWT", text: `${pretty(vpToken)}\n\nKB-JWT payload:\n${pretty(kbPayload)}`, wrap: true },
    });
    await respond(t, req, new URLSearchParams({ vp_token: JSON.stringify(vpToken), state: req.state }), 4, true);
  } catch (e) {
    t.fail(e);
    t.finish("bad", "Couldn't share the credential");
    screen.replaceChildren(notice("bad", "Couldn't share the credential.", e.message));
  }
}

async function respond(t, req, body, stepIndex, shared) {
  const host = new URL(req.response_uri).host;
  try {
    const res = await fetchJson(req.response_uri, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body });
    let next = null;
    try { next = res?.redirect_uri ? new URL(res.redirect_uri) : null; } catch { /* ignore */ }
    if (next && !/^https?:$/.test(next.protocol)) next = null;
    t.set(stepIndex, { status: "ok", rows: [["sent", shared ? "vp_token, state" : "error=access_denied, state"], ["redirect_uri", next ? next.href.replace(/#.*/, "#response_code=…") : "none"]] });
    t.finish(shared ? "ok" : "bad", shared ? `Shared with ${host}` : `You declined ${host}'s request`);
    screen.replaceChildren(
      notice(shared ? "ok" : "", shared ? "Shared." : "Declined.", next ? `Returning you to ${next.host}…` : `${host} has your answer.`),
      next ? h("a", { class: "btn btn-quiet", href: next.href }, `Go back to ${next.host}`) : h("a", { class: "btn btn-quiet", href: "./" }, "Go to your credentials"));
    if (next) setTimeout(() => location.assign(next.href), 1200);
  } catch (e) {
    t.fail(e);
    t.finish("bad", `Couldn't reach ${host}`);
    screen.replaceChildren(notice("bad", `Couldn't reach ${host}.`, e.message));
  }
}

function askToShare({ host, responseUri, matches, requested }) {
  return new Promise((resolve) => {
    let chosen = matches[0];
    const list = h("ul", { class: "share-list" });
    const drawList = () => {
      const names = Object.keys(chosen.claims);
      const on = (n) => !requested || requested.includes(n);
      list.replaceChildren(...[...names.filter(on), ...names.filter((n) => !on(n))].map((n) => h("li", { class: on(n) ? "on" : "off" },
        h("span", { class: "ico", "aria-hidden": "true" }, on(n) ? "✓" : ""),
        h("div", {}, h("div", { class: "lbl" }, chosen.claimLabels?.[n] || claimLabel(n)), h("div", { class: "val" }, on(n) ? chosen.claims[n] : "Not shared")),
        h("span", { class: "tag" }, on(n) ? "shared" : "private"))));
    };
    const header = h("div", { class: "who-asks" }, h("div", { class: "avatar", "aria-hidden": "true" }, host[0].toUpperCase()),
      h("div", {}, h("strong", {}, host), h("span", { class: "hint" }, matches.length ? "wants to see details from your contact card" : "asked for a credential you don't have")));
    const unverified = h("p", { class: "hint" }, h("span", { class: "badge warn" }, "Unverified"), ` The request isn't signed, so the wallet can't confirm who sent it. It only knows the answer goes to ${responseUri}.`);

    if (!matches.length) {
      screen.replaceChildren(h("section", { class: "panel" }, h("div", { class: "panel-bd" }, header, unverified,
        notice("bad", "No matching credential.", requested ? `It needs a contact card with ${requested.map(claimLabel).join(", ")}.` : "It needs a contact card."),
        lab.issuer ? h("a", { href: `${lab.issuer}/` }, "Get a contact card from the issuer") : null,
        h("div", { class: "row" }, h("button", { class: "btn btn-quiet", type: "button", id: "decline", onclick: () => resolve(null) }, "Decline")))));
      return;
    }
    const picker = matches.length > 1 ? h("fieldset", { class: "pick", style: "border:0;padding:0;margin:0" },
      h("legend", { class: "label", style: "margin-bottom:8px" }, "Share from"),
      matches.map((m, i) => h("label", {}, h("input", { type: "radio", name: "cred", checked: i === 0, onchange: () => { chosen = m; drawList(); } }),
        `${m.claims.name || m.display?.name} · issued ${new Date(m.issuedAt).toLocaleString()}`))) : null;
    drawList();
    screen.replaceChildren(h("section", { class: "panel" }, h("div", { class: "panel-bd" }, header, unverified, picker, list,
      h("div", { class: "row" },
        h("button", { class: "btn btn-quiet", type: "button", id: "decline", onclick: () => resolve(null) }, "Decline"),
        h("button", { class: "btn btn-primary", type: "button", id: "share", onclick: () => resolve(chosen) }, "Share")))));
  });
}

// ---------- boot ----------

lab = await labBar("wallet");
if (page === "offer") offerFlow();
else if (page === "authorize") authorizeFlow();
else home();
