import { $, fetchJson, h, labBar, pretty, renderTrace, short } from "./ui/lab.js";
import { CLAIMS, claimLabel } from "./lib/contact.js";

const KEY = "vc-lab-issuer:offer";
const STEPS = [
  { who: "issuer", title: "Create a credential offer", desc: "The issuer keeps your details and creates a single-use pre-authorized code. The offer names the issuer and the credential configuration to request." },
  { who: "issuer", title: "Hand the offer to the wallet", desc: "The offer travels by reference: a URL to the wallet's credential offer endpoint, carrying credential_offer_uri. The wallet fetches the offer from there." },
  { who: "wallet", title: "Redeem the code for an access token", desc: "The wallet posts the pre-authorized code to the token endpoint. The code works once." },
  { who: "wallet", title: "Prove possession of a key", desc: "The wallet gets a fresh c_nonce, makes a new key pair and signs a proof JWT with it. The issuer checks the signature, the audience and the nonce." },
  { who: "issuer", title: "Sign and deliver the credential", desc: "Each claim becomes a salted disclosure. The issuer signs only their digests, plus cnf.jwk, which binds the credential to the wallet's key." },
];

const trace = $("#trace");
let timer = null;

function render(offer, events = []) {
  const steps = STEPS.map((s) => ({ ...s }));
  const seen = (name) => events.find((e) => e.step === name);
  let state = "";
  if (offer) {
    state = "run";
    steps[0] = { ...steps[0], status: "ok", rows: [["offer id", offer.id], ["pre-authorized code", short(offer.credential_offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"], 8)], ["configuration", offer.credential_offer.credential_configuration_ids.join(", ")]], code: { label: "Show credential offer", text: pretty(offer.credential_offer) } };
    steps[1] = { ...steps[1], status: seen("offer_fetched") ? "ok" : "run", rows: [["credential_offer_uri", offer.offer_uri], ["fetched by wallet", seen("offer_fetched") ? "yes" : "not yet"]], code: { label: "Show wallet URL", text: offer.wallet_link, wrap: true } };
    if (seen("token_issued")) steps[2] = { ...steps[2], status: "ok", rows: [["grant_type", "pre-authorized_code"], ["token_type", "Bearer"]] };
    const proof = seen("proof_verified"), rejected = seen("proof_rejected");
    if (proof) steps[3] = { ...steps[3], status: "ok", rows: [["proof typ", "openid4vci-proof+jwt"], ["holder key", `P-256 x=${short(proof.holder_key.x, 8)}`], ["nonce", "fresh, now spent"]] };
    else if (rejected) { steps[3] = { ...steps[3], status: "bad", rows: [["rejected", rejected.reason, false]] }; state = "bad"; }
    const issued = seen("credential_issued");
    if (issued) {
      steps[4] = { ...steps[4], status: "ok", rows: issued.disclosures.map((d) => [claimLabel(d.name), `digest ${short(d.digest, 8)}`]) };
      state = "ok";
    }
  }
  renderTrace(trace, {
    eyebrow: "Issuance · OpenID4VCI",
    heading: !offer ? "What happens when you issue a credential" : state === "ok" ? "Credential delivered to the wallet" : state === "bad" ? "The wallet's proof was rejected" : "Waiting for the wallet",
    state, steps,
  });
  return state;
}

function showHandoff(offer) {
  $("#handoff").hidden = false;
  const u = new URL(offer.wallet_link);
  $("#offer-url").replaceChildren(h("b", {}, `${u.origin}${u.pathname}`), `?credential_offer_uri=${encodeURIComponent(offer.offer_uri)}`);
  $("#open-wallet").href = offer.wallet_link;
}

async function poll(offer) {
  clearTimeout(timer);
  try {
    const { events } = await fetchJson(`./api/offers/${offer.id}/events`);
    const state = render(offer, events);
    if (state === "ok" || state === "bad") return;
  } catch (e) {
    if (e.status === 404) { sessionStorage.removeItem(KEY); render(null); $("#handoff").hidden = true; return; }
  }
  timer = setTimeout(() => poll(offer), document.hidden ? 5000 : 1500);
}

$("#form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const body = Object.fromEntries(CLAIMS.map(({ name }) => [name, $(`#${name}`).value.trim()]));
  const missing = CLAIMS.find(({ name }) => !body[name]);
  if (missing) {
    $("#form-msg").replaceChildren(h("p", { class: "notice bad" }, h("strong", {}, `${missing.label} is empty.`), " Fill in all three fields."));
    $(`#${missing.name}`).focus();
    return;
  }
  $("#form-msg").replaceChildren();
  const btn = $("#issue"); btn.disabled = true;
  try {
    const offer = await fetchJson("./api/offers", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    try { sessionStorage.setItem(KEY, JSON.stringify(offer)); } catch { /* private mode */ }
    showHandoff(offer);
    render(offer);
    poll(offer);
    $("#open-wallet").focus();
  } catch (e) {
    $("#form-msg").replaceChildren(h("p", { class: "notice bad" }, h("strong", {}, "Couldn't create the offer."), ` ${e.message}`));
  } finally {
    btn.disabled = false;
  }
});

labBar("issuer");
let saved = null;
try { saved = JSON.parse(sessionStorage.getItem(KEY) || "null"); } catch { /* ignore */ }
render(saved);
if (saved) { showHandoff(saved); poll(saved); }
