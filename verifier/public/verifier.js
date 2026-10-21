import { $, fetchJson, h, labBar, pretty, renderTrace, short } from "./ui/lab.js";
import { CLAIMS, claimLabel } from "./lib/contact.js";

const KEY = "vc-lab-verifier:tx";
const trace = $("#trace");

const REQUEST_STEP = { who: "verifier", title: "Send the request to the wallet", desc: "A fresh nonce and state, a DCQL query naming the claims, and where to POST the answer. The browser carries it to the wallet's authorization endpoint." };
const CHECK_STEPS = [
  { who: "verifier", title: "Read the response", desc: "The wallet POSTs vp_token and state to the response URI." },
  { who: "verifier", title: "Check the issuer's signature", desc: "The credential must come from a trusted issuer, signed with a key from its JWT VC Issuer Metadata." },
  { who: "verifier", title: "Match the disclosures", desc: "Each disclosure must hash to a digest the issuer signed. Only requested claims should be there." },
  { who: "verifier", title: "Check key binding", desc: "The KB-JWT must be signed by the credential's holder key, for this verifier and this nonce." },
];

function requestStep(request, status) {
  const q = request.dcql_query.credentials[0];
  return {
    ...REQUEST_STEP, status,
    rows: [["client_id", request.client_id], ["response_mode", request.response_mode], ["claims", q.claims.map((c) => claimLabel(c.path[0])).join(", ")], ["nonce", short(request.nonce, 8)], ["state", short(request.state, 8)]],
    code: { label: "Show DCQL query", text: pretty(request.dcql_query) },
  };
}

function render(tx) {
  if (!tx) {
    renderTrace(trace, { eyebrow: "Presentation · OpenID4VP", heading: "What happens when you request a credential", state: "", steps: [REQUEST_STEP, ...CHECK_STEPS] });
    return;
  }
  if (tx.status === "pending") {
    renderTrace(trace, { eyebrow: "Presentation · OpenID4VP", heading: "Waiting for the wallet", state: "run", steps: [requestStep(tx.request, "ok"), { ...CHECK_STEPS[0], status: "run" }, ...CHECK_STEPS.slice(1)] });
    return;
  }
  if (tx.status === "declined") {
    renderTrace(trace, {
      eyebrow: "Presentation · OpenID4VP", heading: "The wallet declined", state: "bad",
      steps: [requestStep(tx.request, "ok"), { ...CHECK_STEPS[0], status: "bad", rows: [["error", tx.wallet_error.error, "info"], ["description", tx.wallet_error.error_description || "none"]] }],
    });
    return;
  }
  const steps = [requestStep(tx.request, "ok"), ...tx.steps.map((s) => ({ ...s, code: s.code ? { ...s.code, wrap: true } : null }))];
  for (const s of CHECK_STEPS.slice(tx.steps.length)) steps.push({ ...s, status: "wait" });
  renderTrace(trace, { eyebrow: "Presentation · OpenID4VP", heading: tx.status === "verified" ? "Credential verified" : "Credential rejected", state: tx.status === "verified" ? "ok" : "bad", steps });
}

function showResult(tx) {
  const box = $("#result");
  if (!tx || tx.status === "pending") { box.hidden = true; return; }
  box.hidden = false;
  if (tx.status === "declined") {
    box.replaceChildren(h("div", { class: "panel-bd" }, h("p", { class: "notice" }, h("strong", {}, "You declined in the wallet."), " Nothing was shared.")));
    return;
  }
  if (tx.status !== "verified") {
    box.replaceChildren(h("div", { class: "panel-bd" }, h("p", { class: "notice bad" }, h("strong", {}, "The presentation failed a check."), " The trace shows which one.")));
    return;
  }
  const notAsked = CLAIMS.filter((c) => !tx.claims.includes(c.name));
  box.replaceChildren(h("div", { class: "panel-hd" }, h("h2", {}, "Received and verified"), h("span", { class: "eyebrow" }, `${tx.claims.length} of ${CLAIMS.length} claims`)),
    h("div", { class: "panel-bd" },
      h("dl", { class: "result-claims" },
        tx.claims.map((n) => h("div", {}, h("dt", {}, claimLabel(n)), h("dd", {}, tx.result[n]))),
        notAsked.map((c) => h("div", { class: "withheld" }, h("dt", {}, c.label), h("dd", {}, "Not requested, so never left the wallet"))))));
}

async function load() {
  let saved = null;
  try { saved = JSON.parse(sessionStorage.getItem(KEY) || "null"); } catch { /* ignore */ }
  const fromHash = new URLSearchParams(location.hash.slice(1)).get("response_code");
  if (fromHash && saved) {
    saved.response_code = fromHash;
    try { sessionStorage.setItem(KEY, JSON.stringify(saved)); } catch { /* ignore */ }
    history.replaceState(null, "", location.pathname);
  }
  if (!saved) return render(null);
  try {
    const q = saved.response_code ? `?response_code=${encodeURIComponent(saved.response_code)}` : "";
    const tx = await fetchJson(`./api/requests/${saved.id}${q}`);
    render(tx);
    showResult(tx);
    for (const c of CLAIMS) { const box = $(`#form input[value="${c.name}"]`); if (box) box.checked = tx.claims.includes(c.name); }
  } catch (e) {
    try { sessionStorage.removeItem(KEY); } catch { /* ignore */ }
    render(null);
    if (e.status !== 404) $("#form-msg").replaceChildren(h("p", { class: "notice bad" }, h("strong", {}, "Couldn't load the last result."), ` ${e.message}`));
  }
}

$("#form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const claims = [...document.querySelectorAll("#form input[type=checkbox]:checked")].map((i) => i.value);
  if (!claims.length) {
    $("#form-msg").replaceChildren(h("p", { class: "notice bad" }, h("strong", {}, "Nothing to request."), " Tick at least one claim."));
    return;
  }
  $("#form-msg").replaceChildren();
  const btn = $("#request"); btn.disabled = true;
  try {
    const res = await fetchJson("./api/requests", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ claims }) });
    try { sessionStorage.setItem(KEY, JSON.stringify({ id: res.id })); } catch { /* the result can't be shown after the redirect */ }
    render({ status: "pending", request: res.request });
    $("#result").hidden = true;
    location.assign(res.wallet_url);
  } catch (e) {
    btn.disabled = false;
    $("#form-msg").replaceChildren(h("p", { class: "notice bad" }, h("strong", {}, "Couldn't create the request."), ` ${e.message}`));
  }
});

labBar("verifier");
load();
