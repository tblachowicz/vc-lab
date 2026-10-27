// Shared browser helpers: DOM builder, lab bar, protocol trace renderer.

export function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat(Infinity)) if (kid != null && kid !== false) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return el;
}

export const $ = (s, root = document) => root.querySelector(s);
export const short = (s, n = 12) => (s = String(s), s.length > n * 2 + 1 ? `${s.slice(0, n)}…${s.slice(-n)}` : s);
export const pretty = (o) => JSON.stringify(o, null, 2);

// Links between the three apps. /lab.json is written by the host (dev server or deploy step).
export async function labBar(current) {
  const bar = $("#labbar");
  if (!bar) return {};
  let urls = {};
  try { urls = await (await fetch("./lab.json", { cache: "no-store" })).json(); } catch { /* standalone */ }
  const apps = [["issuer", "Issuer"], ["wallet", "Wallet"], ["verifier", "Verifier"]];
  bar.replaceChildren(
    urls.home ? h("a", { class: "lab-name", href: `${urls.home}/` }, "VC Lab") : h("span", { class: "lab-name" }, "VC Lab"),
    h("nav", { "aria-label": "Lab apps" }, apps.filter(([k]) => urls[k] || k === current).map(([k, label]) =>
      h("a", { href: k === current ? "./" : `${urls[k]}/`, "aria-current": k === current ? "page" : null }, h("span", { class: `pip ${k}` }), label))));
  return urls;
}

export function verdict(v) {
  if (v === true) return h("span", { class: "verdict ok" }, "ok");
  if (v === false) return h("span", { class: "verdict bad" }, "fail");
  if (typeof v === "string") return h("span", { class: "verdict info" }, v);
  return null;
}

export function kv(rows) {
  return h("dl", { class: "kv" }, rows.filter(Boolean).flatMap(([k, val, v]) => [h("dt", {}, k), h("dd", {}, h("span", { class: "v" }, val), verdict(v))]));
}

export function raw(label, text, { wrap = false } = {}) {
  return h("details", { class: "raw" }, h("summary", {}, label), h("pre", { class: `code${wrap ? " wrap" : ""}` }, text));
}

// steps: [{ title, who, desc, status: ok|bad|run|wait, rows?, code?: {label, text}, body?: [nodes] }]
export function renderTrace(root, { eyebrow, heading, state, steps }) {
  $(".trace-eyebrow", root).textContent = eyebrow;
  $(".trace-heading", root).textContent = heading;
  const pill = $(".status-pill", root);
  pill.className = `status-pill${state ? ` ${state}` : ""}`;
  pill.textContent = { ok: "done", bad: "failed", run: "in progress" }[state] || "waiting";
  $(".steps", root).replaceChildren(...steps.map((s, i) => h("li", { class: `step ${s.status || "wait"}` },
    h("div", { class: "node", "aria-hidden": "true" }, s.status === "ok" ? "✓" : s.status === "bad" ? "✕" : String(i + 1)),
    h("div", { class: "step-body" },
      h("div", { class: "step-title" }, h("h3", {}, s.title), s.who ? h("span", { class: `who ${s.who}` }, s.who) : null),
      s.desc ? h("p", { class: "step-desc" }, s.desc) : null,
      s.rows?.length ? kv(s.rows) : null,
      ...(s.body || []),
      s.code ? raw(s.code.label, s.code.text, s.code) : null))));
}

export async function fetchJson(url, init) {
  const res = await fetch(url, init);
  let body = null;
  try { body = await res.json(); } catch { /* not JSON */ }
  if (!res.ok) {
    const msg = body?.error_description || body?.error || `HTTP ${res.status}`;
    throw Object.assign(new Error(msg), { status: res.status, body });
  }
  return body;
}

