// Response helpers shared by the issuer and verifier handlers.

export function json(body, headers = {}, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
}

export function error(status, code, description, headers = {}) {
  return json({ error: code, error_description: description }, headers, status);
}

// The wallet is a browser app on another origin, so endpoints it calls need CORS. No cookies are involved.
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Authorization, Content-Type, DPoP",
  "Access-Control-Expose-Headers": "WWW-Authenticate",
};

export function cors(res) {
  for (const [k, v] of Object.entries(CORS)) res.headers.set(k, v);
  return res;
}

export const preflight = () => cors(new Response(null, { status: 204, headers: { "Access-Control-Max-Age": "600" } }));

export async function readForm(req) {
  const type = req.headers.get("content-type") || "";
  if (!type.startsWith("application/x-www-form-urlencoded")) return new URLSearchParams();
  return new URLSearchParams(await req.text());
}

// Tiny router: routes is { "METHOD /path/:param": (req, params) => Response }. Returns null when nothing matches.
export function route(routes, req) {
  if (req.method === "OPTIONS") return preflight();
  const path = new URL(req.url).pathname;
  for (const [key, fn] of Object.entries(routes)) {
    const [method, pattern] = key.split(" ");
    if (method !== req.method) continue;
    const params = matchPath(pattern, path);
    if (params) return fn(req, params);
  }
  return null;
}

function matchPath(pattern, path) {
  const p = pattern.split("/"), a = path.split("/");
  if (p.length !== a.length) return null;
  const params = {};
  for (let i = 0; i < p.length; i++) {
    if (p[i].startsWith(":")) params[p[i].slice(1)] = decodeURIComponent(a[i]);
    else if (p[i] !== a[i]) return null;
  }
  return params;
}
