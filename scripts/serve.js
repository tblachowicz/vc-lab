// Runs the issuer, wallet and verifier locally, each on its own origin.
//   node scripts/serve.js
// Override the public URLs (and so the ports) with ISSUER_URL, WALLET_URL, VERIFIER_URL.
import { createServer } from "node:http";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { extname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { createIssuer } from "../issuer/server.js";
import { createVerifier } from "../verifier/server.js";
import { generateKeyPair, importPrivateJwk, importPublicJwk } from "../lib/jose.js";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".json": "application/json", ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon", ".webmanifest": "application/manifest+json" };

export async function loadIssuerKey(file = join(ROOT, ".keys", "issuer.jwk.json")) {
  let jwk;
  try {
    jwk = JSON.parse(await readFile(file, "utf8"));
  } catch {
    const pair = await generateKeyPair({ extractable: true });
    jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
    await mkdir(join(file, ".."), { recursive: true });
    await writeFile(file, JSON.stringify(jwk, null, 2), { mode: 0o600 });
    console.log(`Generated a new issuer signing key in ${file}`);
  }
  const { kty, crv, x, y } = jwk;
  return { privateKey: await importPrivateJwk(jwk), publicKey: await importPublicJwk({ kty, crv, x, y }) };
}

// Static files: the app's own folder, plus the shared /lib and /ui folders.
async function serveStatic(dir, pathname) {
  let base = dir, rel = pathname;
  if (pathname.startsWith("/lib/")) { base = join(ROOT, "lib"); rel = pathname.slice(4); }
  else if (pathname.startsWith("/ui/")) { base = join(ROOT, "ui"); rel = pathname.slice(3); }
  const candidates = rel.endsWith("/") ? [rel + "index.html"] : extname(rel) ? [rel] : [rel + ".html", rel + "/index.html"];
  for (const c of candidates) {
    const file = normalize(join(base, decodeURIComponent(c)));
    if (!file.startsWith(base + sep)) continue;
    try {
      if (!(await stat(file)).isFile()) continue;
      return new Response(await readFile(file), { headers: { "Content-Type": TYPES[extname(file)] || "application/octet-stream", "Cache-Control": "no-cache" } });
    } catch { /* try next */ }
  }
  return new Response("Not found", { status: 404, headers: { "Content-Type": "text/plain" } });
}

function listen(port, handler) {
  const server = createServer(async (req, res) => {
    try {
      const host = req.headers.host || `localhost:${port}`;
      const body = req.method === "GET" || req.method === "HEAD" ? undefined : await new Promise((ok, fail) => {
        const chunks = []; req.on("data", (c) => chunks.push(c)); req.on("end", () => ok(Buffer.concat(chunks))); req.on("error", fail);
      });
      const request = new Request(`http://${host}${req.url}`, { method: req.method, headers: req.headers, body });
      const response = await handler(request);
      res.writeHead(response.status, Object.fromEntries(response.headers));
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch (e) {
      console.error(e);
      res.writeHead(500, { "Content-Type": "text/plain" }).end("Internal error");
    }
  });
  return new Promise((ok) => server.listen(port, () => ok(server)));
}

export async function start({
  issuerUrl = process.env.ISSUER_URL || "http://localhost:3001",
  walletUrl = process.env.WALLET_URL || "http://localhost:3002",
  verifierUrl = process.env.VERIFIER_URL || "http://localhost:3003",
  keyFile,
} = {}) {
  const issuer = await createIssuer({ issuerUrl, walletUrl, signingKey: await loadIssuerKey(keyFile) });
  const verifier = createVerifier({ verifierUrl, walletUrl, trustedIssuers: [issuerUrl] });
  const port = (u) => Number(new URL(u).port) || 80;
  // Every origin serves /lab.json so the UIs can link to each other.
  const lab = JSON.stringify({ issuer: issuerUrl, wallet: walletUrl, verifier: verifierUrl });
  const files = (dir) => (r) => {
    const { pathname } = new URL(r.url);
    if (pathname === "/lab.json") return new Response(lab, { headers: { "Content-Type": "application/json" } });
    return serveStatic(dir, pathname);
  };
  const servers = await Promise.all([
    listen(port(issuerUrl), async (r) => (await issuer.handle(r)) || files(join(ROOT, "issuer", "public"))(r)),
    listen(port(walletUrl), files(join(ROOT, "wallet"))),
    listen(port(verifierUrl), async (r) => (await verifier.handle(r)) || files(join(ROOT, "verifier", "public"))(r)),
  ]);
  return { issuerUrl, walletUrl, verifierUrl, close: () => Promise.all(servers.map((s) => new Promise((ok) => s.close(ok)))) };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { issuerUrl, walletUrl, verifierUrl } = await start();
  console.log(`VC Lab is running:\n  Issuer    ${issuerUrl}\n  Wallet    ${walletUrl}\n  Verifier  ${verifierUrl}`);
}
