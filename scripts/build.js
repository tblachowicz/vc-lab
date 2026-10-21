// Builds the static parts of each app into dist/<app>/, with lib/, ui/ and a lab.json naming all three URLs.
//   ISSUER_URL=… WALLET_URL=… VERIFIER_URL=… node scripts/build.js
import { cp, mkdir, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const urls = { issuer: process.env.ISSUER_URL, wallet: process.env.WALLET_URL, verifier: process.env.VERIFIER_URL };
for (const [k, v] of Object.entries(urls)) if (!/^https?:\/\/[^/]+(\/.*)?$/.test(v || "")) throw new Error(`Set ${k.toUpperCase()}_URL to the app's public URL`);
for (const k of Object.keys(urls)) urls[k] = urls[k].replace(/\/$/, "");

const apps = { issuer: "issuer/public", verifier: "verifier/public", wallet: "wallet" };
await rm(join(ROOT, "dist"), { recursive: true, force: true });
for (const [app, src] of Object.entries(apps)) {
  const out = join(ROOT, "dist", app);
  await mkdir(out, { recursive: true });
  await cp(join(ROOT, src), out, { recursive: true });
  await cp(join(ROOT, "lib"), join(out, "lib"), { recursive: true });
  await cp(join(ROOT, "ui"), join(out, "ui"), { recursive: true });
  await writeFile(join(out, "lab.json"), JSON.stringify(urls));
}
await writeFile(join(ROOT, "dist", "wallet", ".nojekyll"), "");
console.log("Built dist/ for", urls);
