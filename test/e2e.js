// Browser end-to-end test: issuer → wallet → verifier in headless Chromium, three origins.
//   npm run e2e            (needs the playwright package; SHOTS=dir saves screenshots)
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chromium } from "playwright";
import { start } from "../scripts/serve.js";

// Against the local Node servers by default. With E2E_ISSUER_URL, E2E_WALLET_URL and E2E_VERIFIER_URL set,
// it tests already-running apps instead (e.g. `wrangler dev` workers and a built wallet).
const external = !!process.env.E2E_ISSUER_URL;
const urls = external
  ? { homeUrl: process.env.E2E_HOME_URL, issuerUrl: process.env.E2E_ISSUER_URL, walletUrl: process.env.E2E_WALLET_URL, verifierUrl: process.env.E2E_VERIFIER_URL }
  : { homeUrl: "http://localhost:4200", issuerUrl: "http://localhost:4201", walletUrl: "http://localhost:4202", verifierUrl: "http://localhost:4203" };
const shots = process.env.SHOTS;
const lab = external ? { close: async () => {} } : await start({ ...urls, keyFile: join(await mkdtemp(join(tmpdir(), "vclab-")), "k.json") });
const browser = await chromium.launch(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {});
const page = await browser.newPage({ viewport: { width: 1280, height: 1000 } });
const errors = [];
page.on("pageerror", (e) => errors.push(e.message));
page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
const shot = async (name) => { if (shots) await page.screenshot({ path: join(shots, `${name}.png`), fullPage: true }); };
const pill = () => page.locator("#trace .status-pill").textContent();
const assert = (cond, msg) => { if (!cond) throw new Error(`FAIL: ${msg}`); console.log(`ok  ${msg}`); };

try {
  // Home page links to the three apps
  if (urls.homeUrl) {
    await page.goto(`${urls.homeUrl}/`);
    await page.waitForSelector('a[data-app="issuer"][href]');
    await shot("0-home");
    await page.click('a[data-app="issuer"]');
    await page.waitForURL(`${urls.issuerUrl}/`);
    assert(true, "home page links to the issuer");
  }

  // Issue
  await page.goto(`${urls.issuerUrl}/`);
  await page.fill("#name", "Grace Hopper");
  await page.fill("#email", "grace@example.org");
  await page.fill("#phone_number", "+1 202 555 0143");
  await page.click("#issue");
  await page.waitForSelector("#handoff:not([hidden])");
  await shot("1-issuer-offer");
  await page.click("#open-wallet");
  await page.waitForURL(`${urls.walletUrl}/offer?**`);
  await page.waitForSelector("#accept");
  await shot("2-wallet-offer-consent");
  await page.click("#accept");
  await page.waitForSelector(".notice.ok");
  assert((await page.textContent("#screen")).includes("Grace Hopper"), "wallet stored the credential");
  assert((await pill()) === "done", "wallet issuance trace complete");
  await shot("3-wallet-added");

  await page.goto(`${urls.issuerUrl}/`);
  await page.waitForFunction(() => document.querySelector("#trace .status-pill")?.textContent === "done");
  assert(true, "issuer trace shows token, proof and credential steps");
  await shot("4-issuer-done");

  // Share name + email (phone left unticked by default)
  await page.goto(`${urls.verifierUrl}/`);
  await page.click("#request");
  await page.waitForURL(`${urls.walletUrl}/authorize?**`);
  await page.waitForSelector("#share");
  const consent = await page.textContent("#screen");
  assert(consent.includes("grace@example.org") && consent.includes("Not shared"), "consent shows shared and withheld claims");
  await shot("5-wallet-share-consent");
  await page.click("#share");
  await page.waitForURL(`${urls.verifierUrl}/**`);
  await page.waitForSelector("#result:not([hidden])");
  const result = await page.textContent("#result");
  assert(result.includes("Received and verified") && result.includes("Grace Hopper") && !result.includes("555 0143"), "verifier got name + email only");
  assert((await pill()) === "done", "verifier trace complete");
  await shot("6-verifier-verified");

  // Decline
  await page.uncheck("#c-email");
  await page.check("#c-phone");
  await page.click("#request");
  await page.waitForSelector("#decline");
  await page.click("#decline");
  await page.waitForURL(`${urls.verifierUrl}/**`);
  await page.waitForSelector("#result:not([hidden])");
  assert((await page.textContent("#result")).includes("declined"), "verifier reports the decline");

  // Wallet home, phone width, dark
  await page.setViewportSize({ width: 390, height: 844 });
  await page.emulateMedia({ colorScheme: "dark" });
  await page.goto(`${urls.walletUrl}/`);
  await page.waitForSelector(".vc-card");
  await shot("7-wallet-home-phone-dark");
  assert(!(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)), "no horizontal scroll at phone width");
  assert(errors.length === 0, `no page errors${errors.length ? `: ${errors.join(" | ")}` : ""}`);
} finally {
  await browser.close();
  await lab.close();
}
