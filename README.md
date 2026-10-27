# VC Lab

Three small apps that pass a verifiable credential around using the OpenID standards, with every protocol step shown and checked on screen:

| App | Role | Standard |
|-----|------|----------|
| **Issuer** | Takes a full name, email and phone number and issues them as an SD-JWT VC | OpenID4VCI 1.0, pre-authorized code flow |
| **Wallet** | A static web app that receives, stores and presents the credential, asking for your consent | OpenID4VCI client, OpenID4VP responder |
| **Verifier** | Lets you pick which claims to request, then verifies what the wallet sends | OpenID4VP 1.0 with DCQL, `direct_post` |

There are no runtime dependencies. The protocol code and SD-JWT handling are plain JavaScript modules on WebCrypto, shared by the browser and the Node servers (`lib/`).

## Run it

```
node scripts/serve.js        # or: npm start
```

| | |
|---|---|
| Issuer | http://localhost:3001 |
| Wallet | http://localhost:3002 |
| Verifier | http://localhost:3003 |

Node 20 or later. The three apps run on separate origins, as they would in production. The issuer's signing key is created in `.keys/` on first run; delete it to rotate. Set `ISSUER_URL`, `WALLET_URL` and `VERIFIER_URL` to run elsewhere.

## Walkthrough

1. **Issuer:** check the details and press **Issue credential**. The issuer creates a credential offer and shows the URL. **Open in wallet** takes you to the wallet's credential offer endpoint.
2. **Wallet:** shows who is offering what. **Add to wallet** runs the rest of OpenID4VCI: token request, `c_nonce`, a proof JWT signed with a new key, the credential request. It then verifies the credential before storing it.
3. **Verifier:** tick the claims to ask for and press **Request credential**. You go to the wallet's authorization endpoint.
4. **Wallet:** shows exactly which claims will be shared and which stay private. **Share** sends only those disclosures plus a Key Binding JWT. **Decline** sends `access_denied`. Either way you return to the verifier.
5. **Verifier:** shows what it received and each check it ran.

Go back to the issuer page after step 2 to see its side: token issued, proof verified, credential signed.

## The credential

SD-JWT VC (`typ: dc+sd-jwt`), `vct` `urn:vc-lab:contact:1`, ES256. `name`, `email` and `phone_number` (OpenID Connect claim names) are each a separate selective disclosure. `cnf.jwk` binds the credential to a key the wallet created for it. Verifiers find the issuer's key through JWT VC Issuer Metadata at `/.well-known/jwt-vc-issuer`.

## Protocol details

**Issuance (OpenID4VCI 1.0)**
- The offer is passed by reference: `{wallet}/offer?credential_offer_uri=…`. That is the wallet's `credential_offer_endpoint`, an HTTPS URL rather than `openid-credential-offer://`, because a web app can't register a custom scheme.
- Grant: `urn:ietf:params:oauth:grant-type:pre-authorized_code`, with anonymous access and no `tx_code`. The code is single-use and lasts 5 minutes.
- Nonce endpoint, then `proofs.jwt` with `typ: openid4vci-proof+jwt`, the holder key in `jwk`, `aud` = issuer, and `nonce`. On `invalid_nonce` the wallet fetches a new nonce and retries once.
- Response: `{"credentials":[{"credential":"<sd-jwt>"}]}`.

**Presentation (OpenID4VP 1.0)**
- An unsigned request to `{wallet}/authorize`: `client_id=redirect_uri:{verifier}/response`, `response_type=vp_token`, `response_mode=direct_post`, `nonce`, `state`, `dcql_query`, and `client_metadata.vp_formats_supported`.
- The request isn't signed, so the wallet shows the verifier only by the host of its response URI and labels it unverified. OpenID4VP tells wallets to ignore unauthenticated display names.
- `vp_token` is `{"contact":["<issuer-jwt>~<disclosures>~<kb-jwt>"]}`. The KB-JWT has `aud` = client_id, `nonce` and `sd_hash`.
- The verifier answers the POST with `redirect_uri` carrying `#response_code=…`. It releases the result only to a browser that presents that code, as a guard against session fixation.

**What the verifier checks:** a trusted `iss` and the issuer signature (key by `kid` from jwt-vc-issuer), `typ`, `vct`, `exp`, each disclosure digest against `_sd`, nothing disclosed beyond what was requested, and the KB-JWT: signed by `cnf.jwk`, `aud`, `nonce`, `iat` fresh, `sd_hash`.

## Layout

```
lib/        isomorphic modules: base64url, ES256 JWS, SD-JWT, DCQL subset, HTTP helpers
ui/         shared styles and the protocol-trace renderer
issuer/     server.js (fetch-style handler) + public/ UI
verifier/   server.js (fetch-style handler) + public/ UI
wallet/     static site: index.html, offer.html, authorize.html, wallet.js, store.js (IndexedDB)
scripts/    serve.js runs all three locally; build.js builds dist/ for deployment
deploy/     Cloudflare Workers + Durable Object wrappers and Wrangler configs
test/       protocol, interop and browser end-to-end tests
```

The servers export `handle(Request) → Response`, the Fetch API shape, and keep state behind a small async store (`lib/kv.js`): in memory under Node, in Durable Object storage on Cloudflare.

## Deploy

`.github/workflows/deploy.yml` deploys on every push to `main`, all three apps as Cloudflare Workers on custom domains:

| App | URL |
|-----|-----|
| Issuer | https://vc-issuer.loft70.net |
| Wallet | https://vc-wallet.loft70.net (static assets only) |
| Verifier | https://vc-verifier.loft70.net |

The hostnames appear twice: as `routes` in `deploy/*.jsonc` and as the URLs at the top of the workflow. Change both together. `workers.dev` and preview URLs are switched off.

The issuer and verifier run the same handlers as locally, each inside one Durable Object that gives it persistent storage (`deploy/`). The issuer creates its signing key on first use and keeps it there, so no key needs to be managed. The verifier reaches the issuer's key metadata through a service binding, because one Worker on an account can't fetch another of its Workers over the internet. Everything fits the free plans.

One-time setup:

1. **Domain:** add the domain to Cloudflare (**Add a site**, free plan) and switch its nameservers at the registrar to the two Cloudflare gives you. Custom domains on Workers need the zone to be active on the same account.
2. **API token:** **My Profile → API Tokens → Create Token → "Edit Cloudflare Workers"** template, covering your account and the domain's zone. Note your **Account ID** (the 32-character string in the dashboard URL).
3. **GitHub secrets:** in the repo, **Settings → Secrets and variables → Actions**. Add `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`.
4. Push to `main`, or run **Actions → Deploy → Run workflow**. Cloudflare creates the DNS records and certificates for the three hostnames; the run summary lists the URLs.

To try the Cloudflare build locally, build with local URLs and run the three Workers under `wrangler dev` (issuer 8787, verifier 8788, wallet 8789, the wallet with its own `--persist-to` folder). `test/e2e.js` can then test them through `E2E_ISSUER_URL`, `E2E_WALLET_URL` and `E2E_VERIFIER_URL`.

## Tests

```
npm install            # dev dependencies only: playwright, @sd-jwt (interop checks)
npm test               # protocol flow + negative cases, and interop with @sd-jwt
npm run e2e            # headless Chromium: issue, accept, share, decline across three origins
```

The negative cases cover single-use codes and nonces, over-disclosure, a wrong nonce, a replayed response, a stolen credential (wrong holder key) and a decline. `npm run e2e` needs a Chromium that Playwright can find; set `CHROMIUM=/path/to/chrome` if it isn't installed.

## Not covered yet

- Authorization code flow with PAR, PKCE and DPoP; transaction codes.
- Signed requests (`x509_hash` / `request_uri`), encrypted responses (`direct_post.jwt`), cross-device QR codes.
- Status lists, key and wallet attestations: the rest of the HAIP profile.
