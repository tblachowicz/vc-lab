// Cloudflare Worker for the issuer. Static files come from the assets binding; every other request goes
// to one Durable Object, which runs the same handler as the Node server with persistent storage.
import { DurableObject } from "cloudflare:workers";
import { createIssuer } from "../issuer/server.js";
import { generateKeyPair, importPrivateJwk, importPublicJwk } from "../lib/jose.js";
import { doStore, sweep } from "./do-store.js";

export class IssuerState extends DurableObject {
  async fetch(request) {
    this.issuer ??= this.boot(new URL(request.url).origin).catch((e) => { this.issuer = null; throw e; });
    return (await (await this.issuer).handle(request)) || new Response("Not found", { status: 404 });
  }

  // The signing key is created on first use and kept in Durable Object storage, so no secret is needed.
  async boot(origin) {
    const storage = this.ctx.storage;
    let jwk = await storage.get("signing-key");
    if (!jwk) {
      const pair = await generateKeyPair({ extractable: true });
      jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
      await storage.put("signing-key", jwk);
    }
    const { kty, crv, x, y } = jwk;
    return createIssuer({
      issuerUrl: this.env.ISSUER_URL || origin,
      walletUrl: this.env.WALLET_URL,
      signingKey: { privateKey: await importPrivateJwk(jwk), publicKey: await importPublicJwk({ kty, crv, x, y }) },
      store: doStore(storage),
    });
  }

  alarm() { return sweep(this.ctx.storage); }
}

export default {
  fetch: (request, env) => env.STATE.get(env.STATE.idFromName("issuer")).fetch(request),
};
