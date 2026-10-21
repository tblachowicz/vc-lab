// Cloudflare Worker for the verifier; same shape as issuer.worker.js.
import { DurableObject } from "cloudflare:workers";
import { createVerifier } from "../verifier/server.js";
import { doStore, sweep } from "./do-store.js";

export class VerifierState extends DurableObject {
  fetch(request) {
    const { env } = this;
    this.verifier ??= createVerifier({
      verifierUrl: env.VERIFIER_URL || new URL(request.url).origin,
      walletUrl: env.WALLET_URL,
      trustedIssuers: [env.ISSUER_URL],
      // A Worker can't fetch another workers.dev Worker on the same account over the internet,
      // so calls to the issuer go through the ISSUER service binding.
      fetchImpl: (url, init) => (env.ISSUER && new URL(url).origin === new URL(env.ISSUER_URL).origin ? env.ISSUER.fetch(url, init) : fetch(url, init)),
      store: doStore(this.ctx.storage),
    });
    return Promise.resolve(this.verifier.handle(request)).then((res) => res || new Response("Not found", { status: 404 }));
  }

  alarm() { return sweep(this.ctx.storage); }
}

export default {
  fetch: (request, env) => env.STATE.get(env.STATE.idFromName("verifier")).fetch(request),
};
