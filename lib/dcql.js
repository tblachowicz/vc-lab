// A small subset of DCQL (OpenID4VP 1.0, section 6): credential queries with format, vct_values,
// and top-level claim paths with optional `values`. claim_sets and credential_sets are not supported.

export function validateQuery(query) {
  if (!query || !Array.isArray(query.credentials) || !query.credentials.length) throw new Error("dcql_query.credentials must be a non-empty array");
  if (query.credential_sets) throw new Error("credential_sets is not supported by this wallet");
  for (const cq of query.credentials) {
    if (typeof cq.id !== "string" || !/^[A-Za-z0-9_-]+$/.test(cq.id)) throw new Error("Each credential query needs an id of letters, digits, _ or -");
    if (typeof cq.format !== "string") throw new Error(`Credential query ${cq.id} has no format`);
    if (cq.claim_sets) throw new Error("claim_sets is not supported by this wallet");
    for (const c of cq.claims || []) {
      if (!Array.isArray(c.path) || c.path.length !== 1 || typeof c.path[0] !== "string") throw new Error("Only top-level claim paths like [\"email\"] are supported");
    }
  }
  return query;
}

// credentials: [{ format, vct, claims: {name: value} }]. Returns per query the matching credentials and requested claim names.
export function match(query, credentials) {
  return query.credentials.map((cq) => {
    const requested = (cq.claims || []).map((c) => c.path[0]);
    const matches = credentials.filter((cred) => {
      if (cred.format !== cq.format) return false;
      const vcts = cq.meta?.vct_values;
      if (vcts && !vcts.includes(cred.vct)) return false;
      return (cq.claims || []).every((c) => c.path[0] in cred.claims && (!c.values || c.values.includes(cred.claims[c.path[0]])));
    });
    return { id: cq.id, query: cq, requested, matches };
  });
}
