// The one credential type this lab issues and requests.
export const VCT = "urn:vc-lab:contact:1";
export const FORMAT = "dc+sd-jwt";
export const CONFIG_ID = "contact_sd_jwt";

// OpenID Connect standard claim names, in display order.
export const CLAIMS = [
  { name: "name", label: "Full name" },
  { name: "email", label: "Email" },
  { name: "phone_number", label: "Phone number" },
];
export const claimLabel = (name) => CLAIMS.find((c) => c.name === name)?.label || name;

export const PRE_AUTH_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
