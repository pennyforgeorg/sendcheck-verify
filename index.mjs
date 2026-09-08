/* sendcheck-verify — verify-before-pay client for the SendCheck x402 API.
 *
 * The jobs, in order:
 *  1. verifyBeforePay(address)     — FREE GET /validate pre-check: is the
 *     settlement address even a well-formed, correctly-cased EVM address?
 *  2. checkService(origin)         — does the service's own discovery doc
 *     carry a signed service card, and does the signed payTo match the payTo
 *     the doc advertises? (Pin the key once; first contact = TOFU.)
 *  3. verifyChallenge(challenge, attestation) — the drift-proof step: the
 *     payTo + maxPrice in the 402 PAYMENT CHALLENGE are cryptographically
 *     bound to the key you pinned.
 *
 * The signed service card (v0.2.0): the SendCheck worker signs its payment
 * details (payTo + per-route maxPrice) with a stable ES256 key at every
 * deploy. The signed block {jws, key} is served at
 *   <origin>/.well-known/x402            (top-level "attestation")
 *   <origin>/openapi.json                (info["x-attestation"])
 *   the 402 challenge                    (extensions["x-sendcheck-attestation"])
 *
 * Honest claim (do not overclaim): SendCheck signs its payment details with
 * a stable key at every deploy, so any client that has pinned that key once
 * can cryptographically confirm — before paying — that the address in the
 * payment challenge is one we signed; first contact is still
 * trust-on-first-use. What the signature BUYS: key continuity for returning
 * clients (a compromised worker/DNS/CDN cannot silently redirect payments; a
 * rotated key is loud). What it does NOT buy: first-visit authenticity,
 * protection for clients with no pin, or price drops below the signed maxPrice.
 *
 * Zero dependencies, no API key, no account — the check itself costs $0.
 * Needs only global fetch + WebCrypto (Node >= 18, browsers, workerd).
 *
 * Docs for the underlying API: https://api.pennyforge.org/llms.txt
 * Paid endpoints ($0.01/check, $0.05/deep): GET /openapi.json on the same host.
 */

export const VERSION = "0.2.1";
export const DEFAULT_BASE_URL = "https://api.pennyforge.org";
export const ATTESTATION_EXTENSION = "x-sendcheck-attestation";

const FORMAT_RE = /^0x[0-9a-fA-F]{40}$/;
const SKEW_S = 60; /* client clock skew grace, seconds */
const STALE_S = 30 * 24 * 3600; /* iat age that triggers the soft "stale" warning */
const USDC_DECIMALS = 6;

const te = new TextEncoder();

export class SendCheckVerifyError extends Error {
  constructor(result) {
    super(result.message + (result.status || result.reason ? ` [${result.status || result.reason}]` : ""));
    this.name = "SendCheckVerifyError";
    this.result = result;
  }
}

/* --- tiny base64url helpers (JWS uses no padding) ------------------------- */

function b64urlText(text) {
  let s = "";
  const bytes = te.encode(text);
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlToBytes(b64) {
  const s = String(b64).replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  const bin = atob(s + "=".repeat((4 - (s.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/* RFC-8785-style canonical JSON (recursively sorted keys, no whitespace).
 * Full JCS only differs on special number formats; the signed payload is
 * strings + integers, where sorted-key JSON.stringify IS JCS. */
export function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  const keys = Object.keys(value).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(value[k])).join(",") + "}";
}

const normOrigin = (o) => String(o || "").trim().toLowerCase().replace(/\/+$/, "");
const normAddr = (a) => String(a || "").trim().toLowerCase();

/**
 * Verify a signed block {jws, key} (ES256 JWS over a canonical-JSON payload).
 *
 * @param {{jws:string, key:object}} attestation - the signed block as served.
 * @param {object} [opts]
 * @param {string} [opts.origin]      - canonical origin the doc was fetched from.
 * @param {string} [opts.expectedPayTo] - the payTo ADVERTISED by the same doc (consistency).
 * @param {string} [opts.challengePayTo] - the payTo in the 402 CHALLENGE (the binding).
 * @param {string} [opts.route]        - challenged resource path, e.g. "/check".
 * @param {string} [opts.challengeMaxAmount] - challenge maxAmountRequired (atomic USDC).
 * @param {number} [opts.now]          - unix seconds (default Date.now()/1000).
 * @returns {Promise<{valid:boolean, reason?:string, payload?:object, keyId?:string,
 *   signedAt?:number, expiresAt?:number, warning?:string}>}
 * reason codes: malformed | header_mismatch | kid_mismatch | signature_invalid |
 *   service_mismatch | payto_mismatch | challenge_payto_mismatch |
 *   route_not_signed | price_exceeded | expired | iat_future
 * Windows: exp hard reject (+60s skew); iat may be up to 60s in the future;
 * iat older than 30 days = valid + warning "stale".
 */
export async function verifyAttestation(attestation, opts = {}) {
  const fail = (reason, extra = {}) => Object.assign({ valid: false, reason }, extra);

  if (!attestation || typeof attestation.jws !== "string" || !attestation.key) return fail("malformed");
  const parts = String(attestation.jws).split(".");
  if (parts.length !== 3) return fail("malformed");

  let header, payload;
  try {
    const dec = new TextDecoder();
    header = JSON.parse(dec.decode(b64urlToBytes(parts[0])));
    payload = JSON.parse(dec.decode(b64urlToBytes(parts[1])));
  } catch {
    return fail("malformed");
  }
  if (!payload || typeof payload !== "object") return fail("malformed");

  if (header.alg !== "ES256") return fail("header_mismatch", { header });
  if (header.kid && attestation.key.kid && header.kid !== attestation.key.kid)
    return fail("kid_mismatch", { headerKid: header.kid, keyKid: attestation.key.kid });

  let key;
  try {
    key = await crypto.subtle.importKey("jwk", attestation.key, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const good = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      b64urlToBytes(parts[2]),
      te.encode(parts[0] + "." + parts[1])
    );
    if (!good) return fail("signature_invalid");
  } catch (e) {
    return fail("signature_invalid", { error: String((e && e.message) || e) });
  }

  const base = {
    payload,
    keyId: header.kid || attestation.key.kid || null,
    signedAt: typeof payload.iat === "number" ? payload.iat : null,
    expiresAt: typeof payload.exp === "number" ? payload.exp : null,
  };

  const now = typeof opts.now === "number" ? opts.now : Math.floor(Date.now() / 1000);
  if (typeof payload.exp === "number" && now > payload.exp + SKEW_S) return fail("expired", base);
  if (typeof payload.iat === "number" && payload.iat > now + SKEW_S) return fail("iat_future", base);

  if (opts.origin && payload.service && normOrigin(payload.service) !== normOrigin(opts.origin))
    return fail("service_mismatch", base);
  if (opts.expectedPayTo && payload.payTo && normAddr(payload.payTo) !== normAddr(opts.expectedPayTo))
    return fail("payto_mismatch", base);

  if (opts.challengePayTo && payload.payTo && normAddr(opts.challengePayTo) !== normAddr(payload.payTo))
    return fail("challenge_payto_mismatch", base);
  if (opts.route && Array.isArray(payload.routes)) {
    const match = payload.routes.find((r) => typeof r === "object" && String(r.resource || "").toLowerCase() === String(opts.route).toLowerCase());
    if (!match) return fail("route_not_signed", base);
    if (typeof opts.challengeMaxAmount === "string" && typeof match.maxPrice === "string") {
      const maxAtomic = Math.round(Number(match.maxPrice) * 10 ** USDC_DECIMALS);
      const reqAtomic = Number(opts.challengeMaxAmount);
      if (Number.isFinite(maxAtomic) && Number.isFinite(reqAtomic) && reqAtomic > maxAtomic) return fail("price_exceeded", base);
    }
  }

  const warning = typeof payload.iat === "number" && now - payload.iat > STALE_S ? "stale" : undefined;
  return Object.assign({ valid: true }, base, warning ? { warning } : {});
}

/**
 * Check the service: fetch <origin>/.well-known/x402, verify its signed
 * service card against the doc's OWN advertised payTo, and report whether the
 * pinned key changed (a rotation is loud — inspect before trusting).
 *
 * @param {string} origin - the service origin, e.g. "https://api.pennyforge.org"
 * @param {object} [opts]
 * @param {typeof fetch} [opts.fetchFn] - fetch implementation (dependency injection).
 * @param {{kid?:string, x?:string, y?:string}} [opts.pinnedKey] - the key you pinned
 *   on a previous visit (kid alone, or kid + JWK coordinates).
 * @param {boolean} [opts.throwOnError=true]
 * @returns {Promise<{ok:boolean, origin:string, payTo:string|null, key:object|null,
 *   keyId:string|null, signedAt:number|null, expiresAt:number|null, warning?:string,
 *   attestation:{valid:boolean, reason?:string}, block:{jws:string, key:object}|null, keyChanged:boolean,
 *   endpoints:Array<{resource:string, amount:string|null}>}>}
 */
export async function checkService(origin, opts = {}) {
  const f = typeof opts.fetchFn === "function" ? opts.fetchFn : fetch;
  const o = normOrigin(origin);
  const out = {
    ok: false,
    origin: o,
    payTo: null,
    keyId: null,
    signedAt: null,
    expiresAt: null,
    attestation: { valid: false },
    block: null,
    key: null,
    keyChanged: false,
    endpoints: []
  };

  let doc = null;
  let docPayTo = null;
  try {
    const res = await f(`${o}/.well-known/x402`, { headers: { accept: "application/json" } });
    if (!res.ok) throw new Error("HTTP " + res.status);
    doc = await res.json();
  } catch (e) {
    out.attestation = { valid: false, reason: "fetch", error: (e && e.message) || String(e) };
    if (opts.throwOnError !== false) throw new SendCheckVerifyError(out);
    return out;
  }

  const items = Array.isArray(doc.items) ? doc.items : Array.isArray(doc) ? doc : [];
  for (const item of items) {
    const acc = item && Array.isArray(item.accepts) ? item.accepts[0] : null;
    if (item && item.resource)
      out.endpoints.push({
        resource: item.resource,
        amount: acc && acc.amount != null ? acc.amount : null /* atomic USDC */
      });
    if (acc && acc.payTo) docPayTo = docPayTo || acc.payTo;
  }
  const att = doc && doc.attestation;
  if (!att || !att.jws) {
    out.payTo = docPayTo;
    out.attestation = { valid: false, reason: "not_signed" };
    if (opts.throwOnError !== false) throw new SendCheckVerifyError(out);
    return out;
  }

  out.block = att; /* the raw signed block as served: {jws, key, note?} — feed it to verifyChallenge */
  const v = await verifyAttestation(att, { origin: o, expectedPayTo: docPayTo });
  out.payTo = docPayTo;
  out.key = att.key; /* the public JWK — persist it as your pin */
  out.keyId = v.keyId || null;
  out.signedAt = v.signedAt || null;
  out.expiresAt = v.expiresAt || null;
  if (v.warning) out.warning = v.warning;
  out.attestation = v;
  out.ok = v.valid === true;

  if (v.valid && opts.pinnedKey) {
    const pk = opts.pinnedKey;
    out.keyChanged =
      (typeof pk.kid === "string" && v.keyId && pk.kid !== v.keyId) ||
      (typeof pk.x === "string" && att.key && att.key.x && pk.x !== att.key.x) ||
      (typeof pk.y === "string" && att.key && att.key.y && pk.y !== att.key.y);
  }

  if (!out.ok && opts.throwOnError !== false) throw new SendCheckVerifyError(out);
  return out;
}

/**
 * The drift-proof step: bind the 402 PAYMENT CHALLENGE to the signed card.
 * Call this with the decoded challenge (the base64 PAYMENT-REQUIRED header,
 * or the 402 JSON body) and the attestation block from the same service.
 * If this passes, the payTo your agent is about to pay was SIGNED by the key
 * you pinned — and the challenge price is within the signed maxPrice.
 *
 * @param {object} challenge - decoded 402 declaration: { resource:{url}, accepts:[{payTo, maxAmountRequired|amount, ...}] }
 * @param {{jws:string, key:object}} attestation - the signed block.
 * @param {object} [opts]
 * @param {string} [opts.origin] - origin the challenge came from.
 * @param {number} [opts.now] - unix seconds override (tests).
 * @returns {Promise<object>} verifyAttestation result (valid + reason/warning + payload).
 */
export async function verifyChallenge(challenge, attestation, opts = {}) {
  const acc = challenge && Array.isArray(challenge.accepts) ? challenge.accepts[0] : null;
  const url = challenge && challenge.resource && typeof challenge.resource.url === "string"
    ? challenge.resource.url
    : challenge && challenge.resource && typeof challenge.resource === "string"
      ? challenge.resource
      : "";
  const route = url ? String(url).split("?")[0].replace(/^https?:\/\/[^/]+/, "") : opts.route;
  return verifyAttestation(attestation, {
    origin: opts.origin,
    challengePayTo: acc ? acc.payTo : opts.challengePayTo,
    route,
    challengeMaxAmount: acc ? acc.maxAmountRequired || acc.amount : opts.challengeMaxAmount,
    now: opts.now
  });
}

/**
 * Offline format check: does this look like 0x + 40 hex characters?
 * @param {unknown} address
 * @returns {boolean}
 */
export function looksLikeAddress(address) {
  return FORMAT_RE.test(String(address == null ? "" : address).trim());
}

/**
 * Call the free GET /validate before you pay.
 *
 * @param {string} address - EVM address to verify (0x + 40 hex).
 * @param {object} [opts]
 * @param {string} [opts.baseUrl] - override the API host (defaults to the live worker).
 * @param {typeof fetch} [opts.fetchFn] - fetch implementation to use (dependency injection for tests).
 * @param {boolean} [opts.throwOnError=true] - throw SendCheckVerifyError on a non-valid result;
 *   pass false to always get the result object back.
 * @returns {Promise<{valid:boolean, status:string, message:string, normalized:string|null, checked:boolean}>}
 *   `checked:false` means the address failed the LOCAL format check (no request was sent).
 *   `status` is one of: "valid" | "plain" | "mismatch" | "format" | "network" | "http".
 */
export async function verifyBeforePay(address, opts = {}) {
  const baseUrl = String(opts.baseUrl || DEFAULT_BASE_URL).replace(/\/+$/, "");
  const f = typeof opts.fetchFn === "function" ? opts.fetchFn : fetch;
  const clean = String(address == null ? "" : address).trim();

  if (!FORMAT_RE.test(clean)) {
    const result = {
      valid: false,
      status: "format",
      message: "Not a 0x + 40-hex address (local format check — no request was sent).",
      normalized: null,
      checked: false,
    };
    if (opts.throwOnError !== false) throw new SendCheckVerifyError(result);
    return result;
  }

  let res;
  try {
    res = await f(`${baseUrl}/validate?address=${encodeURIComponent(clean)}`, {
      headers: { accept: "application/json" },
    });
  } catch (e) {
    const result = {
      valid: false,
      status: "network",
      message: "Could not reach the SendCheck /validate endpoint: " + (e && e.message ? e.message : String(e)),
      normalized: clean,
      checked: true,
    };
    if (opts.throwOnError !== false) throw new SendCheckVerifyError(result);
    return result;
  }

  let body = null;
  try {
    body = await res.json();
  } catch {
    /* non-JSON body → handled below */
  }

  if (!res.ok || !body) {
    const result = {
      valid: false,
      status: "http",
      message: `HTTP ${res.status} from /validate${body && body.message ? " — " + body.message : ""}`,
      normalized: clean,
      checked: true,
    };
    if (opts.throwOnError !== false) throw new SendCheckVerifyError(result);
    return result;
  }

  const result = {
    valid: !!body.valid,
    status: body.status,
    message: body.message,
    normalized: body.normalized,
    checked: true,
  };
  if (!result.valid && opts.throwOnError !== false) throw new SendCheckVerifyError(result);
  return result;
}

export default verifyBeforePay;
