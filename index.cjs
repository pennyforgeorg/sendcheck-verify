/* sendcheck-verify — CommonJS build (same logic as index.mjs, v0.2.0).
 * Verify-before-pay client for the SendCheck x402 API:
 *   1. verifyBeforePay(address) — free GET /validate pre-check.
 *   2. checkService(origin)     — verify the service's signed service card.
 *   3. verifyChallenge(...)     — bind the 402 challenge to the pinned key.
 * Zero dependencies (global fetch + WebCrypto).
 * Docs: https://api.pennyforge.org/llms.txt
 */
"use strict";

Object.defineProperty(exports, "__esModule", { value: true });

exports.VERSION = "0.2.0";
exports.DEFAULT_BASE_URL = "https://api.pennyforge.org";
exports.ATTESTATION_EXTENSION = "x-sendcheck-attestation";

const FORMAT_RE = /^0x[0-9a-fA-F]{40}$/;
const SKEW_S = 60;
const STALE_S = 30 * 24 * 3600;
const USDC_DECIMALS = 6;
const te = new TextEncoder();

class SendCheckVerifyError extends Error {
  constructor(result) {
    super(result.message + (result.status || result.reason ? ` [${result.status || result.reason}]` : ""));
    this.name = "SendCheckVerifyError";
    this.result = result;
  }
}
exports.SendCheckVerifyError = SendCheckVerifyError;

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

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  const keys = Object.keys(value).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(value[k])).join(",") + "}";
}
exports.canonicalJson = canonicalJson;

const normOrigin = (o) => String(o || "").trim().toLowerCase().replace(/\/+$/, "");
const normAddr = (a) => String(a || "").trim().toLowerCase();

async function verifyAttestation(attestation, opts = {}) {
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
exports.verifyAttestation = verifyAttestation;

async function checkService(origin, opts = {}) {
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
    if (item && item.resource) out.endpoints.push({ resource: item.resource, amount: acc && acc.amount != null ? acc.amount : null });
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
exports.checkService = checkService;

async function verifyChallenge(challenge, attestation, opts = {}) {
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
exports.verifyChallenge = verifyChallenge;

function looksLikeAddress(address) {
  return FORMAT_RE.test(String(address == null ? "" : address).trim());
}
exports.looksLikeAddress = looksLikeAddress;

async function verifyBeforePay(address, opts = {}) {
  const baseUrl = String(opts.baseUrl || exports.DEFAULT_BASE_URL).replace(/\/+$/, "");
  const f = typeof opts.fetchFn === "function" ? opts.fetchFn : fetch;
  const clean = String(address == null ? "" : address).trim();

  if (!FORMAT_RE.test(clean)) {
    const result = {
      valid: false,
      status: "format",
      message: "Not a 0x + 40-hex address (local format check — no request sent).",
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
exports.verifyBeforePay = verifyBeforePay;
exports.default = verifyBeforePay;
