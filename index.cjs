/* sendcheck-verify — CommonJS build (same logic as index.mjs).
 * Verify-before-pay client for the SendCheck x402 API: free GET /validate
 * pre-check before your agent signs an x402 payment. Zero dependencies.
 * Docs: https://sendcheck-x402.pennyforge.workers.dev/llms.txt
 */
"use strict";

Object.defineProperty(exports, "__esModule", { value: true });

exports.VERSION = "0.1.0";
exports.DEFAULT_BASE_URL = "https://sendcheck-x402.pennyforge.workers.dev";

const FORMAT_RE = /^0x[0-9a-fA-F]{40}$/;

class SendCheckVerifyError extends Error {
  constructor(result) {
    super(result.message + (result.status ? ` [${result.status}]` : ""));
    this.name = "SendCheckVerifyError";
    this.result = result;
  }
}
exports.SendCheckVerifyError = SendCheckVerifyError;

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
