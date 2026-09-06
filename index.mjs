/* sendcheck-verify — verify-before-pay client for the SendCheck x402 API.
 *
 * The one job: before your agent signs an x402 payment to some service, hit the
 * FREE GET /validate pre-check on the SendCheck worker and make sure the
 * settlement address is even a well-formed, correctly-cased EVM address.
 * Zero dependencies, no API key, no account — the check itself costs $0.
 *
 * Docs for the underlying API: https://sendcheck-x402.pennyforge.workers.dev/llms.txt
 * Paid endpoints ($0.01/check, $0.05/deep): GET /openapi.json on the same host.
 */

export const VERSION = "0.1.0";
export const DEFAULT_BASE_URL = "https://sendcheck-x402.pennyforge.workers.dev";

const FORMAT_RE = /^0x[0-9a-fA-F]{40}$/;

export class SendCheckVerifyError extends Error {
  constructor(result) {
    super(result.message + (result.status ? ` [${result.status}]` : ""));
    this.name = "SendCheckVerifyError";
    this.result = result;
  }
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

export default verifyBeforePay;
