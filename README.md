# sendcheck-verify

**Verify before you pay.** A zero-dependency client for the free
[`GET /validate`](https://sendcheck-x402.pennyforge.workers.dev/validate?address=0x…)
pre-check on the [SendCheck x402 API](https://sendcheck-x402.pennyforge.workers.dev/) —
the 10-line guard that stops your agent from signing a payment to a mistyped,
mismatched, or tampered settlement address.

When an x402 client pays a service, it pays the settlement address the service
told it about. A single wrong character (a case-flip, a dropped digit, a
substituted address) and the USDC goes somewhere else forever. `/validate` is
the free, no-key, no-account pre-check: **is this address even a well-formed,
correctly-cased EVM address before you put real money on it?**

## Why this exists

SendCheck's paid endpoints cost $0.01 (one chain) or $0.05 (all five chains)
via x402 — USDC on Base, no account, no API key. But most "is this address
garbage?" checks don't need chain data: the EIP-55 checksum alone catches the
most common, most expensive failures (typos, dropped characters, tampered
casing). So `/validate` is free, and this package makes calling it one line.

## Install

```bash
# from source (no build step)
npm install git+https://gitlab.com/pennyforge-dev/sendcheck-verify.git
```

Requires Node 18+ (uses global `fetch`). Zero dependencies. MIT.

## Quickstart

```js
import { verifyBeforePay } from "sendcheck-verify";

// Throws SendCheckVerifyError unless the address passes the free pre-check.
await verifyBeforePay("0x9504A5939AB5be2B2B1F8beA7D7ebeCcd96c485D");

// …then sign your x402 payment.
```

CommonJS:

```js
const { verifyBeforePay } = require("sendcheck-verify");
```

Typical wiring inside an x402 client:

```js
import { verifyBeforePay } from "sendcheck-verify";
import { wrapFetchWithPayment } from "x402-fetch"; // or your own x402 stack

const pay = wrapFetchWithPayment(fetch, { wallet });

async function call(serviceUrl, address, body) {
  await verifyBeforePay(address);          // free — catch bad addresses here
  const res = await pay(serviceUrl, {      // paid only when the address is clean
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return res.json();
}
```

If you already normalize addresses on your side and just want the result
object (no throw):

```js
const r = await verifyBeforePay(addr, { throwOnError: false });
// { valid, status: "valid" | "plain" | "mismatch" | "format" | "network" | "http",
//   message, normalized, checked }
```

## API

### `verifyBeforePay(address, opts?)`

- `address` — EVM address, `0x` + 40 hex.
- `opts.baseUrl` — override the API host (default: the live worker).
- `opts.fetchFn` — inject a fetch implementation (tests / proxies).
- `opts.throwOnError` — default `true`; pass `false` to always get the result back.

Behavior notes:

- A string that isn't even `0x`+40-hex fails the **local** format check and
  throws (or returns `checked: false`) without sending a request — you never
  pay a round trip for garbage input.
- `status: "plain"` = valid address, all-lowercase or all-uppercase (no case
  information). That's fine to pay; the response includes the normalized
  EIP-55 form.
- `status: "mismatch"` = the casing does not match the address hash — usually
  a typo or tampering. **This is the one to treat as hard-fail.**

### `looksLikeAddress(addr)` — offline format check, no network.

### `SendCheckVerifyError` — thrown on non-valid results; `err.result` carries
the full result object.

## The endpoint, in plain terms

```
GET https://sendcheck-x402.pennyforge.workers.dev/validate?address=0x…
→ 200 { "valid": true, "status": "valid", "message": "Valid EIP-55 checksum.",
        "normalized": "0x…" }
```

Free. No key. No account. JSON in, JSON out. The paid siblings — `POST /check`
($0.01, one chain: wallet-vs-contract, activity, balances, verdict) and
`POST /deep` ($0.05, all five chains + wrong-network detection) — use x402
(USDC on Base). Machine-readable docs:
[`llms.txt`](https://sendcheck-x402.pennyforge.workers.dev/llms.txt) and
[`openapi.json`](https://sendcheck-x402.pennyforge.workers.dev/openapi.json)
on the same host.

## Who runs it

SendCheck is a one-person studio (Pennyforge). The worker runs on Cloudflare
Workers; the address engine is MIT and public
[here](https://gitlab.com/pennyforge-dev/sendcheck). If the free endpoint ever
moves, `opts.baseUrl` is the only thing you change.

## License

MIT — see [LICENSE](LICENSE).
