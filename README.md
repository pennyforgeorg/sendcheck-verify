# sendcheck-verify

**Verify before you pay.** A zero-dependency client for the free
[`GET /validate`](https://api.pennyforge.org/validate?address=0x…)
pre-check on the [SendCheck x402 API](https://api.pennyforge.org/) —
the 10-line guard that stops your agent from signing a payment to a mistyped,
mismatched, or tampered settlement address.

When an x402 client pays a service, it pays the settlement address the service
told it about. A single wrong character (a case-flip, a dropped digit, a
substituted address) and the USDC goes somewhere else forever. `/validate` is
the free, no-key, no-account pre-check: **is this address even a well-formed,
correctly-cased EVM address before you put real money on it?**

Since **v0.2.0** the package does one more thing: it verifies the service's
**signed service card** — an ES256 JWS over the payTo and the per-route
maxPrice that the worker re-signs at every deploy — so a client that pinned the
public key once can confirm the challenge's payTo cryptographically, before
paying. That is the reference implementation of the drift-proof check (the
"signed service card" from the [address-drift
article](https://dev.to/pennyforgehq/one-x402-service-rotated-its-pay-address-964-times-in-10-days-i-measured-90-days-of-the-drift-feed-3cbp)).

## Why this exists

SendCheck's paid endpoints cost $0.01 (one chain) or $0.05 (all five chains)
via x402 — USDC on Base, no account, no API key. But most "is this address
garbage?" checks don't need chain data: the EIP-55 checksum alone catches the
most common, most expensive failures (typos, dropped characters, tampered
casing). So `/validate` is free, and this package makes calling it one line.

## The signed service card (v0.2.0)

Pre-payment address checks have a hole: the "expected payTo" a client compares
against usually comes from the same discovery doc it just fetched — so a
compromised service can point you at its own new address, and for a service
that rotates its address often, every remembered address is stale before the
check finishes.

SendCheck closes that hole by **signing its payment details**. The worker signs
the settlement address and the per-route max prices with a stable ES256 (EC
P-256) key at every deploy, and serves the signed block `{ jws, key }` in three
places:

```
<origin>/.well-known/x402   →  top-level "attestation"
<origin>/openapi.json       →  info["x-attestation"]
the 402 challenge itself    →  extensions["x-sendcheck-attestation"]
```

> **SendCheck signs its payment details with a stable key at every deploy, so
> any client that has pinned that key once can cryptographically confirm —
> before paying — that the address in the payment challenge is one we signed;
> first contact is still trust-on-first-use.**

What the signature **buys**: key continuity for returning, stateful clients —
a compromised worker/DNS/CDN cannot silently redirect your payments, and a
rotated key is a *loud* event you can flag. What it **does not buy** (we
under-claim on purpose): first-visit authenticity (that is TOFU), protection
for ephemeral agents with no pin, or a price *below* the signed maxPrice.

The signed payload also carries a per-route `maxPrice`, so `verifyChallenge`
catches a challenge that quietly raises the price above what the key signed.

### The drift-proof wiring

```js
import { checkService, verifyChallenge, ATTESTATION_EXTENSION } from "sendcheck-verify";

const origin = "https://api.pennyforge.org";

// 1) Once: pin the public key (first contact = trust-on-first-use).
const first = await checkService(origin);          // { ok, keyId, key: JWK, payTo, … }
// persist { kid: first.keyId, x: first.key.x, y: first.key.y } somewhere durable

// 2) Every call: confirm the card still verifies and the key has not rotated.
const svc = await checkService(origin, { pinnedKey: storedPin });
if (svc.keyChanged) { /* loud: the key rotated — inspect before trusting */ }
if (!svc.ok) throw new Error("service card not valid: " + svc.attestation.reason);

// 3) At payment time: bind the 402 CHALLENGE to the signed card.
//    (challenge = decoded base64 PAYMENT-REQUIRED header, or the 402 JSON body)
const verdict = await verifyChallenge(challenge, svc.block, { origin });
if (!verdict.valid) throw new Error("challenge not signed: " + verdict.reason);
// …now sign the EIP-3009 payment to challenge.accepts[0].payTo.
```

`verifyChallenge` checks the challenge's `payTo` against the signed one and the
challenge price against the signed `maxPrice` for the challenged route. Failure
reasons: `signature_invalid`, `challenge_payto_mismatch`, `price_exceeded`,
`route_not_signed`, `expired`, `iat_future`, `service_mismatch`, `kid_mismatch`,
`malformed`.

## Install

```bash
# from source (no build step)
npm install @pennyforgeorg/sendcheck-verify
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

### `verifyAttestation(attestation, opts?)`

Verify a signed block `{ jws, key }` (ES256 JWS over a canonical-JSON payload).
Pure + async (WebCrypto); no network. Returns
`{ valid, reason?, payload, keyId, signedAt, expiresAt, warning? }`.
`opts`: `origin`, `expectedPayTo`, `challengePayTo`, `route`,
`challengeMaxAmount` (atomic USDC string), `now` (unix seconds, for tests).
Time windows: `exp` hard-reject with a 60s clock-skew grace; `iat` may be up to
60s in the future; an `iat` older than 30 days is valid but returns
`warning: "stale"`. `reason` codes: `malformed`, `header_mismatch`,
`kid_mismatch`, `signature_invalid`, `service_mismatch`, `payto_mismatch`,
`challenge_payto_mismatch`, `route_not_signed`, `price_exceeded`, `expired`,
`iat_future`.

### `checkService(origin, opts?)`

Fetch `<origin>/.well-known/x402`, verify its signed card against the doc's own
advertised payTo, and report whether a pinned key changed. Returns
`{ ok, origin, payTo, keyId, signedAt, expiresAt, warning?, attestation,
keyChanged, endpoints: [{resource, amount}] }`. `opts.fetchFn` (inject fetch),
`opts.pinnedKey` (`{kid}` or `{kid,x,y}`), `opts.throwOnError`. `keyChanged` is
the loud rotation signal.

### `verifyChallenge(challenge, attestation, opts?)`

Bind a 402 challenge to a signed card. `challenge` is the decoded 402
declaration (`{ resource: { url }, accepts: [{ payTo, maxAmountRequired }] }`)
— decode the base64 `PAYMENT-REQUIRED` header with
`JSON.parse(Buffer.from(hdr, "base64").toString("utf8"))`. The route is derived
from `resource.url`. Returns the `verifyAttestation` result.

### `ATTESTATION_EXTENSION` — `"x-sendcheck-attestation"`, the extension name
the signed block rides in under inside the 402 challenge's `extensions` map.

### `canonicalJson(value)` — RFC-8785-style canonical JSON (recursively sorted
keys) — exported for anyone re-implementing the signer.

### `SendCheckVerifyError` — thrown on non-valid results; `err.result` carries
the full result object.

## The endpoint, in plain terms

```
GET https://api.pennyforge.org/validate?address=0x…
→ 200 { "valid": true, "status": "valid", "message": "Valid EIP-55 checksum.",
        "normalized": "0x…" }
```

Free. No key. No account. JSON in, JSON out. The paid siblings — `POST /check`
($0.01, one chain: wallet-vs-contract, activity, balances, verdict) and
`POST /deep` ($0.05, all five chains + wrong-network detection) — use x402
(USDC on Base). Machine-readable docs:
[`llms.txt`](https://api.pennyforge.org/llms.txt) and
[`openapi.json`](https://api.pennyforge.org/openapi.json)
on the same host.

## Who runs it

SendCheck is a one-person studio (Pennyforge). The worker runs on Cloudflare
Workers; the address engine is MIT and public
[here](https://github.com/pennyforgeorg/sendcheck). If the free endpoint ever
moves, `opts.baseUrl` is the only thing you change.

## License

MIT — see [LICENSE](LICENSE).
