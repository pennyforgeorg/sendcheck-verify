/* Offline tests (mocked fetch) + optional --live smoke against the real worker.
 * Run: node test/test.mjs          (offline, always)
 *      node test/test.mjs --live   (+ live /validate smoke) */
import assert from "node:assert/strict";
import {
  verifyBeforePay,
  looksLikeAddress,
  verifyAttestation,
  checkService,
  verifyChallenge,
  canonicalJson,
  SendCheckVerifyError,
  VERSION,
  DEFAULT_BASE_URL,
  ATTESTATION_EXTENSION,
} from "../index.mjs";

const GOOD = "0x9504A5939AB5be2B2B1F8beA7D7ebeCcd96c485D"; // checksum-valid
const LOWER = GOOD.toLowerCase(); // same address, no case information
const MISMATCH = "0x9504a5939Ab5be2b2b1f8bea7d7ebeCCd96c485D"; // same hex, broken casing
let calls = [];
const mockFetch = (result, { status = 200, ok = true } = {}) => {
  calls = [];
  return async (url, opts) => {
    calls.push(url);
    return { ok, status, json: async () => (typeof result === "function" ? result(url) : result) };
  };
};

let n = 0;
async function t(name, fn) {
  n++;
  try {
    await fn();
    console.log("ok", n, "-", name);
  } catch (e) {
    console.error("FAIL", n, "-", name, "\n  ", e.message);
    process.exitCode = 1;
  }
}

await t("exports sanity", () => {
  assert.equal(VERSION, "0.2.1");
  assert.equal(DEFAULT_BASE_URL, "https://api.pennyforge.org");
  assert.equal(ATTESTATION_EXTENSION, "x-sendcheck-attestation");
});

await t("looksLikeAddress: good / lower / garbage", () => {
  assert.equal(looksLikeAddress(GOOD), true);
  assert.equal(looksLikeAddress(LOWER), true);
  assert.equal(looksLikeAddress("0x123"), false);
  assert.equal(looksLikeAddress(null), false);
  assert.equal(looksLikeAddress("0x" + "a".repeat(39)), false);
});

await t("valid checksum → resolves, checked:true, no throw", async () => {
  const r = await verifyBeforePay(GOOD, {
    fetchFn: mockFetch({ valid: true, status: "valid", message: "Valid EIP-55 checksum.", normalized: GOOD }),
  });
  assert.equal(r.valid, true);
  assert.equal(r.status, "valid");
  assert.equal(r.checked, true);
  assert.equal(calls.length, 1);
  assert.ok(calls[0].startsWith(DEFAULT_BASE_URL + "/validate?address="));
});

await t("plain (no case info) → valid:true, status plain", async () => {
  const r = await verifyBeforePay(LOWER, {
    fetchFn: mockFetch({ valid: true, status: "plain", message: "Plain — normalized to EIP-55 below.", normalized: GOOD }),
  });
  assert.equal(r.valid, true);
  assert.equal(r.status, "plain");
  assert.equal(r.normalized, GOOD);
});

await t("checksum mismatch → throws SendCheckVerifyError by default", async () => {
  await assert.rejects(
    () =>
      verifyBeforePay(MISMATCH, {
        fetchFn: mockFetch({ valid: false, status: "mismatch", message: "EIP-55 checksum MISMATCH.", normalized: null }),
      }),
    (e) => {
      assert.ok(e instanceof SendCheckVerifyError);
      assert.equal(e.result.status, "mismatch");
      return true;
    }
  );
});

await t("mismatch with throwOnError:false → returns result, no throw", async () => {
  const r = await verifyBeforePay(MISMATCH, {
    fetchFn: mockFetch({ valid: false, status: "mismatch", message: "EIP-55 checksum MISMATCH.", normalized: null }),
    throwOnError: false,
  });
  assert.equal(r.valid, false);
  assert.equal(r.status, "mismatch");
  assert.equal(r.checked, true);
});

await t("garbage address → local format fail, NO request sent", async () => {
  calls = [];
  const r = await verifyBeforePay("0x123", {
    fetchFn: mockFetch({ valid: true, status: "valid", message: "x", normalized: null }),
    throwOnError: false,
  });
  assert.equal(r.valid, false);
  assert.equal(r.status, "format");
  assert.equal(r.checked, false);
  assert.equal(calls.length, 0);
});

await t("network failure → status network (throwOnError:false)", async () => {
  const r = await verifyBeforePay(GOOD, {
    fetchFn: async () => {
      throw new Error("ECONNREFUSED");
    },
    throwOnError: false,
  });
  assert.equal(r.valid, false);
  assert.equal(r.status, "network");
  assert.ok(/ECONNREFUSED/.test(r.message));
});

await t("HTTP 502 → status http (throwOnError:false)", async () => {
  const r = await verifyBeforePay(GOOD, {
    fetchFn: mockFetch(null, { status: 502, ok: false }),
    throwOnError: false,
  });
  assert.equal(r.valid, false);
  assert.equal(r.status, "http");
  assert.ok(/502/.test(r.message));
});

await t("baseUrl override is honored", async () => {
  const r = await verifyBeforePay(GOOD, {
    baseUrl: "http://localhost:9999/",
    fetchFn: mockFetch({ valid: true, status: "valid", message: "m", normalized: GOOD }),
  });
  assert.equal(r.valid, true);
  assert.ok(calls[0].startsWith("http://localhost:9999/validate"));
});

// ---- signed service card (v0.2.0) — offline crypto + mock-fetch tests ------
/* Build a real ES256 JWS over a canonical payload with a throwaway key, so
 * verifyAttestation runs the FULL path (parse → verify sig → windows → binds). */
const te = new TextEncoder();
const b64u = (bytes) => {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
async function makeKey() {
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const priv = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const pub = await crypto.subtle.exportKey("jwk", kp.publicKey);
  return { kp, priv, pub };
}
async function signJws(privJwk, kid, payload) {
  const key = await crypto.subtle.importKey("jwk", privJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const h = b64u(te.encode(JSON.stringify({ alg: "ES256", kid })));
  const p = b64u(te.encode(canonicalJson(payload)));
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, te.encode(h + "." + p)));
  return { jws: h + "." + p + "." + b64u(sig), pub: null, kid };
}

const PAYTO = "0x1111111111111111111111111111111111111111";
const ORIGIN = "https://svc.example";
let now = Math.floor(Date.now() / 1000);
const PAYLOAD = {
  v: 1,
  service: ORIGIN,
  payTo: PAYTO,
  network: "eip155:8453",
  asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  iat: now,
  exp: now + 365 * 24 * 3600,
  routes: [
    { resource: "/check", maxPrice: "0.01" },
    { resource: "/deep", maxPrice: "0.05" }
  ]
};

await t("canonicalJson: recursively sorted, array order kept", () => {
  assert.equal(canonicalJson({ b: 1, a: { d: 2, c: 3 } }), '{"a":{"c":3,"d":2},"b":1}');
  assert.equal(canonicalJson({ a: [3, 1, 2] }), '{"a":[3,1,2]}');
  assert.equal(canonicalJson(null), "null");
});

await t("verifyAttestation: sign→verify valid + fields", async () => {
  const { priv, pub } = await makeKey();
  const { jws } = await signJws(priv, "kid-1", PAYLOAD);
  const v = await verifyAttestation({ jws, key: { ...pub, kid: "kid-1" } }, { origin: ORIGIN, expectedPayTo: PAYTO });
  assert.equal(v.valid, true);
  assert.equal(v.keyId, "kid-1");
  assert.equal(v.signedAt, PAYLOAD.iat);
  assert.equal(v.payload.payTo, PAYTO);
});

await t("verifyAttestation: tampered payload → signature_invalid", async () => {
  const { priv, pub } = await makeKey();
  const { jws } = await signJws(priv, "kid-1", PAYLOAD);
  const parts = jws.split(".");
  const dec = (s) => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
  const tampered = parts[0] + "." + b64u(te.encode(canonicalJson({ ...PAYLOAD, payTo: "0x2222222222222222222222222222222222222222" }))) + "." + parts[2];
  void dec;
  const v = await verifyAttestation({ jws: tampered, key: { ...pub, kid: "kid-1" } }, {});
  assert.equal(v.valid, false);
  assert.equal(v.reason, "signature_invalid");
});

await t("verifyAttestation: wrong key → signature_invalid", async () => {
  const a = await makeKey();
  const b = await makeKey();
  const { jws } = await signJws(a.priv, "kid-1", PAYLOAD);
  const v = await verifyAttestation({ jws, key: { ...b.pub, kid: "kid-1" } }, {});
  assert.equal(v.valid, false);
  assert.equal(v.reason, "signature_invalid");
});

await t("verifyAttestation: kid mismatch → kid_mismatch", async () => {
  const { priv, pub } = await makeKey();
  const { jws } = await signJws(priv, "kid-A", PAYLOAD);
  const v = await verifyAttestation({ jws, key: { ...pub, kid: "kid-B" } }, {});
  assert.equal(v.valid, false);
  assert.equal(v.reason, "kid_mismatch");
});

await t("verifyAttestation: wrong origin → service_mismatch", async () => {
  const { priv, pub } = await makeKey();
  const { jws } = await signJws(priv, "kid-1", PAYLOAD);
  const v = await verifyAttestation({ jws, key: { ...pub, kid: "kid-1" } }, { origin: "https://other.example" });
  assert.equal(v.valid, false);
  assert.equal(v.reason, "service_mismatch");
});

await t("verifyAttestation: doc payTo != signed → payto_mismatch", async () => {
  const { priv, pub } = await makeKey();
  const { jws } = await signJws(priv, "kid-1", PAYLOAD);
  const v = await verifyAttestation({ jws, key: { ...pub, kid: "kid-1" } }, { expectedPayTo: "0x2222222222222222222222222222222222222222" });
  assert.equal(v.valid, false);
  assert.equal(v.reason, "payto_mismatch");
});

await t("verifyChallenge: matching challenge binds OK (route derived from url)", async () => {
  const { priv, pub } = await makeKey();
  const { jws } = await signJws(priv, "kid-1", PAYLOAD);
  const att = { jws, key: { ...pub, kid: "kid-1" } };
  const challenge = {
    resource: { url: ORIGIN + "/check" },
    accepts: [{ scheme: "exact", payTo: PAYTO, maxAmountRequired: "10000", network: "eip155:8453" }]
  };
  const v = await verifyChallenge(challenge, att, { origin: ORIGIN });
  assert.equal(v.valid, true);
});

await t("verifyChallenge: poisoned challenge payTo → challenge_payto_mismatch", async () => {
  const { priv, pub } = await makeKey();
  const { jws } = await signJws(priv, "kid-1", PAYLOAD);
  const att = { jws, key: { ...pub, kid: "kid-1" } };
  const challenge = {
    resource: { url: ORIGIN + "/check" },
    accepts: [{ scheme: "exact", payTo: "0x2222222222222222222222222222222222222222", maxAmountRequired: "10000" }]
  };
  const v = await verifyChallenge(challenge, att, { origin: ORIGIN });
  assert.equal(v.valid, false);
  assert.equal(v.reason, "challenge_payto_mismatch");
});

await t("verifyChallenge: price above signed max → price_exceeded", async () => {
  const { priv, pub } = await makeKey();
  const { jws } = await signJws(priv, "kid-1", PAYLOAD);
  const att = { jws, key: { ...pub, kid: "kid-1" } };
  const challenge = {
    resource: { url: ORIGIN + "/check" },
    accepts: [{ scheme: "exact", payTo: PAYTO, maxAmountRequired: "10001" }] /* $0.010001 > signed $0.01 */
  };
  const v = await verifyChallenge(challenge, att, { origin: ORIGIN });
  assert.equal(v.valid, false);
  assert.equal(v.reason, "price_exceeded");
});

await t("verifyChallenge: exactly signed max → valid (0.01 → 10000 atomic)", async () => {
  const { priv, pub } = await makeKey();
  const { jws } = await signJws(priv, "kid-1", PAYLOAD);
  const att = { jws, key: { ...pub, kid: "kid-1" } };
  const challenge = { resource: { url: ORIGIN + "/check" }, accepts: [{ payTo: PAYTO, maxAmountRequired: "10000" }] };
  const v = await verifyChallenge(challenge, att, { origin: ORIGIN });
  assert.equal(v.valid, true);
});

await t("verifyChallenge: unsigned route → route_not_signed", async () => {
  const { priv, pub } = await makeKey();
  const { jws } = await signJws(priv, "kid-1", PAYLOAD);
  const att = { jws, key: { ...pub, kid: "kid-1" } };
  const challenge = { resource: { url: ORIGIN + "/mystery" }, accepts: [{ payTo: PAYTO, maxAmountRequired: "1" }] };
  const v = await verifyChallenge(challenge, att, { origin: ORIGIN });
  assert.equal(v.valid, false);
  assert.equal(v.reason, "route_not_signed");
});

await t("verifyAttestation: expired (now > exp+60s) → expired", async () => {
  const { priv, pub } = await makeKey();
  const { jws } = await signJws(priv, "kid-1", PAYLOAD);
  const v = await verifyAttestation({ jws, key: { ...pub, kid: "kid-1" } }, { now: PAYLOAD.exp + 100 });
  assert.equal(v.valid, false);
  assert.equal(v.reason, "expired");
});

await t("verifyAttestation: iat far future → iat_future", async () => {
  const { priv, pub } = await makeKey();
  const { jws } = await signJws(priv, "kid-1", PAYLOAD);
  const v = await verifyAttestation({ jws, key: { ...pub, kid: "kid-1" } }, { now: PAYLOAD.iat - 200 });
  assert.equal(v.valid, false);
  assert.equal(v.reason, "iat_future");
});

await t("verifyAttestation: stale (iat >30d old) → valid + warning=stale", async () => {
  const { priv, pub } = await makeKey();
  const { jws } = await signJws(priv, "kid-1", PAYLOAD);
  const v = await verifyAttestation({ jws, key: { ...pub, kid: "kid-1" } }, { now: PAYLOAD.iat + 31 * 24 * 3600 });
  assert.equal(v.valid, true);
  assert.equal(v.warning, "stale");
});

await t("verifyAttestation: malformed jws → malformed", async () => {
  const { pub } = await makeKey();
  assert.equal((await verifyAttestation({ jws: "x.y", key: pub }, {})).reason, "malformed");
  assert.equal((await verifyAttestation({ jws: "a.b.c", key: pub }, {})).reason, "malformed");
  assert.equal((await verifyAttestation(null, {})).reason, "malformed");
});

/* --- checkService: mock-fetch doc tests ------------------------------------ */
function docFetch(doc) {
  return async (url) => {
    assert.ok(url.endsWith("/.well-known/x402"));
    return { ok: true, status: 200, json: async () => doc };
  };
}

await t("checkService: signed doc → ok, endpoints+payTo extracted, keyChanged=false", async () => {
  const { priv, pub } = await makeKey();
  const { jws } = await signJws(priv, "kid-1", PAYLOAD);
  const doc = {
    items: [
      { resource: ORIGIN + "/check", accepts: [{ scheme: "exact", payTo: PAYTO, amount: "10000" }] },
      { resource: ORIGIN + "/deep", accepts: [{ scheme: "exact", payTo: PAYTO, amount: "50000" }] }
    ],
    attestation: { jws, key: { ...pub, kid: "kid-1" } }
  };
  const r = await checkService(ORIGIN, { fetchFn: docFetch(doc), pinnedKey: { kid: "kid-1", x: pub.x, y: pub.y } });
  assert.equal(r.ok, true);
  assert.equal(r.payTo, PAYTO);
  assert.equal(r.keyId, "kid-1");
  assert.equal(r.keyChanged, false);
  assert.equal(r.endpoints.length, 2);
  assert.equal(r.endpoints[0].resource, ORIGIN + "/check");
  assert.equal(r.endpoints[0].amount, "10000");
});

await t("checkService: rotated key (pinned kid differs) → ok + keyChanged=true (loud)", async () => {
  const a = await makeKey();
  const b = await makeKey();
  const { jws } = await signJws(b.priv, "kid-NEW", PAYLOAD);
  const doc = {
    items: [{ resource: ORIGIN + "/check", accepts: [{ payTo: PAYTO, amount: "10000" }] }],
    attestation: { jws, key: { ...b.pub, kid: "kid-NEW" } }
  };
  const r = await checkService(ORIGIN, { fetchFn: docFetch(doc), pinnedKey: { kid: "kid-1", x: a.pub.x, y: a.pub.y }, throwOnError: false });
  assert.equal(r.ok, true);
  assert.equal(r.keyChanged, true);
});

await t("checkService: unsigned doc (no attestation) → attestation.reason=not_signed (throwOnError:false)", async () => {
  const doc = { items: [{ resource: ORIGIN + "/check", accepts: [{ payTo: PAYTO, amount: "10000" }] }] };
  const r = await checkService(ORIGIN, { fetchFn: docFetch(doc), throwOnError: false });
  assert.equal(r.ok, false);
  assert.equal(r.attestation.reason, "not_signed");
  assert.equal(r.payTo, PAYTO);
});

await t("checkService: fetch failure → attestation.reason=fetch (throwOnError:false)", async () => {
  const r = await checkService(ORIGIN, { fetchFn: async () => { throw new Error("ECONNRESET"); }, throwOnError: false });
  assert.equal(r.ok, false);
  assert.equal(r.attestation.reason, "fetch");
});

await t("checkService: bad signature in doc → ok=false, reason=signature_invalid", async () => {
  const a = await makeKey();
  const b = await makeKey();
  const { jws } = await signJws(a.priv, "kid-1", PAYLOAD);
  const doc = {
    items: [{ resource: ORIGIN + "/check", accepts: [{ payTo: PAYTO, amount: "10000" }] }],
    attestation: { jws, key: { ...b.pub, kid: "kid-1" } } /* key != signer */
  };
  const r = await checkService(ORIGIN, { fetchFn: docFetch(doc), throwOnError: false });
  assert.equal(r.ok, false);
  assert.equal(r.attestation.reason, "signature_invalid");
});

// ---- optional live smoke -------------------------------------------------
if (process.argv.includes("--live")) {
  await t("LIVE: /validate checksum-valid address → 200 valid:true", async () => {
    const r = await verifyBeforePay(GOOD);
    assert.equal(r.valid, true);
    assert.ok(["valid", "plain"].includes(r.status));
  });
  await t("LIVE: /validate plain lowercase → 200 valid:true status plain", async () => {
    const r = await verifyBeforePay(LOWER);
    assert.equal(r.valid, true);
    assert.equal(r.status, "plain");
  });
  await t("LIVE: /validate broken casing → valid:false status mismatch", async () => {
    const r = await verifyBeforePay(MISMATCH, { throwOnError: false });
    assert.equal(r.valid, false);
    assert.equal(r.status, "mismatch");
  });

  // ---- LIVE signed service card (the drift-proof path, end to end) --------
  await t("LIVE: checkService(real origin) → ok, kid pinned, signed==advertised payTo", async () => {
    const r = await checkService(DEFAULT_BASE_URL);
    assert.equal(r.ok, true, JSON.stringify(r.attestation));
    assert.ok(r.keyId, "keyId present");
    assert.ok(r.payTo, "payTo present");
    assert.equal(r.keyChanged, false);
    assert.ok(r.signedAt && r.expiresAt, "signedAt+expiresAt present");
  });

  await t("LIVE: 402 challenge carries x-sendcheck-attestation; verifyChallenge BINDS", async () => {
    const svc = await checkService(DEFAULT_BASE_URL);
    const res = await fetch(DEFAULT_BASE_URL + "/check", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ address: GOOD, chain: "base" })
    });
    assert.equal(res.status, 402);
    const hdr = res.headers.get("PAYMENT-REQUIRED") || res.headers.get("payment-required");
    assert.ok(hdr, "PAYMENT-REQUIRED header present");
    const decl = JSON.parse(Buffer.from(hdr, "base64").toString("utf8"));
    const ext = decl.extensions && decl.extensions[ATTESTATION_EXTENSION];
    assert.ok(ext && ext.jws, "extension " + ATTESTATION_EXTENSION + " present in challenge");
    assert.equal(ext.jws, svc.block.jws, "challenge carries the SAME signed block as the doc");
    const v = await verifyChallenge(decl, ext, { origin: DEFAULT_BASE_URL });
    assert.equal(v.valid, true, JSON.stringify(v));
    assert.equal(String(v.payload.payTo).toLowerCase(), String(decl.accepts[0].payTo).toLowerCase(), "challenge payTo == signed payTo");
  });
}

console.log(process.exitCode ? "SOME TESTS FAILED" : `ALL ${n} TESTS PASSED`);
