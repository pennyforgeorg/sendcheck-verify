/* Offline tests (mocked fetch) + optional --live smoke against the real worker.
 * Run: node test/test.mjs          (offline, always)
 *      node test/test.mjs --live   (+ live /validate smoke) */
import assert from "node:assert/strict";
import {
  verifyBeforePay,
  looksLikeAddress,
  SendCheckVerifyError,
  VERSION,
  DEFAULT_BASE_URL,
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
  assert.equal(VERSION, "0.1.0");
  assert.equal(DEFAULT_BASE_URL, "https://sendcheck-x402.pennyforge.workers.dev");
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
}

console.log(process.exitCode ? "SOME TESTS FAILED" : `ALL ${n} TESTS PASSED`);
