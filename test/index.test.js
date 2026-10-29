import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import worker, { signBody } from "../src/index.js";

globalThis.crypto = webcrypto;
const secret = "synthetic-secret-for-tests-only";
const target = "https://example.invalid/preview";
const hex = bytes => Array.from(bytes, value => value.toString(16).padStart(2, "0")).join("");

async function signedRequest(body, timestamp = String(Math.floor(Date.now() / 1000))) {
  return new Request(target, { method: "POST", headers: {
    "content-type": "application/json", "x-demo-timestamp": timestamp,
    "x-demo-signature": hex(await signBody(secret, timestamp, body))
  }, body });
}

test("fails closed when the secret is absent", async () => {
  const response = await worker.fetch(new Request(target, { method: "POST" }), {});
  assert.equal(response.status, 503);
});

test("rejects stale and altered signatures", async () => {
  const body = JSON.stringify({ ip: "192.0.2.10", type: "sample_event" });
  assert.equal((await worker.fetch(await signedRequest(body, "1000000000"), { INGEST_SECRET: secret })).status, 401);
  const request = await signedRequest(body);
  request.headers.set("x-demo-signature", "0".repeat(64));
  assert.equal((await worker.fetch(request, { INGEST_SECRET: secret })).status, 401);
});

test("returns a preview and never sends an alert", async () => {
  const body = JSON.stringify({ ip: "192.0.2.10", type: "blocked_login" });
  const response = await worker.fetch(await signedRequest(body), { INGEST_SECRET: secret });
  assert.equal(response.status, 200);
  const data = await response.json();
  assert.equal(data.delivery_preview.severity, "high");
  assert.equal(data.delivered, false);
});
