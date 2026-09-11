import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { generateKeyPairSync, sign } from "node:crypto";
import { canonicalizeJson, hashMerValue, parseMerJson, signMerReceipt, verifyMer, verifyMerChain } from "../dist/index.js";

const { vectors } = JSON.parse(readFileSync(new URL("../data/vectors.json", import.meta.url)));
for (const vector of vectors) {
  test(`published fixture: ${vector.id}`, () => {
    const actual = verifyMer(vector.envelope, vector);
    assert.equal(actual.valid, vector.expected.valid);
    assert.deepEqual(actual.checks, vector.expected.checks);
    assert.deepEqual([...new Set(actual.issues.map((issue) => issue.code))].sort(), vector.expected.issueCodes);
  });
}

function independentIssuer() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const at = "2026-09-10T20:00:00.000Z";
  const key = { issuerId: "example-issuer", keyId: "example-key-1", verificationMethod: "https://example.invalid/keys#example-key-1", environment: "TEST", publicJwk: { ...publicKey.export({ format: "jwk" }), kid: "example-key-1", alg: "EdDSA", use: "sig" }, keyLifecycle: [{ status: "ACTIVE", effectiveAt: at, recordedAt: at }] };
  const receipt = structuredClone(vectors[0].envelope.receipt);
  receipt.receiptId = "mer_independent_demo";
  receipt.issuer = { id: key.issuerId, keyId: key.keyId };
  receipt.issuedAt = receipt.event.occurredAt = at;
  receipt.subject.providerId = "example-provider";
  receipt.economics.principal.amount = receipt.economics.totalAuthorized.amount = "0.00";
  receipt.economics.settlement = "NOT_APPLICABLE";
  return { key, receipt, at, sign: (bytes) => sign(null, bytes, privateKey) };
}

test("an independent issuer signs and verifies without Axiom or network access", async () => {
  const issuer = independentIssuer();
  const envelope = await signMerReceipt(issuer.receipt, { trustedKey: issuer.key, sign: issuer.sign, verificationTime: issuer.at });
  assert.equal(verifyMer(envelope, { trustedKeys: [issuer.key], verificationTime: issuer.at }).valid, true);
  assert.equal(verifyMer(envelope, { trustedKeys: [], verificationTime: issuer.at }).valid, false);
  assert.equal(verifyMer(envelope, { trustedKeys: [{ ...issuer.key, issuerId: "someone-else" }], verificationTime: issuer.at }).valid, false);
  assert.equal(verifyMer(envelope, { trustedKeys: [issuer.key, issuer.key], verificationTime: issuer.at }).valid, false);
  envelope.receipt.economics.totalAuthorized.amount = "10000000.00";
  assert.equal(verifyMer(envelope, { trustedKeys: [issuer.key], verificationTime: issuer.at }).valid, false);
});

test("invalid economics are refused before invoking a signing service", async () => {
  const issuer = independentIssuer();
  issuer.receipt.economics.totalAuthorized.amount = "10.00";
  let signed = false;
  await assert.rejects(signMerReceipt(issuer.receipt, { trustedKey: issuer.key, sign: () => { signed = true; return Buffer.alloc(64); }, verificationTime: issuer.at }), /ECONOMIC_TOTAL_MISMATCH/);
  assert.equal(signed, false);
});

test("incorrect signer output and issuer configuration are rejected", async () => {
  const issuer = independentIssuer();
  await assert.rejects(signMerReceipt(issuer.receipt, { trustedKey: issuer.key, sign: () => Buffer.alloc(64), verificationTime: issuer.at }), /does not verify/);
  await assert.rejects(signMerReceipt(issuer.receipt, { trustedKey: { ...issuer.key, publicJwk: { ...issuer.key.publicJwk, d: "must-never-be-trusted" } }, sign: issuer.sign, verificationTime: issuer.at }), /UNSUPPORTED/);
});

test("full chain validation rejects a parent with an invalid signature", () => {
  const child = vectors.find((item) => item.id === "refund-correction");
  const parent = structuredClone(child.predecessorEnvelope);
  assert.equal(verifyMerChain([child.envelope, parent], child).valid, true);
  parent.proof.proofValue = "A".repeat(86);
  const result = verifyMerChain([child.envelope, parent], child);
  assert.equal(result.valid, false);
  assert.ok(result.receipts[0].issues.some((issue) => issue.code === "CORRECTION_PREDECESSOR_INVALID"));
  assert.equal(verifyMerChain([child.envelope], child).valid, false);
  assert.throws(() => verifyMerChain([parent, parent], child), /distinct/);
});

test("canonical bytes preserve UTF-16 order, Unicode and exact integer fields", () => {
  assert.equal(canonicalizeJson({ "\ue000": 2, "😀": 1, a: "雪\n", z: -0 }), '{"a":"雪\\n","z":0,"😀":1,"":2}');
  assert.equal(hashMerValue({ b: 2, a: 1 }), hashMerValue({ a: 1, b: 2 }));
  for (const value of [NaN, Infinity, 0.1, Number.MAX_SAFE_INTEGER + 1, "\ud800", new Date(), [undefined], { a: undefined }]) assert.throws(() => canonicalizeJson(value));
  const cyclic = {}; cyclic.self = cyclic;
  assert.throws(() => canonicalizeJson(cyclic), /acyclic/);
  const getter = Object.defineProperty({}, "secret", { enumerable: true, get() { throw new Error("Getter must not run"); } });
  assert.throws(() => canonicalizeJson(getter), /accessors/);
  assert.throws(() => parseMerJson('"' + "x".repeat(65536) + '"'), /65,536/);
  assert.throws(() => canonicalizeJson(new Array(3)), /sparse/);
});
