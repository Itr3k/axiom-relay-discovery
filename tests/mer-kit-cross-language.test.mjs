import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync, sign } from "node:crypto";
import { fileURLToPath } from "node:url";
import { canonicalizeJson, hashMerValue, verifyMer } from "../packages/mer/typescript/dist/index.js";

const root = fileURLToPath(new URL("../", import.meta.url));
const { vectors } = JSON.parse(readFileSync(new URL("../packages/mer/typescript/data/vectors.json", import.meta.url)));
const cases = vectors.map((vector) => structuredClone(vector));
const at = "2026-09-10T20:00:00.000Z";
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const key = { issuerId: "interop-issuer", keyId: "interop-key-1", verificationMethod: "https://example.invalid/keys#interop-key-1", environment: "TEST", publicJwk: { ...publicKey.export({ format: "jwk" }), kid: "interop-key-1", alg: "EdDSA", use: "sig" }, keyLifecycle: [{ status: "ACTIVE", effectiveAt: at, recordedAt: at }] };
const receipt = structuredClone(vectors[0].envelope.receipt);
receipt.receiptId = "mer_interop_001";
receipt.issuer = { id: key.issuerId, keyId: key.keyId };
receipt.issuedAt = receipt.event.occurredAt = at;
receipt.subject.providerId = "example-provider";
receipt.economics.settlement = "SIMULATED";
const wrap = (value) => ({ receipt: value, proof: { type: "DataIntegrityProof", cryptosuite: "eddsa-jcs-2022", created: value.issuedAt, verificationMethod: key.verificationMethod, proofValue: sign(null, Buffer.from(canonicalizeJson(value)), privateKey).toString("base64url") } });
const add = (id, value, overrides = {}) => cases.push({ id, envelope: wrap(value), trustedKeys: [key], verificationTime: at, ...overrides });
add("node-independent-signature", receipt);
for (const [id, mutate] of [
  ["total-mismatch", (v) => v.economics.totalAuthorized.amount = "0.02"],
  ["currency-mismatch", (v) => v.economics.totalAuthorized.currency = "EUR"],
  ["network-mismatch", (v) => v.economics.totalAuthorized.network = "solana"],
  ["fee-mismatch", (v) => v.economics.axiomRelayFee.amount = "0.01"],
  ["other-fee-mismatch", (v) => v.economics.otherFees = [{ amount: "0.01", currency: "USDC" }]],
  ["unknown-field", (v) => v.untrusted = true],
  ["invalid-sequence", (v) => v.event.sequence = 0],
  ["event-after-issued", (v) => v.event.occurredAt = "2026-09-10T20:01:00.000Z"],
  ["future-issued", (v) => v.issuedAt = "2099-01-01T00:00:00.000Z"],
  ["invalid-money-format", (v) => v.economics.totalAuthorized.amount = "1e-2"],
]) {
  const value = structuredClone(receipt); mutate(value); add(id, value);
}
for (const environment of ["TEST", "SANDBOX", "PRODUCTION"]) {
  const value = structuredClone(receipt);
  value.subject.providerId = "axiom";
  value.economics.principal.recipientRole = "axiom_first_party_merchant";
  value.economics.settlement = "SETTLED";
  value.commerce = { merchantRef: "merchant.axiom", merchantType: "AXIOM_FIRST_PARTY", pricing: { amount: "0.01", currency: "USDC" }, grossEconomicVolume: { amount: "0.01", currency: "USDC" }, providerPrincipal: { amount: "0.00", currency: "USDC" }, axiomRevenue: { amount: "0.01", currency: "USDC" }, activityClass: environment === "PRODUCTION" ? "FIRST_PARTY_PRODUCTION" : "INTERNAL_TEST", realMoneyMoved: environment === "PRODUCTION", commercialPolicy: { termsPolicyRef: "terms.axiom.example-1", refundPolicyRef: "refund.axiom.example-1", acceptedAt: at }, settlement: { amount: "0.01", asset: "USDC", network: "base", decimals: 6, profileRef: "settlement.example", methodRef: "method.example", recipient: "receiver.example", paymentReference: "payment.example", finality: "CONFIRMED" } };
  add(`commerce-${environment}`, value, { trustedKeys: [{ ...key, environment }] });
  for (const [field, replacement] of [["merchantRef", "merchant.other"], ["activityClass", "EXTERNAL"], ["realMoneyMoved", true], ["commercialPolicy", null], ["pricing", { amount: "0.02", currency: "USDC" }], ["axiomRevenue", { amount: "0.02", currency: "USDC" }], ["providerPrincipal", { amount: "0.02", currency: "EUR" }]]) {
    const altered = structuredClone(value); altered.commerce[field] = replacement;
    add(`commerce-${environment}-${field}`, altered, { trustedKeys: [{ ...key, environment }] });
  }
}

const parent = wrap(receipt);
const successor = structuredClone(receipt);
successor.receiptId = "mer_interop_refund_001";
successor.issuedAt = successor.event.occurredAt = "2026-09-10T20:01:00.000Z";
successor.event.sequence += 1;
successor.event.type = "refund";
successor.economics.settlement = "REFUNDED";
successor.lineage.previousEventIds = [receipt.receiptId];
successor.correction = { type: "refund", reasonCode: "TEST_REFUND", rootReceiptId: receipt.receiptId, predecessorReceiptId: receipt.receiptId, predecessorDigest: hashMerValue(receipt), amount: { amount: "0.01", currency: "USDC" }, cumulativeAdjustedAmount: { amount: "0.01", currency: "USDC" }, scope: "FULL", resolution: "APPLIED" };
add("independent-refund", successor, { predecessorEnvelope: parent, verificationTime: successor.issuedAt });
for (const [field, replacement] of [["predecessorDigest", `sha256:${"0".repeat(64)}`], ["predecessorReceiptId", "mer_missing"], ["rootReceiptId", "mer_wrong_root"], ["type", "dispute"], ["scope", "PARTIAL"], ["resolution", "OPEN"], ["cumulativeAdjustedAmount", { amount: "0.02", currency: "USDC" }]]) {
  const altered = structuredClone(successor); altered.correction[field] = replacement;
  add(`refund-${field}`, altered, { predecessorEnvelope: parent, verificationTime: successor.issuedAt });
}

for (const time of ["2026-02-30T00:00:00.000Z", "2026-09-10", "2026-09-10T20:00:00", "2026-09-10T20:00:00.1234Z", "2026-09-10T24:00:00.000Z", "0000-09-10T20:00:00.000Z", "2026-09-10T20:00:00.000+24:00", "2026-09-10T13:00:00.123-07:00", "2026-09-10T20:00:00Z"]) {
  const altered = structuredClone(receipt); altered.issuedAt = altered.event.occurredAt = time;
  add(`timestamp-${time}`, altered);
}
for (const lifecycle of [[null], [{ status: "ACTIVE", effectiveAt: "2026-02-30T00:00:00.000Z", recordedAt: at }]]) {
  add("malformed-lifecycle", receipt, { trustedKeys: [{ ...key, keyLifecycle: lifecycle }] });
}

const canonicalValues = [{ "\ue000": 2, "😀": 1, a: "雪\n", z: 0 }, [true, false, null, 9007199254740991], { slash: "/", quote: '"', control: "\u0000\u001f", separator: "\u2028" }];
const run = spawnSync(process.env.MER_KIT_PYTHON ?? `${root}packages/mer/.venv/bin/python`, [`${root}tests/mer-kit-python-bridge.py`], { cwd: root, env: { ...process.env, PYTHONPATH: `${root}packages/mer/python/src` }, input: JSON.stringify({ cases, signReceipt: receipt, signKey: key, at, canonicalValues }), encoding: "utf8", maxBuffer: 8 * 1024 * 1024 });
assert.equal(run.status, 0, run.stderr);
const python = JSON.parse(run.stdout);
for (const [index, item] of cases.entries()) {
  const actual = verifyMer(item.envelope, item);
  const expected = { valid: actual.valid, checks: actual.checks, codes: [...new Set(actual.issues.map((issue) => issue.code))].sort() };
  assert.deepEqual(python.results[index], expected, `Cross-language disagreement: ${item.id}`);
}
assert.equal(verifyMer(python.signed, { trustedKeys: [python.key], verificationTime: at }).valid, true);
assert.deepEqual(python.canonical, canonicalValues.map(canonicalizeJson));
console.log(`PASS: ${cases.length} shared cases, Node→Python and Python→Node signatures, and canonical Unicode/integer boundaries.`);
