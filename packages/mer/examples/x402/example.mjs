// Local-only interoperability demonstration. Generates ephemeral keys; sends no payment or network request.
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { createOfferJWS, createReceiptJWS, verifyOfferSignatureJWS, verifyReceiptSignatureJWS, verifyReceiptMatchesOffer } from "@x402/extensions/offer-receipt";
import { hashMerValue, signMerReceipt, verifyMer } from "@axiom-relay/mer";

const x402Keys = generateKeyPairSync("ed25519");
const merKeys = generateKeyPairSync("ed25519");
const x402Public = x402Keys.publicKey.export({ format: "jwk" });
const signer = { kid: "did:web:example.invalid#x402-demo", format: "jws", algorithm: "EdDSA", sign: async (bytes) => sign(null, bytes, x402Keys.privateKey).toString("base64url") };
const resource = "https://example.invalid/mer-audit";
const payer = "0x1111111111111111111111111111111111111111";
const offer = await createOfferJWS(resource, { acceptIndex: 0, scheme: "exact", network: "eip155:8453", asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", payTo: "0x2222222222222222222222222222222222222222", amount: "1000000", offerValiditySeconds: 120 }, signer);
// Synthetic delivery evidence only: no transaction hash and no assertion of real settlement.
const x402Receipt = await createReceiptJWS({ resourceUrl: resource, payer, network: "eip155:8453" }, signer);
const decodedOffer = await verifyOfferSignatureJWS(offer, x402Public);
const decodedReceipt = await verifyReceiptSignatureJWS(x402Receipt, x402Public);
assert.equal(decodedReceipt.resourceUrl, resource);
assert.equal(verifyReceiptMatchesOffer(x402Receipt, { ...decodedOffer, format: "jws", signedOffer: offer }, [payer]), true);

const verificationTime = new Date().toISOString();
const trustedKey = {
  issuerId: "example-independent-issuer", keyId: "mer-demo",
  verificationMethod: "https://example.invalid/keys#mer-demo", environment: "TEST",
  publicJwk: { ...merKeys.publicKey.export({ format: "jwk" }), kid: "mer-demo", alg: "EdDSA", use: "sig" },
  keyLifecycle: [{ status: "ACTIVE", effectiveAt: verificationTime, recordedAt: verificationTime }],
};
const vectors = JSON.parse(readFileSync(new URL("../../typescript/data/vectors.json", import.meta.url)));
const receipt = structuredClone(vectors.vectors[0].envelope.receipt);
receipt.receiptId = "mer_x402_independent_demo";
receipt.issuer = { id: trustedKey.issuerId, keyId: trustedKey.keyId };
receipt.subject = { serviceId: "example.mer-audit", serviceVersion: "1.0.0", providerId: "example-provider" };
receipt.issuedAt = receipt.event.occurredAt = verificationTime;
receipt.economics.principal.amount = receipt.economics.totalAuthorized.amount = "1.00";
receipt.economics.settlement = "SIMULATED";
receipt.lineage.previousEventIds = [];
receipt.privacy.intentMode = "public_synthetic";
const deliveredBundle = { kind: "SYNTHETIC_LOCAL_DEMO", realMoneyMoved: false, x402Offer: offer, x402Receipt, report: { status: "example_complete" } };
receipt.evidence = { inputHash: hashMerValue({ demonstration: "independent MER issuer with x402 signed evidence" }), resultHash: hashMerValue(deliveredBundle) };
const mer = await signMerReceipt(receipt, { trustedKey, verificationTime, sign: (bytes) => sign(null, bytes, merKeys.privateKey) });
assert.equal(verifyMer(mer, { trustedKeys: [trustedKey], verificationTime }).valid, true);
assert.equal(mer.receipt.evidence.resultHash, hashMerValue(deliveredBundle));
const changed = structuredClone(deliveredBundle);
changed.report.status = "tampered";
assert.notEqual(hashMerValue(changed), mer.receipt.evidence.resultHash);
await assert.rejects(verifyReceiptSignatureJWS(x402Receipt, merKeys.publicKey.export({ format: "jwk" })));
assert.equal(verifyMer(mer, { trustedKeys: [], verificationTime }).valid, false);
console.log(JSON.stringify({ status: "PASS", x402OfferVerified: true, x402ReceiptVerified: true, merVerified: true, resultBindingVerified: true, independentIssuer: true, realMoneyMoved: false, networkRequests: 0 }));
