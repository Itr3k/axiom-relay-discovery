// Public synthetic fixture only. No network, wallet, private key or Axiom account.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { verifyMer } from "@axiom-relay/mer";

const fixtures = JSON.parse(readFileSync(createRequire(import.meta.url).resolve("@axiom-relay/mer/vectors"), "utf8"));
const fixture = fixtures.vectors.find((item) => item.id === "legacy-fulfillment");
assert.ok(fixture, "Expected published fixture is missing");
const options = { trustedKeys: fixture.trustedKeys, verificationTime: fixture.verificationTime };
assert.equal(verifyMer(fixture.envelope, options).valid, true);
const changed = structuredClone(fixture.envelope);
changed.receipt.economics.totalAuthorized.amount = "0.02";
assert.equal(verifyMer(changed, options).valid, false);
console.log(JSON.stringify({ synthetic: true, originalVerified: true, tamperingRejected: true, networkRequests: 0 }));
