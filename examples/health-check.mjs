import assert from "node:assert/strict";

const apiDescription = {
  openapi: "3.1.0", info: { title: "Example agent API", version: "1.0.0" },
  paths: { "/search": { get: { responses: { "200": {} } } }, "/summarize": { post: { operationId: "summarize" } } },
};
const response = await fetch("https://axiomrelay.io/api/v1/agents/api-doctor", {
  method: "POST", headers: { "Content-Type": "application/json", "X-Axiom-Discovery-Source": "github" },
  body: JSON.stringify({ apiDescription }), signal: AbortSignal.timeout(20_000), redirect: "error",
});
assert.equal(response.status, 200, `API returned ${response.status}`);
const result = await response.json();
assert.equal(result.status, "success");
assert.deepEqual(result.data.summary, { operationCount: 2, errorCount: 1, warningCount: 2, remoteReferencesFetched: false });
console.log(JSON.stringify(result.data, null, 2));
