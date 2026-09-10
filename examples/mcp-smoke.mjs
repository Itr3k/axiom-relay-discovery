import assert from "node:assert/strict";

const endpoint = "https://axiomrelay.io/mcp/discovery";
let id = 0;
async function call(method, params = {}) {
  const response = await fetch(endpoint, {
    method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method, params }), signal: AbortSignal.timeout(20_000), redirect: "error",
  });
  assert.equal(response.status, 200, `MCP returned ${response.status}`);
  const text = await response.text();
  const result = JSON.parse(response.headers.get("content-type")?.includes("text/event-stream")
    ? text.split("\n").filter(line => line.startsWith("data:")).map(line => line.slice(5).trimStart()).join("\n")
    : text);
  assert.ok(!result.error, JSON.stringify(result.error));
  return result.result;
}
const initialized = await call("initialize", { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "axiom-discovery-example", version: "1.0.0" } });
assert.equal(initialized.serverInfo.name, "axiom-relay-discovery");
const { tools } = await call("tools/list");
assert.ok(tools.some(tool => tool.name === "axiom_api_doctor"));
assert.ok(tools.every(tool => tool.annotations?.readOnlyHint === true));
assert.ok(!tools.some(tool => /quote|order|payment|sign_receipt/.test(tool.name)));
const result = await call("tools/call", { name: "axiom_api_doctor", arguments: { apiDescription: { openapi: "3.1.0", info: { title: "MCP example", version: "1" }, paths: { "/search": { get: {} } } } } });
assert.ok(!result.isError);
assert.equal(result.structuredContent.status, "success");
assert.equal(result.structuredContent.data.summary.operationCount, 1);
console.log(JSON.stringify({ server: initialized.serverInfo, tools: tools.map(tool => tool.name), result: result.structuredContent.data }, null, 2));
