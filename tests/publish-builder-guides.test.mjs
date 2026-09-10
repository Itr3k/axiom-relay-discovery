import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { selectGuide, publish, REPOSITORY } from "../scripts/publish-builder-guides.mjs";

const now = Date.parse("2026-09-12T12:00:00Z");
function fixtures() {
  const item = { id: "test-guide", title: "Check an API document", summary: "A practical guide for integration builders.", content_text: "Use a small example to inspect an API document before integrating a service. The check is advisory. https://axiomrelay.io/health-check", date_published: "2026-09-10T12:00:00Z", url: "https://axiomrelay.io/updates/test-guide", _axiom: { source: "source-controlled-builder-guide" } };
  item._axiom.content_sha256 = createHash("sha256").update(JSON.stringify([item.title,item.summary,item.content_text])).digest("hex");
  return { feed: { version: "https://jsonfeed.org/version/1.1", home_page_url: "https://axiomrelay.io/updates", _axiom: { policy: "owned-channels-v1", publishing_enabled: true }, items: [item] }, ledger: { version: 1, publications: {} }, item };
}
test("only new, intact, permitted guide content qualifies", () => {
  const { feed, ledger, item } = fixtures();
  assert.equal(selectGuide(feed,ledger,now).id, item.id);
  assert.equal(selectGuide({ ...feed, _axiom: { ...feed._axiom, publishing_enabled: false } },ledger,now), null);
  assert.throws(() => selectGuide(feed,ledger,Date.parse("2026-10-11")), /POLICY_REVIEW/);
  assert.throws(() => selectGuide({ ...feed, items: [{ ...item, content_text: `${item.content_text} altered` }] },ledger,now), /DIGEST/);
  assert.throws(() => selectGuide({ ...feed, items: [{ ...item, url: "https://attacker.example" }] },ledger,now), /INVALID_GUIDE/);
  assert.throws(() => selectGuide(feed,{ version: 1, publications: { old: { state: "RESERVED" } } },now), /UNRESOLVED/);
  ledger.publications[item.id] = { state: "PUBLISHED", contentSha256: item._axiom.content_sha256, reservedAt: "2026-09-08T12:00:00Z", url: `https://github.com/${REPOSITORY}/discussions/1` };
  assert.equal(selectGuide(feed,ledger,now), null, "A previously published guide is never selected again, even after its discussion is removed");
  const older = { ...ledger, publications: { other: { ...ledger.publications[item.id], reservedAt: new Date(now-1000).toISOString() } } };
  assert.equal(selectGuide(feed,older,now), null, "No more than one publication per 72 hours");
});
test("dry run has no writes and never sends the GitHub token to the feed", async () => {
  const { feed, ledger } = fixtures(); const calls = [];
  const result = await publish({ token: "TEST_TOKEN", repository: REPOSITORY, now, fetchImpl: async (url, init) => {
    calls.push({ url, init });
    if (url.startsWith("https://axiomrelay.io/")) { assert.equal(init.headers.Authorization, undefined); return Response.json(feed); }
    return Response.json({ encoding: "base64", sha: "first", content: Buffer.from(JSON.stringify(ledger)).toString("base64") });
  } });
  assert.equal(result.state,"DRY_RUN"); assert.ok(calls.every(call => !call.init.method));
  await assert.rejects(publish({ token: "TEST_TOKEN", repository: "someone/else" }), /IDENTITY/);
});
test("reservation is committed before posting and an uncertain post remains reserved", async () => {
  const { feed } = fixtures(); let ledger = { version: 1, publications: {} }; const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, method: init.method });
    if (url.startsWith("https://axiomrelay.io")) return Response.json(feed);
    if (init.method === "PUT") { ledger = JSON.parse(Buffer.from(JSON.parse(init.body).content,"base64").toString()); return Response.json({ content: { sha: "reserved" } }); }
    if (url.endsWith("graphql")) { assert.equal(ledger.publications["test-guide"].state,"RESERVED"); throw new TypeError("lost response"); }
    return Response.json({ encoding: "base64", sha: "first", content: Buffer.from(JSON.stringify(ledger)).toString("base64") });
  };
  await assert.rejects(publish({ token: "TEST_TOKEN", repository: REPOSITORY, now, dryRun: false, fetchImpl }), /lost response/);
  await assert.rejects(publish({ token: "TEST_TOKEN", repository: REPOSITORY, now, dryRun: false, fetchImpl }), /UNRESOLVED/);
  assert.equal(calls.filter(call => call.url.endsWith("graphql")).length, 1);
});
test("successful delivery persists its verified repository discussion receipt", async () => {
  const { feed } = fixtures(); let ledger = { version: 1, publications: {} }; let writes = 0;
  const fetchImpl = async (url, init) => {
    if (url.startsWith("https://axiomrelay.io")) return Response.json(feed);
    if (init.method === "PUT") { writes++; ledger = JSON.parse(Buffer.from(JSON.parse(init.body).content,"base64").toString()); return Response.json({ content: { sha: String(writes) } }); }
    if (url.endsWith("graphql")) return Response.json({ data: { createDiscussion: { discussion: { url: `https://github.com/${REPOSITORY}/discussions/1` } } } });
    return Response.json({ encoding: "base64", sha: "first", content: Buffer.from(JSON.stringify(ledger)).toString("base64") });
  };
  const result = await publish({ token: "TEST_TOKEN", repository: REPOSITORY, now, dryRun: false, fetchImpl });
  assert.equal(result.state,"PUBLISHED"); assert.equal(writes,2); assert.equal(ledger.publications["test-guide"].url,result.url);
});
