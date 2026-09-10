import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";

export const REPOSITORY = "Itr3k/axiom-relay-discovery";
const REPOSITORY_ID = "R_kgDOUVqynQ";
const CATEGORY_ID = "DIC_kwDOUVqync4DFVgY";
const FEED = "https://axiomrelay.io/updates/feed.json";
const LEDGER = ".beacon-publications.json";
export const POLICY_REVIEW_EXPIRES = "2026-10-10T00:00:00Z";
const INTERVAL = 72 * 3600000;

export function attributedGuideText(body) {
  return body.replace(/https:\/\/axiomrelay\.io\/[^\s)]+/g, value => {
    const url = new URL(value);
    if (["/health-check", "/commons", "/directory"].includes(url.pathname) || url.pathname.startsWith("/developers/")) {
      url.searchParams.set("utm_source", "github");
      return url.toString();
    }
    return value;
  });
}

export function selectGuide(feed, ledger, now = Date.now()) {
  if (now >= Date.parse(POLICY_REVIEW_EXPIRES)) throw new Error("POLICY_REVIEW_REQUIRED");
  if (feed?.version !== "https://jsonfeed.org/version/1.1" || feed.home_page_url !== "https://axiomrelay.io/updates"
    || feed._axiom?.policy !== "owned-channels-v1" || typeof feed._axiom.publishing_enabled !== "boolean" || !Array.isArray(feed.items) || feed.items.length > 100) throw new Error("INVALID_FEED");
  if (ledger?.version !== 1 || !ledger.publications || Array.isArray(ledger.publications) || typeof ledger.publications !== "object") throw new Error("INVALID_LEDGER");
  const entries = Object.values(ledger.publications);
  if (entries.length > 1000) throw new Error("LEDGER_LIMIT_REACHED");
  if (entries.some(entry => entry.state !== "PUBLISHED")) throw new Error("UNRESOLVED_PUBLICATION_RESERVATION");
  if (entries.some(entry => !Number.isFinite(Date.parse(entry.reservedAt)) || !/^https:\/\/github\.com\/Itr3k\/axiom-relay-discovery\/discussions\/\d+$/.test(entry.url))) throw new Error("INVALID_LEDGER_RECEIPT");
  if (!feed._axiom.publishing_enabled || entries.some(entry => now - Date.parse(entry.reservedAt) < INTERVAL)) return null;
  const items = [...feed.items].sort((a,b) => Date.parse(a.date_published)-Date.parse(b.date_published));
  for (const item of items) {
    if (typeof item.id !== "string" || !/^[a-z0-9][a-z0-9-]{2,79}$/.test(item.id) || item.url !== `https://axiomrelay.io/updates/${item.id}`
      || typeof item.title !== "string" || item.title.length < 5 || item.title.length > 180 || /[\r\n<>]/.test(item.title)
      || typeof item.summary !== "string" || item.summary.length > 700 || typeof item.content_text !== "string"
      || item.content_text.length < 100 || item.content_text.length > 16000 || item._axiom?.source !== "source-controlled-builder-guide"
      || !Number.isFinite(Date.parse(item.date_published)) || Date.parse(item.date_published)>now
      || now-Date.parse(item.date_published)>90*86400000) throw new Error("INVALID_GUIDE");
    const digest = createHash("sha256").update(JSON.stringify([item.title,item.summary,item.content_text])).digest("hex");
    if (digest !== item._axiom.content_sha256) throw new Error("GUIDE_DIGEST_MISMATCH");
    if (ledger.publications[item.id]) {
      if (ledger.publications[item.id].contentSha256 !== digest) throw new Error("PUBLISHED_CONTENT_CHANGED");
      continue;
    }
    const text = `${item.title}\n${item.summary}\n${item.content_text}`;
    if (/@[a-z0-9_]/i.test(text) || /<[^>]+>/.test(text)) throw new Error("GUIDE_MENTIONS_OR_HTML");
    for (const match of text.matchAll(/https?:\/\/[^\s)]+/g)) {
      const url = new URL(match[0]);
      if (url.protocol !== "https:" || url.username || url.password || url.port
        || !(url.hostname === "axiomrelay.io" || url.hostname === "github.com" && (url.pathname === `/${REPOSITORY}` || url.pathname.startsWith(`/${REPOSITORY}/`)))) throw new Error("UNREVIEWED_GUIDE_LINK");
    }
    return item;
  }
  return null;
}

export async function publish({ token, repository, dryRun = true, fetchImpl = fetch, now = Date.now() }) {
  if (repository !== REPOSITORY || !token) throw new Error("PUBLISHER_IDENTITY_MISMATCH");
  async function json(url, init = {}, authenticated = false) {
    const response = await fetchImpl(url, { ...init, redirect: "error", signal: AbortSignal.timeout(15000), headers: {
      Accept: "application/vnd.github+json", "User-Agent": "AxiomRelay-Beacon-Publisher/1.0", ...(authenticated ? { Authorization: `Bearer ${token}`, "X-GitHub-Api-Version": "2022-11-28" } : {}), ...init.headers,
    } });
    if (!response.ok) throw new Error(`PUBLISHER_HTTP_${response.status}`);
    let size = 0; const chunks = []; const reader = response.body.getReader();
    while (true) { const { done, value } = await reader.read(); if (done) break; size += value.byteLength; if (size > 512000) { await reader.cancel(); throw new Error("PUBLISHER_RESPONSE_TOO_LARGE"); } chunks.push(value); }
    const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (body.errors) throw new Error("PUBLISHER_GRAPHQL_REJECTED");
    return body;
  }
  const feed = await json(FEED);
  const ledgerUrl = `https://api.github.com/repos/${REPOSITORY}/contents/${LEDGER}`;
  const source = await json(ledgerUrl, {}, true);
  if (source.encoding !== "base64" || typeof source.content !== "string" || typeof source.sha !== "string") throw new Error("INVALID_LEDGER_RESPONSE");
  const ledger = JSON.parse(Buffer.from(source.content, "base64").toString("utf8"));
  const item = selectGuide(feed, ledger, now);
  if (!item) return { state: "IDLE", reason: "Paused, within publishing interval, or no new guide." };
  if (dryRun) return { state: "DRY_RUN", id: item.id, title: item.title, destination: `https://github.com/${REPOSITORY}/discussions/categories/announcements` };
  async function save(sha, message) {
    const result = await json(ledgerUrl, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ branch: "main", sha, message, content: Buffer.from(`${JSON.stringify(ledger,null,2)}\n`).toString("base64") }) }, true);
    if (!result.content?.sha) throw new Error("LEDGER_COMMIT_UNCONFIRMED");
    return result.content.sha;
  }
  ledger.publications[item.id] = { state: "RESERVED", contentSha256: item._axiom.content_sha256, reservedAt: new Date(now).toISOString() };
  // Persist before the non-idempotent external mutation. Any uncertain outcome
  // leaves a reservation that blocks automated re-posting and further delivery.
  const reservedSha = await save(source.sha, `Reserve Beacon guide: ${item.id}`);
  const result = await json("https://api.github.com/graphql", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
    query: "mutation($input:CreateDiscussionInput!){createDiscussion(input:$input){discussion{url}}}",
    variables: { input: { repositoryId: REPOSITORY_ID, categoryId: CATEGORY_ID, title: item.title,
      body: `${item.summary}\n\n${attributedGuideText(item.content_text)}\n\n---\nPublished automatically by Axiom Relay Beacon from [the original guide](${item.url}?utm_source=github). This discussion is for integration questions and corrections.\n\n<!-- axiom-beacon:${item.id} -->` } },
  }) }, true);
  const url = result.data?.createDiscussion?.discussion?.url;
  if (typeof url !== "string" || !/^https:\/\/github\.com\/Itr3k\/axiom-relay-discovery\/discussions\/\d+$/.test(url)) throw new Error("PUBLICATION_RECEIPT_UNCONFIRMED");
  ledger.publications[item.id] = { ...ledger.publications[item.id], state: "PUBLISHED", url };
  await save(reservedSha, `Record Beacon publication: ${item.id}`);
  return { state: "PUBLISHED", id: item.id, url };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  publish({ token: process.env.GITHUB_TOKEN, repository: process.env.GITHUB_REPOSITORY, dryRun: process.env.BEACON_DRY_RUN !== "false" })
    .then(result => console.log(JSON.stringify(result)))
    .catch(error => { console.error(error instanceof Error && /^[A-Z0-9_]+$/.test(error.message) ? error.message : "PUBLICATION_FAILED_CHECK_LEDGER_BEFORE_RETRYING"); process.exitCode = 1; });
}
