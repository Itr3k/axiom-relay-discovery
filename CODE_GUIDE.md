# Code guide

## Overview
This small public repository contains Axiom Relay connection metadata and working examples for free service discovery and API document checks. It is intended for agent builders.

## Stack and architecture
The Node.js 22+ examples use native HTTPS fetch with no dependencies. The optional Python 3.10+ adapter uses HTTPX 0.28.1. There is no database, payment operation, API key or local server. Calls go to Axiom Relay's public HTTPS endpoints; the hosted platform is maintained separately.

## Files and features
- `README.md`: introduction, connection configuration and links.
- `server.json`: remote Streamable HTTP MCP Registry metadata, version 1.0.0.
- `examples/health-check.mjs`: submits a small OpenAPI example and checks its expected findings.
- `examples/mcp-smoke.mjs`: initializes the live server, verifies its free tools, and calls API Doctor.
- `examples/api_doctor_tool.py`: bounded Python HTTP function and an agent function-tool declaration; `examples/requirements.txt` pins HTTPX.
- `.github/workflows/publish-mcp.yml`: manually triggered, live-verified publication through GitHub OIDC. No saved registry credential is needed.
- `.github/workflows/publish-builder-guides.yml`: daily scheduled and manual distribution of original guides to this repository's Announcements discussions.
- `scripts/publish-builder-guides.mjs`: verifies the public feed, exact destinations, immutable content and minimum 72-hour interval before publishing. Failures with an uncertain send outcome stop further publishing.
- `.beacon-publications.json`: per-guide state, content digest, reservation time and confirmed discussion URL. Reservations precede the non-idempotent discussion API call.
- `tests/publish-builder-guides.test.mjs`: mocked API tests for content validation, campaign pause, interval, reservations and token isolation.
- `LICENSE`: MIT license for these examples and documentation.

## Data and interfaces
The example OpenAPI object is public fixture data. API Doctor returns a summary and findings. MCP carries JSON-RPC over stateless Streamable HTTP POST requests. Examples reject HTTP and unexpected result failures. They never send credentials or submit orders.

## Configuration and checks
The examples need no environment variables. For maintainer reference, `node examples/health-check.mjs` and `node examples/mcp-smoke.mjs` verify the live interfaces. The registry workflow repeats both checks before publication. Registry metadata must be versioned for every new publication. The guide publisher receives `GITHUB_TOKEN` (the temporary Actions token), `GITHUB_REPOSITORY` (must exactly match this repository) and `BEACON_DRY_RUN` (only `false` permits a write). It reads `https://axiomrelay.io/updates/feed.json` without sending the token and uses GitHub's Contents and Discussions APIs. Tests run with `node --test tests/publish-builder-guides.test.mjs`. There is no install or build step.

## Recent changes
- 2026-09-10: Exhausted queues remain idle. Policy renewal is required before a new publication after October 10; already published or expired material does not create repeated daily failure notices.
- 2026-09-10: Guide and human destination links use the platform's existing `utm_source=github` attribution contract for anonymous channel-level arrival and activation counts. API and MCP connection URLs remain exact. Five mocked publication tests pass.
- 2026-09-10 candidate: Added the automatic builder-guide publisher. `.github/workflows/publish-builder-guides.yml` checks Axiom's public JSON Feed daily and can be run manually. `scripts/publish-builder-guides.mjs` publishes at most one original guide every 72 hours to this repository's Announcements category. `.beacon-publications.json` records a reservation before sending and the resulting discussion URL afterward; unresolved reservations stop further posting. The publisher honors Axiom's campaign pause, uses only the built-in repository token, and never writes to other repositories or contacts individual users. Its policy review expires October 10, 2026; a maintainer must recheck platform rules before extending that date. No completed publication is implied until a workflow and its receipt succeed.
- 2026-09-10: Added the verified Builders community link and room guidance to `README.md` after the production federation test and cross-server alias lookup passed.
- 2026-09-10: Routed feedback directly to GitHub issues while the forum introduction awaits staff moderation.
- 2026-09-10: Added and live-tested the free Python tool adapter following Pixel Office's confirmation that their x402 starter supports ordinary HTTP tools. The example returned two operations, one error and two warnings. It includes explicit failure handling and bounded input/time; the function handles no payment or execution authorization.
- 2026-09-10: Official MCP Registry publication passed through GitHub OIDC; API readback confirmed version 1.0.0 active. Registry name: `io.github.Itr3k/axiom-relay-discovery`.
- 2026-09-10: Both examples passed against production. MCP initialization listed ten tools and API Doctor returned the expected findings. Registry acceptance is tracked separately from a successful live connection.
- 2026-09-10: Prepared the dedicated public discovery repository, two dependency-free examples and a manually triggered registry publication workflow. Production and registry acceptance must be verified before describing this as published.
