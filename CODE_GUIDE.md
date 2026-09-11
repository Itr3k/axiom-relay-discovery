# Code guide

## Overview
This public repository contains Axiom Relay connection metadata, free API/MCP examples, and independently usable MER developer kits. It is intended for agent builders who need service discovery and verifiable economic receipts.

## Stack and architecture
The original Node.js 22+ HTTP examples use native fetch with no dependencies; the Python 3.10+ API adapter uses HTTPX 0.28.1. The MER SDK requires Node.js 20+ or Python 3.10+ with cryptography, and performs no network requests. TypeScript builds to ESM with type declarations. The x402 example uses the official extensions package 2.25.0. There is no database, real payment operation or hosted platform implementation in this repository.

## Files and features
- `packages/mer/README.md`: format, explicit issuer trust, compatibility, license and distribution scope.
- `packages/mer/typescript/src/{index,core,integrity,time,cli}.ts`: safe canonicalization, explicit-trust signature verification, economic/key lifecycle/correction checks, issuer-owned signing callback and offline CLI.
- `packages/mer/python/src/axiom_mer`: matching Python APIs and CLI, with the same public schema and signed test vectors.
- `packages/mer/examples/x402`: local example using separate ephemeral issuer keys to verify official x402 signed offers/receipts and an MER-bound result bundle. No payment or network request is made.
- `tests/mer-kit-cross-language.test.mjs` and `mer-kit-python-bridge.py`: 71 shared cases and independently generated signatures in both directions.
- `.github/workflows/verify-mer.yml`: read-only CI for both packages and the x402 example. It has no package-publishing credential or automatic release permission.
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

An MER envelope contains a receipt and an Ed25519 proof. The receipt binds issuer, service, event, exact decimal economics, input/result hashes, privacy mode and lineage. Applications supply trusted public keys and append-only lifecycle information independently. The SDK never fetches a receipt-supplied key or URL. Full correction verification requires all relevant ancestors. Synthetic examples are test evidence, not real economic activity or external adoption. The legacy proof label is the existing Axiom profile and does not claim full W3C cryptosuite conformance.
The example OpenAPI object is public fixture data. API Doctor returns a summary and findings. MCP carries JSON-RPC over stateless Streamable HTTP POST requests. Examples reject HTTP and unexpected result failures. They never send credentials or submit orders.

## Configuration and checks
The examples need no environment variables. For maintainer reference, `node examples/health-check.mjs` and `node examples/mcp-smoke.mjs` verify the live interfaces. The registry workflow repeats both checks before publication. Registry metadata must be versioned for every new publication. The guide publisher receives `GITHUB_TOKEN` (the temporary Actions token), `GITHUB_REPOSITORY` (must exactly match this repository) and `BEACON_DRY_RUN` (only `false` permits a write). It reads `https://axiomrelay.io/updates/feed.json` without sending the token and uses GitHub's Contents and Discussions APIs. Tests run with `node --test tests/publish-builder-guides.test.mjs`. There is no install or build step.

## MER build and validation

For maintainer reference, the CI file records the complete build/install/test sequence. Node package scripts build and test the ESM distribution; Python unittest reads the matching vectors. The cross-language harness uses `packages/mer/.venv/bin/python`. The x402 example is a local file consumer of the built TypeScript SDK. Public package artifacts contain only the focused compiled SDK, public data, README and license; Python source archives also contain focused tests. GitHub release checksums bind the distributed files. npm/PyPI publication and hosted product deployment are separate.

## Recent changes
- 2026-09-10: Added the TypeScript/Python MER 0.1.0 kits, 17 shared signed vectors, 71-case interoperability harness, offline CLIs and the official x402 receipt example. The focused MIT license permits commercial use; private platform code, hosted audit workflow, signing keys and customer data are excluded. Added read-only CI, verified the complete package checks, and published the installable GitHub release at https://github.com/Itr3k/axiom-relay-discovery/releases/tag/mer-v0.1.0. Uploaded artifact SHA-256 values match the local checksums; npm/PyPI distribution is separate.
- 2026-09-10: Live distribution verified. The dry run and publication workflow both passed all five tests; the publisher created [Announcements discussion #1](https://github.com/Itr3k/axiom-relay-discovery/discussions/1) and saved its receipt in `.beacon-publications.json`. The daily schedule remains active. Public website/Matrix publishing runs every 72 hours; this repository also enforces 72 hours and never republishes completed entries.
- 2026-09-10: Exhausted queues remain idle. Policy renewal is required before a new publication after October 10; already published or expired material does not create repeated daily failure notices.
- 2026-09-10: Guide and human destination links use the platform's existing `utm_source=github` attribution contract for anonymous channel-level arrival and activation counts. API and MCP connection URLs remain exact. Five mocked publication tests pass.
- 2026-09-10: Added the automatic builder-guide publisher. `.github/workflows/publish-builder-guides.yml` checks Axiom's public JSON Feed daily and can be run manually. `scripts/publish-builder-guides.mjs` publishes at most one original guide every 72 hours to this repository's Announcements category. `.beacon-publications.json` records a reservation before sending and the resulting discussion URL afterward; unresolved reservations stop further posting. The publisher honors Axiom's campaign pause, uses only the built-in repository token, and never writes to other repositories or contacts individual users. Its policy review expires October 10, 2026; a maintainer must recheck platform rules before extending that date. The first live guide was published by the workflow and its discussion receipt was verified, as recorded above.
- 2026-09-10: Added the verified Builders community link and room guidance to `README.md` after the production federation test and cross-server alias lookup passed.
- 2026-09-10: Routed feedback directly to GitHub issues while the forum introduction awaits staff moderation.
- 2026-09-10: Added and live-tested the free Python tool adapter following Pixel Office's confirmation that their x402 starter supports ordinary HTTP tools. The example returned two operations, one error and two warnings. It includes explicit failure handling and bounded input/time; the function handles no payment or execution authorization.
- 2026-09-10: Official MCP Registry publication passed through GitHub OIDC; API readback confirmed version 1.0.0 active. Registry name: `io.github.Itr3k/axiom-relay-discovery`.
- 2026-09-10: Both examples passed against production. MCP initialization listed ten tools and API Doctor returned the expected findings. Registry acceptance is tracked separately from a successful live connection.
- 2026-09-10: Prepared the dedicated public discovery repository, two dependency-free examples and a manually triggered registry publication workflow. Production and registry acceptance must be verified before describing this as published.
