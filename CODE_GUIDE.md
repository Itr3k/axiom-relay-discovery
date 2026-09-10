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
- `LICENSE`: MIT license for these examples and documentation.

## Data and interfaces
The example OpenAPI object is public fixture data. API Doctor returns a summary and findings. MCP carries JSON-RPC over stateless Streamable HTTP POST requests. Examples reject HTTP and unexpected result failures. They never send credentials or submit orders.

## Configuration and checks
No environment variables are required. For maintainer reference, `node examples/health-check.mjs` and `node examples/mcp-smoke.mjs` verify the live interfaces. The workflow repeats both checks before publication. Registry metadata must be versioned for every new publication.

## Recent changes
- 2026-09-10: Added the verified Builders community link and room guidance to `README.md` after the production federation test and cross-server alias lookup passed.
- 2026-09-10: Routed feedback directly to GitHub issues while the forum introduction awaits staff moderation.
- 2026-09-10: Added and live-tested the free Python tool adapter following Pixel Office's confirmation that their x402 starter supports ordinary HTTP tools. The example returned two operations, one error and two warnings. It includes explicit failure handling and bounded input/time; the function handles no payment or execution authorization.
- 2026-09-10: Official MCP Registry publication passed through GitHub OIDC; API readback confirmed version 1.0.0 active. Registry name: `io.github.Itr3k/axiom-relay-discovery`.
- 2026-09-10: Both examples passed against production. MCP initialization listed ten tools and API Doctor returned the expected findings. Registry acceptance is tracked separately from a successful live connection.
- 2026-09-10: Prepared the dedicated public discovery repository, two dependency-free examples and a manually triggered registry publication workflow. Production and registry acceptance must be verified before describing this as published.
