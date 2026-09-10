# Code guide

## Overview
This small public repository contains Axiom Relay connection metadata and working examples for free service discovery and API document checks. It is intended for agent builders.

## Stack and architecture
The examples use Node.js 22 or newer with native HTTPS fetch. There are no dependencies, database, payment operations, API keys or local server. Calls go to Axiom Relay's public HTTPS endpoints; the hosted platform is maintained separately.

## Files and features
- `README.md`: introduction, connection configuration and links.
- `server.json`: remote Streamable HTTP MCP Registry metadata, version 1.0.0.
- `examples/health-check.mjs`: submits a small OpenAPI example and checks its expected findings.
- `examples/mcp-smoke.mjs`: initializes the live server, verifies its free tools, and calls API Doctor.
- `.github/workflows/publish-mcp.yml`: manually triggered, live-verified publication through GitHub OIDC. No saved registry credential is needed.
- `LICENSE`: MIT license for these examples and documentation.

## Data and interfaces
The example OpenAPI object is public fixture data. API Doctor returns a summary and findings. MCP carries JSON-RPC over stateless Streamable HTTP POST requests. Examples reject HTTP and unexpected result failures. They never send credentials or submit orders.

## Configuration and checks
No environment variables are required. For maintainer reference, `node examples/health-check.mjs` and `node examples/mcp-smoke.mjs` verify the live interfaces. The workflow repeats both checks before publication. Registry metadata must be versioned for every new publication.

## Recent changes
- 2026-09-10: Prepared the dedicated public discovery repository, two dependency-free examples and a manually triggered registry publication workflow. Production and registry acceptance must be verified before describing this as published.
