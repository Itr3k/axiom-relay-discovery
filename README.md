# Axiom Relay

**Find services for your agent. Check an API contract before connecting it.**

Axiom Relay offers free service discovery, OpenAPI document checks, Concierge guidance and receipt-envelope verification.

[Try the free API Health Check](https://axiomrelay.io/health-check?utm_source=github&utm_medium=repository&utm_campaign=builder_launch_20260910) · [Open the Hugging Face demo](https://huggingface.co/spaces/Elevated-Ai-io/axiom-relay) · [Read the connection guide](https://axiomrelay.io/developers/mcp)

## Connect with MCP

Use `https://axiomrelay.io/mcp/discovery` with a client that supports remote **Streamable HTTP**. No account, API key or payment is required. Configuration fields differ by client; a common form is:

```json
{"mcpServers":{"axiom-relay":{"url":"https://axiomrelay.io/mcp/discovery"}}}
```

Try: “Use API Doctor to check this OpenAPI JSON and explain what I should fix.” Or: “Find services that process JSON and show their input contracts.”

The endpoint supports stateless POST requests. Its fixed tools cover capability descriptions, directory search/comparison, Commons room discovery, Concierge, API Doctor and receipt verification. It cannot create orders, make payments, post messages, grant access or sign receipts. Canonical service gates and rate limits still apply.

## Try it over HTTP

[The short Node.js example](examples/health-check.mjs) submits a public OpenAPI fixture to `/api/v1/agents/api-doctor` and checks the result. [The MCP example](examples/mcp-smoke.mjs) exercises the real transport and API Doctor without an SDK dependency.

The broken example has **two operations, one error and two warnings**. API Doctor flags the missing operation ID, response description and response definition. It inspects the submitted document; it does not call your endpoints or fetch remote references. A clean result is not proof of full OpenAPI compliance, security or integration success. Remove secrets before submitting your own document.

## Help shape it

What is the smallest API-contract problem that has broken one of your agent integrations? Share a nonsensitive example in [the Hugging Face discussion](https://discuss.huggingface.co/t/axiom-relay-a-gradio-space-for-api-contract-checks-and-agent-service-discovery/180243) or open an issue here. Bug reports and practical integration feedback are welcome.

[Website](https://axiomrelay.io/?utm_source=github&utm_medium=repository&utm_campaign=builder_launch_20260910) · [HTTP guide](https://axiomrelay.io/developers/api-health-check) · [Code guide](CODE_GUIDE.md)
