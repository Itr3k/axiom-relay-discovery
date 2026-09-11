# Axiom Relay

**Find services for your agent. Check an API contract before connecting it.**

Axiom Relay offers free service discovery, OpenAPI document checks, Concierge guidance and receipt-envelope verification.

## Build with MER

**Create and verify Machine Economic Receipts with your own keys.** The free [MER developer kits](packages/mer) provide TypeScript and Python APIs for offline signature verification, exact economics, issuer key history and correction chains. They work without an Axiom account, network request or Axiom signing service.

Get the installable Node package, Python wheel and checksums from the [MER 0.1.0 release](https://github.com/Itr3k/axiom-relay-discovery/releases/tag/mer-v0.1.0). The focused SDK, schema and fixtures are MIT-licensed for commercial use; Axiom's hosted platform is separate. The format remains MER Draft 0.1. npm and PyPI publication, x402 activation and directory listings have separate status.

The [local x402 example](packages/mer/examples/x402) verifies x402's existing signed offers and receipts and binds that evidence into an independently issued MER. It uses ephemeral test keys and moves no money. Try it in your own integration and share a small, nonsensitive issue or pull request describing what worked or what is missing.

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

## Add the free Python tool to an agent

[The Python adapter](examples/api_doctor_tool.py) exports `check_api_doctor` and the standard function-tool declaration `API_DOCTOR_TOOL`. It works as an ordinary HTTP tool alongside an x402 starter. The adapter uses Python 3.10+ and the single dependency pinned in [examples/requirements.txt](examples/requirements.txt).

Register the declaration with your agent, then dispatch that exact tool name to the function after validating its arguments. The included runnable fixture checks the expected two operations, one error and two warnings. HTTP failures are raised, redirects are rejected, and input size and request time are bounded. This free call uses no wallet or payment headers. Document findings remain advisory; authorization for any later action is separate.

## Builder community

Join [Axiom Relay Builders on Matrix](https://matrix.to/#/#builders:axiomrelay.io) to discuss API contracts, MCP tools and practical integration problems. Bring a small public example and the result you expected. The [community page](https://axiomrelay.io/commons?utm_source=github&utm_medium=repository&utm_campaign=builder_launch_20260910) explains the room rules and moderator contact. Use an existing Matrix account; messages are public and unencrypted.

## Help shape it

What is the smallest API-contract problem that has broken one of your agent integrations? [Open an issue](https://github.com/Itr3k/axiom-relay-discovery/issues) with a nonsensitive example. Bug reports and practical integration feedback are welcome.

[Website](https://axiomrelay.io/?utm_source=github&utm_medium=repository&utm_campaign=builder_launch_20260910) · [HTTP guide](https://axiomrelay.io/developers/api-health-check) · [Code guide](CODE_GUIDE.md)

## Builder guides and discussion

Read [practical integration guides](https://axiomrelay.io/updates?source=github), subscribe through [RSS](https://axiomrelay.io/updates/feed.xml) or [JSON Feed](https://axiomrelay.io/updates/feed.json), and ask questions in [repository Discussions](https://github.com/Itr3k/axiom-relay-discovery/discussions). Axiom Relay Beacon automatically publishes new original guides to this repository at most once every three days. It does not send unsolicited messages to other projects.
