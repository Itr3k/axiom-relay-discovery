"""Free HTTP tool for a Python agent, including Pixel Office's x402 starter.

This function inspects the supplied OpenAPI document. Its output is advisory;
it does not establish safety, authorize execution or handle a payment.
"""
import json
import httpx

API_DOCTOR_TOOL = {
    "type": "function",
    "function": {
        "name": "check_api_doctor",
        "description": "Check an OpenAPI JSON document for common contract issues before connecting an agent. Results do not certify endpoint safety or authorize execution.",
        "parameters": {
            "type": "object",
            "properties": {"apiDescription": {"type": "object"}},
            "required": ["apiDescription"],
            "additionalProperties": False,
        },
    },
}


def check_api_doctor(apiDescription: dict) -> dict:
    """Raise on invalid input, HTTP failures or an invalid Axiom response."""
    if not isinstance(apiDescription, dict):
        raise ValueError("apiDescription must be a JSON object")
    body = json.dumps({"apiDescription": apiDescription}, allow_nan=False).encode("utf-8")
    if len(body) > 500_000:
        raise ValueError("The encoded request must be at most 500,000 bytes")
    with httpx.Client(timeout=httpx.Timeout(15.0, connect=5.0), follow_redirects=False) as client:
        response = client.post(
            "https://axiomrelay.io/api/v1/agents/api-doctor",
            content=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "AxiomRelay-Python-Example/1.0",
                "X-Axiom-Discovery-Source": "github",
            },
        )
        response.raise_for_status()
        result = response.json()
    if not isinstance(result, dict) or result.get("status") != "success" or not isinstance(result.get("data"), dict):
        raise ValueError("Axiom returned an unexpected result")
    return result["data"]


if __name__ == "__main__":
    example = {
        "openapi": "3.1.0", "info": {"title": "Example agent API", "version": "1.0.0"},
        "paths": {
            "/search": {"get": {"responses": {"200": {}}}},
            "/summarize": {"post": {"operationId": "summarize"}},
        },
    }
    result = check_api_doctor(example)
    assert result["summary"] == {"operationCount": 2, "errorCount": 1, "warningCount": 2, "remoteReferencesFetched": False}
    print(json.dumps(result, indent=2))
