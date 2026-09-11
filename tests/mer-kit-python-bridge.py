"""Isolated synthetic interoperability harness; never receives a private key."""
import base64
import copy
import json
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from axiom_mer import canonicalize_json, sign_mer_receipt, verify_mer

request = json.load(sys.stdin)
results = []
for case in request["cases"]:
    try:
        result = verify_mer(case["envelope"], trusted_keys=case["trustedKeys"], verification_time=case["verificationTime"], predecessor_envelope=case.get("predecessorEnvelope"))
        results.append({"valid": result["valid"], "checks": result["checks"], "codes": sorted({item["code"] for item in result["issues"]})})
    except (ValueError, TypeError):
        results.append({"rejected": True})

private_key = Ed25519PrivateKey.generate()
public_bytes = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
receipt = copy.deepcopy(request["signReceipt"])
key = copy.deepcopy(request["signKey"])
key["publicJwk"]["x"] = base64.urlsafe_b64encode(public_bytes).decode().rstrip("=")
signed = sign_mer_receipt(receipt, trusted_key=key, sign=private_key.sign, verification_time=request["at"])
print(json.dumps({"results": results, "signed": signed, "key": key, "canonical": [canonicalize_json(value) for value in request["canonicalValues"]]}))
