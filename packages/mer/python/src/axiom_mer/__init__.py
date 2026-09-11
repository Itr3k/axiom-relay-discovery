"""Offline, explicit-trust MER Draft 0.1 signing and verification.

No network requests, key provisioning, storage, or telemetry are performed.
The application supplies trusted issuer keys and, for issuance, its own signer.
"""
import base64
import hashlib
import json
import math
import re
from datetime import datetime, timezone
from importlib.resources import files
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .integrity import issue, record, semantic_integrity, timestamp

MER_KIT_VERSION = "0.1.0"
MER_DRAFT_VERSION = "0.1.0-draft"
MER_CONTRACT_VERSION = "2026-09-02.mer-draft-0.1-integrity-3"
MER_MAX_INPUT_BYTES = 65536
MER_SCHEMA = json.loads(files(__package__).joinpath("data/receipt-0.1.schema.json").read_text(encoding="utf-8"))


def _assert_json(value, depth=0, seen=None, budget=None):
    seen, budget = (set() if seen is None else seen), ([0] if budget is None else budget)
    budget[0] += 1
    if budget[0] > 8192 or depth > 32:
        raise ValueError("MER JSON exceeds its structural limit.")
    if value is None or type(value) is bool:
        return
    if type(value) in (int, float):
        if not math.isfinite(value) or int(value) != value or abs(value) > 9007199254740991:
            raise ValueError("MER JSON numbers must be safe integers; use decimal strings for amounts.")
        return
    if type(value) is str:
        if len(value) > MER_MAX_INPUT_BYTES or re.search(r"[\ud800-\udfff]", value):
            raise ValueError("MER JSON contains an oversized string or invalid Unicode.")
        return
    if type(value) not in (dict, list) or id(value) in seen:
        raise ValueError("MER accepts finite, acyclic JSON values only.")
    seen.add(id(value))
    for key, child in value.items() if type(value) is dict else enumerate(value):
        if type(value) is dict:
            if type(key) is not str:
                raise ValueError("MER object keys must be strings.")
            _assert_json(key, depth + 1, seen, budget)
        else:
            _assert_json(str(key), depth + 1, seen, budget)
        _assert_json(child, depth + 1, seen, budget)
    seen.remove(id(value))


def _canonical(value):
    if type(value) is dict:
        return "{" + ",".join(json.dumps(key, ensure_ascii=False) + ":" + _canonical(value[key]) for key in sorted(value, key=lambda key: key.encode("utf-16be"))) + "}"
    if type(value) is list:
        return "[" + ",".join(map(_canonical, value)) + "]"
    if type(value) in (int, float):
        return str(int(value))
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def canonicalize_json(value):
    """Canonical MER JSON: UTF-16 key order, preserved arrays, exact integer fields."""
    _assert_json(value)
    canonical = _canonical(value)
    if len(canonical.encode("utf-8")) > MER_MAX_INPUT_BYTES:
        raise ValueError("A MER document may not exceed 65,536 bytes.")
    return canonical


def parse_mer_json(text):
    if not isinstance(text, str) or len(text.encode("utf-8")) > MER_MAX_INPUT_BYTES:
        raise ValueError("A MER document may not exceed 65,536 bytes.")
    result = json.loads(text)
    canonicalize_json(result)
    return result


def hash_mer_value(value):
    return "sha256:" + hashlib.sha256(canonicalize_json(value).encode("utf-8")).hexdigest()


def _equal(left, right):
    if type(left) is bool or type(right) is bool:
        return type(left) is type(right) and left == right
    return left == right


def _schema_check(schema, value, path, issues):
    if "oneOf" in schema:
        matches = 0
        for candidate in schema["oneOf"]:
            candidate_issues = []
            _schema_check(candidate, value, path, candidate_issues)
            matches += not candidate_issues
        if matches != 1:
            issue(issues, "SCHEMA_ONE_OF", path)
        return
    if "const" in schema and not _equal(schema["const"], value):
        issue(issues, "SCHEMA_CONST", path)
        return
    if "enum" in schema and not any(_equal(option, value) for option in schema["enum"]):
        issue(issues, "SCHEMA_ENUM", path)
        return
    kind = schema.get("type")
    if kind == "object":
        if not isinstance(value, dict):
            issue(issues, "SCHEMA_TYPE", path)
            return
        for required in schema.get("required", []):
            if required not in value:
                issue(issues, "SCHEMA_REQUIRED", path + "." + required)
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in properties:
                    issue(issues, "SCHEMA_ADDITIONAL_PROPERTY", path + "." + key)
        for key, child in properties.items():
            if key in value:
                _schema_check(child, value[key], path + "." + key, issues)
    elif kind == "array":
        if not isinstance(value, list):
            issue(issues, "SCHEMA_TYPE", path)
            return
        if len(value) < schema.get("minItems", 0):
            issue(issues, "SCHEMA_MIN_ITEMS", path)
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            issue(issues, "SCHEMA_MAX_ITEMS", path)
        for index, item in enumerate(value):
            if "items" in schema:
                _schema_check(schema["items"], item, f"{path}[{index}]", issues)
    elif kind == "string":
        if not isinstance(value, str):
            issue(issues, "SCHEMA_TYPE", path)
            return
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            issue(issues, "SCHEMA_PATTERN", path)
        if schema.get("format") == "date-time" and timestamp(value) is None:
            issue(issues, "SCHEMA_FORMAT", path)
        if schema.get("format") == "uri":
            try:
                parsed = urlparse(value)
                if not parsed.scheme or (parsed.scheme in ("http", "https") and not parsed.netloc):
                    issue(issues, "SCHEMA_FORMAT", path)
            except ValueError:
                issue(issues, "SCHEMA_FORMAT", path)
    elif kind == "integer":
        if type(value) not in (int, float) or not math.isfinite(value) or int(value) != value:
            issue(issues, "SCHEMA_TYPE", path)
        elif value < schema.get("minimum", float("-inf")):
            issue(issues, "SCHEMA_MINIMUM", path)
    elif kind == "boolean" and type(value) is not bool:
        issue(issues, "SCHEMA_TYPE", path)


def _key_for(envelope, trusted_keys):
    if not isinstance(trusted_keys, (list, tuple)) or len(trusted_keys) > 128:
        raise ValueError("Configure at most 128 explicitly trusted keys.")
    receipt, proof = record(record(envelope).get("receipt")), record(record(envelope).get("proof"))
    issuer = record(receipt.get("issuer"))
    matches = [key for key in trusted_keys if isinstance(key, dict) and key.get("issuerId") == issuer.get("id") and key.get("keyId") == issuer.get("keyId") and key.get("verificationMethod") == proof.get("verificationMethod")]
    if len(matches) != 1:
        return None
    key = matches[0]
    jwk = record(key.get("publicJwk"))
    events = key.get("keyLifecycle")
    if not key.get("issuerId") or key.get("environment") not in {"SANDBOX", "TEST", "PRODUCTION"} or not isinstance(events, list) or len(events) > 128 or not all(isinstance(event, dict) for event in events) or "d" in jwk or jwk.get("use") != "sig":
        return None
    return key


def _base64url(value):
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        raise ValueError("Invalid base64url value.")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def verify_mer(envelope, *, trusted_keys, verification_time=None, predecessor_envelope=None):
    """Verify against caller-selected trust. A valid signature is not a truth attestation."""
    canonicalize_json(envelope)
    if predecessor_envelope is not None:
        canonicalize_json(predecessor_envelope)
    at = verification_time or datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    issues = []
    _schema_check(MER_SCHEMA, envelope, "$", issues)
    key = _key_for(envelope, trusted_keys)
    root = record(envelope)
    receipt, proof = record(root.get("receipt")), record(root.get("proof"))
    jwk = record(key.get("publicJwk")) if key else {}
    supported = bool(key and jwk.get("kid") == key.get("keyId") and jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519" and jwk.get("alg") == "EdDSA")
    signature_valid, digest = False, None
    if isinstance(root.get("receipt"), dict) and isinstance(root.get("proof"), dict):
        if not supported:
            issue(issues, "UNSUPPORTED_VERIFICATION_METHOD", "$.proof.verificationMethod")
        schema_valid = not any(item["code"].startswith("SCHEMA_") for item in issues)
        if supported and schema_valid:
            commerce = record(receipt.get("commerce"))
            funding = record(record(receipt.get("economics")).get("paymentFunding"))
            if key["environment"] in {"SANDBOX", "TEST"}:
                if commerce and commerce.get("activityClass") != "INTERNAL_TEST":
                    issue(issues, "KEY_ENVIRONMENT_CLAIM_MISMATCH", "$.receipt.commerce.activityClass")
                if commerce and commerce.get("realMoneyMoved") is not False:
                    issue(issues, "KEY_ENVIRONMENT_CLAIM_MISMATCH", "$.receipt.commerce.realMoneyMoved")
                if funding and funding.get("environment") != "TEST":
                    issue(issues, "KEY_ENVIRONMENT_CLAIM_MISMATCH", "$.receipt.economics.paymentFunding.environment")
            if key["environment"] == "PRODUCTION":
                if commerce.get("activityClass") == "INTERNAL_TEST":
                    issue(issues, "KEY_ENVIRONMENT_CLAIM_MISMATCH", "$.receipt.commerce.activityClass")
                if funding and funding.get("environment") != "PRODUCTION":
                    issue(issues, "KEY_ENVIRONMENT_CLAIM_MISMATCH", "$.receipt.economics.paymentFunding.environment")
                if commerce.get("realMoneyMoved") is True and not isinstance(commerce.get("commercialPolicy"), dict):
                    issue(issues, "PRODUCTION_COMMERCIAL_POLICY_MISSING", "$.receipt.commerce.commercialPolicy")
        parent, parent_digest = None, None
        if isinstance(predecessor_envelope, dict):
            parent = predecessor_envelope.get("receipt") if isinstance(predecessor_envelope.get("receipt"), dict) else predecessor_envelope
            parent_digest = hash_mer_value(parent)
        if key and schema_valid:
            issues.extend(semantic_integrity(root, key["keyLifecycle"], at, parent, parent_digest))
        if schema_valid:
            canonical = canonicalize_json(receipt).encode("utf-8")
            digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
            if supported:
                try:
                    public_key = Ed25519PublicKey.from_public_bytes(_base64url(jwk.get("x")))
                    public_key.verify(_base64url(proof.get("proofValue")), canonical)
                    signature_valid = True
                except InvalidSignature:
                    pass
                except (ValueError, TypeError):
                    issue(issues, "CANONICALIZATION_FAILED", "$.receipt")
        if supported and not signature_valid and schema_valid:
            issue(issues, "SIGNATURE_INVALID", "$.proof.proofValue")
    codes = {entry["code"] for entry in issues}
    valid = not issues and signature_valid
    return {
        "valid": valid, "draft": True, "productionSigning": bool(key and key["environment"] == "PRODUCTION" and valid), "retained": False,
        "checks": {
            "schema": not any(code.startswith("SCHEMA_") for code in codes), "supportedIssuer": supported,
            "signature": signature_valid, "canonicalDigest": digest,
            "keyLifecycle": not any(code.startswith("KEY_") for code in codes),
            "proofBinding": not any(code.startswith("PROOF_") or code == "EVENT_AFTER_ISSUANCE" for code in codes),
            "economicConsistency": not any(code.startswith(("ECONOMIC_", "COMMERCE_", "FUNDING_", "SETTLEMENT_")) for code in codes),
            "correctionLineage": not any(code.startswith("CORRECTION_") or code == "UNEXPECTED_CORRECTION_DETAILS" for code in codes),
        }, "issues": issues,
    }


def verify_mer_chain(envelopes, *, trusted_keys, verification_time=None):
    if not isinstance(envelopes, list) or not 1 <= len(envelopes) <= 64:
        raise ValueError("A MER chain must contain between 1 and 64 envelopes.")
    entries = {}
    for envelope in envelopes:
        canonicalize_json(envelope)
        receipt_id = record(record(envelope).get("receipt")).get("receiptId")
        if not isinstance(receipt_id, str) or receipt_id in entries:
            raise ValueError("A MER chain requires distinct receipt identifiers.")
        entries[receipt_id] = envelope
    results, visiting = {}, set()

    def visit(receipt_id):
        if receipt_id in results:
            return results[receipt_id]
        if receipt_id in visiting:
            raise ValueError("MER correction lineage contains a cycle.")
        visiting.add(receipt_id)
        envelope = entries[receipt_id]
        parent_id = record(envelope["receipt"].get("correction")).get("predecessorReceiptId")
        parent = entries.get(parent_id) if isinstance(parent_id, str) else None
        result = verify_mer(envelope, trusted_keys=trusted_keys, verification_time=verification_time, predecessor_envelope=parent)
        if parent is not None and not visit(parent_id)["valid"]:
            result["valid"] = result["productionSigning"] = result["checks"]["correctionLineage"] = False
            issue(result["issues"], "CORRECTION_PREDECESSOR_INVALID", "$.receipt.correction.predecessorReceiptId")
        visiting.remove(receipt_id)
        results[receipt_id] = result
        return result

    receipts = [{"receiptId": receipt_id, **visit(receipt_id)} for receipt_id in entries]
    return {"valid": all(receipt["valid"] for receipt in receipts), "receipts": receipts}


def sign_mer_receipt(receipt, *, trusted_key, sign, verification_time=None, predecessor_envelope=None):
    """The signer accepts canonical UTF-8 bytes and returns a 64-byte Ed25519 signature."""
    snapshot = parse_mer_json(canonicalize_json(receipt))
    envelope = {"receipt": snapshot, "proof": {"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "created": snapshot.get("issuedAt"), "verificationMethod": trusted_key.get("verificationMethod"), "proofValue": "A" * 86}}
    options = {"trusted_keys": [trusted_key], "verification_time": verification_time, "predecessor_envelope": predecessor_envelope}
    preliminary = verify_mer(envelope, **options)
    invalid = [item["code"] for item in preliminary["issues"] if item["code"] != "SIGNATURE_INVALID"]
    if invalid:
        raise ValueError("Refusing to sign an invalid MER: " + ", ".join(invalid))
    signature = sign(canonicalize_json(snapshot).encode("utf-8"))
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise ValueError("The signer must return a 64-byte Ed25519 signature.")
    envelope["proof"]["proofValue"] = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    if not verify_mer(envelope, **options)["valid"]:
        raise ValueError("The returned signature does not verify against the configured issuer key.")
    return envelope
