import base64
import copy
import json
import unittest
from importlib.resources import files
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from axiom_mer import canonicalize_json, hash_mer_value, sign_mer_receipt, verify_mer, verify_mer_chain

VECTORS = json.loads(files("axiom_mer").joinpath("data/vectors.json").read_text())["vectors"]


class MerTests(unittest.TestCase):
    def test_published_vectors(self):
        for vector in VECTORS:
            with self.subTest(vector=vector["id"]):
                result = verify_mer(vector["envelope"], trusted_keys=vector["trustedKeys"], verification_time=vector["verificationTime"], predecessor_envelope=vector.get("predecessorEnvelope"))
                self.assertEqual(result["valid"], vector["expected"]["valid"])
                self.assertEqual(result["checks"], vector["expected"]["checks"])
                self.assertEqual(sorted({issue["code"] for issue in result["issues"]}), vector["expected"]["issueCodes"])

    def test_independent_signer(self):
        private_key = Ed25519PrivateKey.generate()
        public_bytes = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        at = "2026-09-10T20:00:00.000Z"
        key = {"issuerId": "example-issuer", "keyId": "example-key-1", "verificationMethod": "https://example.invalid/keys#example-key-1", "environment": "TEST", "publicJwk": {"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": "example-key-1", "x": base64.urlsafe_b64encode(public_bytes).decode().rstrip("=")}, "keyLifecycle": [{"status": "ACTIVE", "effectiveAt": at, "recordedAt": at}]}
        receipt = copy.deepcopy(VECTORS[0]["envelope"]["receipt"])
        receipt.update(receiptId="mer_independent_python", issuedAt=at, issuer={"id": key["issuerId"], "keyId": key["keyId"]})
        receipt["event"]["occurredAt"] = at
        receipt["subject"]["providerId"] = "example-provider"
        result = sign_mer_receipt(receipt, trusted_key=key, sign=private_key.sign, verification_time=at)
        self.assertTrue(verify_mer(result, trusted_keys=[key], verification_time=at)["valid"])
        self.assertFalse(verify_mer(result, trusted_keys=[], verification_time=at)["valid"])
        self.assertFalse(verify_mer(result, trusted_keys=[key, key], verification_time=at)["valid"])
        with self.assertRaises(ValueError):
            sign_mer_receipt(receipt, trusted_key=key, sign=lambda _: bytes(64), verification_time=at)

    def test_chain_rejects_invalid_parent(self):
        child = next(vector for vector in VECTORS if vector["id"] == "refund-correction")
        parent = copy.deepcopy(child["predecessorEnvelope"])
        options = {"trusted_keys": child["trustedKeys"], "verification_time": child["verificationTime"]}
        self.assertTrue(verify_mer_chain([child["envelope"], parent], **options)["valid"])
        parent["proof"]["proofValue"] = "A" * 86
        self.assertFalse(verify_mer_chain([child["envelope"], parent], **options)["valid"])
        self.assertFalse(verify_mer_chain([child["envelope"]], **options)["valid"])

    def test_canonical_boundaries(self):
        self.assertEqual(canonicalize_json({"\ue000": 2, "😀": 1, "a": "雪\n", "z": 0}), '{"a":"雪\\n","z":0,"😀":1,"":2}')
        self.assertEqual(hash_mer_value({"b": 2, "a": 1}), hash_mer_value({"a": 1, "b": 2}))
        for value in (float("nan"), float("inf"), 0.1, 9007199254740992, "\ud800", "x" * 65537):
            with self.subTest(value=type(value).__name__), self.assertRaises(ValueError):
                canonicalize_json(value)
        cyclic = {}; cyclic["self"] = cyclic
        with self.assertRaises(ValueError):
            canonicalize_json(cyclic)


if __name__ == "__main__":
    unittest.main()
