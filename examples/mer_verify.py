"""Public synthetic fixture only; no network, wallet, private key or Axiom account."""
import copy
import json
from importlib.resources import files
from axiom_mer import verify_mer

fixtures = json.loads(files("axiom_mer").joinpath("data/vectors.json").read_text())
fixture = next(item for item in fixtures["vectors"] if item["id"] == "legacy-fulfillment")
options = {"trusted_keys": fixture["trustedKeys"], "verification_time": fixture["verificationTime"]}
if not verify_mer(fixture["envelope"], **options)["valid"]:
    raise RuntimeError("Published fixture verification failed")
changed = copy.deepcopy(fixture["envelope"])
changed["receipt"]["economics"]["totalAuthorized"]["amount"] = "0.02"
if verify_mer(changed, **options)["valid"]:
    raise RuntimeError("Tampered fixture was accepted")
print(json.dumps({"synthetic": True, "originalVerified": True, "tamperingRejected": True, "networkRequests": 0}))
