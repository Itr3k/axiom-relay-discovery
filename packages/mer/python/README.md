# Axiom MER developer kit

MER is a portable Machine Economic Receipt format. This kit verifies receipt signatures, exact economics, issuer key lifecycle and correction lineage. It can also sign a receipt through an issuer-supplied signing function. It does not contact Axiom, provision keys, move money, store documents or send telemetry.

Package version: **0.1.0**. Supported receipt format: **MER Draft 0.1** (`0.1.0-draft`). A package release does not imply standards-body approval, x402 endorsement, external adoption or a completed security audit.

## Trust and scope

The application supplies the issuer ID, key ID, verification method, public Ed25519 JWK, environment and key lifecycle through a trust configuration obtained independently of the receipt. A receipt cannot establish its own trust by embedding a key or a URL. The verifier performs no URL fetching. Protect the source of that configuration; signature validity alone does not establish that the service ran, that a person consented, or that a claim is true.

`verifyMer` / `verify_mer` verifies one envelope and its binding to a supplied correction predecessor. Use `verifyMerChain` / `verify_mer_chain` to validate every supplied predecessor signature and the complete correction chain. Missing ancestors, duplicate receipt identifiers and cycles cannot produce a successful complete-chain result. Non-correction `previousEventIds` remain references, not independently proven events.

The supplied historical fixtures are synthetic and use public verification keys. They never prove production or outside usage. Production signing keys and fixture private keys are not included. Applications must keep sandbox/test and production trust separate, preserve append-only key lifecycle information, and handle compromise/revocation as new events. Only issuer-controlled code should call the signing API. The signing callback can be backed by a managed signing service; the SDK never stores a private key.

## Encoding and compatibility

The existing MER Draft 0.1 profile signs the UTF-8 canonical **receipt** object with Ed25519. Object keys sort by UTF-16 code units; arrays retain their order. The profile permits integral numeric fields only within JavaScript's safe integer range. Monetary amounts are exact decimal strings. Invalid Unicode, accessors, non-JSON objects, cycles, excessive depth and documents larger than 65,536 bytes are rejected. At most 64 envelopes can be checked as one correction chain.

The legacy proof label is `eddsa-jcs-2022`, but this is the existing Axiom receipt profile, not a claim of complete W3C Data Integrity cryptosuite conformance. `proof.created` must exactly match signed `receipt.issuedAt`. Existing signatures and schema remain compatible; a different signature input or receipt schema requires a separately versioned protocol change.

Results distinguish schema, signature, configured issuer, key lifecycle, proof binding, economic consistency and correction lineage. Decimal fee/total relations are checked without floating-point arithmetic. A successful result proves consistency with the chosen trust configuration; it is not a safety certification, financial authorization, payment confirmation from a blockchain, or an attestation of real-world truth.

## Conformance and license

`data/receipt-0.1.schema.json` is the public receipt schema. `data/vectors.json` contains 17 previously published signed fixtures, expected outcomes and fixed verification times, covering legacy receipts, tampering, future proofs, key activation/rotation/retirement/revocation/compromise, exact economics and corrections. Both packages consume the same files. Additional tests create independent ephemeral issuers and verify full-chain rejection and input bounds.

The included code, schema and fixtures are MIT-licensed; keep the copyright and license notices when redistributing. The license covers this kit, not Axiom's private platform, hosted services, customer data, signing keys, or branding. Commercial use of the kit does not automatically incur an Axiom fee.

Axiom's hosted MER Batch Audit is a separate paid workflow under development. Do not rely on it, a package registry release, or an x402 listing until their live status is verified at the [MER developer page](https://axiomrelay.io/developers/mer).

## Python

Requires Python 3.10 or newer and the `cryptography` library. The package includes its schema and public fixtures; it makes no network requests.

```python
from axiom_mer import verify_mer, verify_mer_chain, sign_mer_receipt

result = verify_mer(receipt_envelope, trusted_keys=configured_issuer_keys)
chain = verify_mer_chain(envelopes_including_predecessors,
                         trusted_keys=configured_issuer_keys)
signed = sign_mer_receipt(receipt, trusted_key=configured_issuer_key,
                          sign=issuer_signing_service.sign_ed25519)
```

The signing callback accepts canonical UTF-8 bytes and returns 64 raw signature bytes. The callback is synchronous; applications using asynchronous KMS clients should adapt their own signing boundary explicitly. Invalid schema, economics, issuer binding or key lifecycle is rejected before signing; the returned signature is verified before returning the envelope.

The offline CLI accepts a receipt file and a separate trusted-key array. Its exit status is 0 for a valid receipt, 1 for verification failure, and 2 for invalid input or an execution error.

Development reference: the package is built with the standard Python build frontend; tests use `unittest`. A wheel installation in a clean environment is tested before publication.

Timestamp profile: explicit RFC 3339 timezone, valid calendar dates and at most millisecond precision. Local dates, rollover dates, leap seconds and excess precision are rejected consistently in both languages.

## Release distribution

The initial implementation is distributed through the [MER 0.1.0 GitHub release](https://github.com/Itr3k/axiom-relay-discovery/releases/tag/mer-v0.1.0), with Node tarball, Python wheel/source archive and SHA-256 checksums. npm and PyPI registry publication is separate and is not claimed by these artifacts. The hosted paid workflow and x402 activation have independent deployment status.
