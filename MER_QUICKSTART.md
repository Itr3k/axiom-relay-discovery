# Verify your first MER

Use the published 0.1.0 artifacts without an Axiom account or wallet. Installation downloads the package; verification itself runs offline. Node.js 20+ and Python 3.10+ are supported. These are GitHub release installations; npm/PyPI registry publication is not being claimed.

The examples below use a checkout of this repository as the working directory. Python installation belongs in your application's virtual environment.

## Node.js

```sh
npm install --ignore-scripts https://github.com/Itr3k/axiom-relay-discovery/releases/download/mer-v0.1.0/axiom-relay-mer-0.1.0.tgz
node examples/mer-verify.mjs
```

The [example](examples/mer-verify.mjs) loads the packaged public fixture, checks it against its explicitly supplied fixture trust and fixed time, then verifies that changing the amount is rejected.

## Python

```sh
python -m pip install "https://github.com/Itr3k/axiom-relay-discovery/releases/download/mer-v0.1.0/axiom_mer-0.1.0-py3-none-any.whl#sha256=8f838a1b7013fa4aac8f971af9ccf8262c987fa634a59ba9963c010cd4682028"
python examples/mer_verify.py
```

The [Python example](examples/mer_verify.py) performs the same checks. Both examples report `synthetic: true`, `originalVerified: true` and `tamperingRejected: true`. They move no funds and are not evidence of customer adoption. Published [SHA-256 checksums](https://github.com/Itr3k/axiom-relay-discovery/releases/download/mer-v0.1.0/SHA256SUMS.txt) cover the release files.

## Use your own receipt

Replace the example envelope with your service's receipt. Supply your issuer's public key, issuer ID, environment and key lifecycle from a source you independently trust. Use the current verification time for real checks; the fixed time above belongs only to the historical fixture. Keep test and production trust separate. A key supplied inside an untrusted receipt is not an independent trust source.

Use `signMerReceipt` / `sign_mer_receipt` with your own signing callback to issue MER; use `verifyMerChain` / `verify_mer_chain` when validating corrections and their ancestors. See the [SDK contract and language examples](packages/mer) and the [x402 interoperability example](packages/mer/examples/x402). MER remains Draft 0.1 and does not certify the truth of a receipt's claims.

For an adoption pilot, add MER to one real service result, independently verify it in a second component, and retain a nonsensitive example showing both working. Repeat use is stronger evidence than a download. Share implementation feedback through [Issues](https://github.com/Itr3k/axiom-relay-discovery/issues) or [Builders](https://axiomrelay.io/commons); do not share private receipts or keys. The SDK sends no adoption telemetry.
