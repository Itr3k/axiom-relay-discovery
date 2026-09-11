# MER alongside x402 signed offers and receipts

This local demonstration uses the official x402 2.25.0 offer-receipt extension and the MER SDK. It generates two ephemeral Ed25519 key pairs, independently verifies an x402 signed offer and receipt, then signs and verifies an MER whose result hash binds a bundle containing that evidence and an example report. Modifying the report breaks the hash binding. Wrong issuer keys fail verification.

It sends no network request, uses no real wallet and moves no funds. All receipts are synthetic test evidence. The example does not demonstrate a live facilitator settlement, directory listing, endorsement or independent customer adoption. Private keys exist only in process memory and are never printed or saved.

x402 already supports signed payment offers and service receipts. MER adds a separately verifiable record for exact economic allocations, service/result digests, privacy mode, lifecycle events and correction lineage. The two signatures retain their own issuer trust. Neither signature independently proves that a claimed real-world event happened. The caller must check actual settlement and the service's trust policy separately.

The bundle hash binds the particular x402 evidence and report to MER. It does not alter the x402 protocol, convert x402 receipts into MER, or make an EIP-3009 payment signature authorize arbitrary HTTP content.

For maintainers: build the TypeScript package, install this example's pinned dependencies, then execute its test script. The local file dependency keeps this example runnable before registry publication. Public data contains only synthetic fixtures and public verification keys.
