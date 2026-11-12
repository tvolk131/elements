# External cryptographic review package

This is an engineering handoff for an **unaudited research fork**. It is not an
independent audit, security certification, production recommendation or claim
that passing the included tests establishes cryptographic security.

The package describes the code that exists, the assumptions it needs, concrete
known limits and questions an independent reviewer should resolve. Institutional
settlement and repeated membership rotation continue to evolve; identify the
exact source snapshot with the generated inventory before reviewing behavior.

## Start here

1. Generate the public source inventory and retain its digest with your report.
2. Read [PROTOCOL.md](PROTOCOL.md) for statement, wire encoding and invariants.
3. Read [THREAT-MODEL.md](THREAT-MODEL.md) for scope and unproven assumptions.
4. Run the Python and native expected-result vectors below.
5. Use [REVIEW-CHECKLIST.md](REVIEW-CHECKLIST.md) to record conclusions, findings,
   reproducible evidence, affected source hashes and unresolved questions.

Existing detailed references remain authoritative for implementation context:
[native integration](../NATIVE-INTEGRATION.md),
[governance](../NATIVE-GOVERNANCE.md), [wallet/PSET](../NATIVE-WALLET.md),
[TAC2 equations](../OPTIMIZATION.md), [guardian services](../GUARDIAN-SERVICES.md)
and [institutional rotation](../FEDERATION-ROTATION.md).

## Snapshot identity

```sh
python3 contrib/threshold-audit/review/inventory.py \
  --output /tmp/elements-review-inventory.json
```

The JSON contains `base_commit`, `submodules`, `working_tree_dirty`, `files`
with relative paths/size/SHA256, and `source_tree_digest`. The base commit pins
unchanged upstream source; the digest pins the complete selected experimental
source and native/test overlay. A dirty checkout is expected during development
and must not be confused with the base commit alone. Recompute the inventory
after source changes. Verification tooling records compiler/build artifacts and
execution evidence separately; source identity does not assert tests passed.

The inventory excludes runtime credential/state JSON, generated reports, build
output and Python caches. Only the explicitly named public vector JSON and
benchmark example JSON are included as source fixtures. It reads no running
sandbox, bank account, guardian private state or wallet. Reports should normally
be written outside the source checkout.

## Fixed PUBLIC TEST ONLY vectors

Every scalar, private identity, polynomial coefficient and nonce in
[vectors/public-v1.json](vectors/public-v1.json) is deliberately reconstructible
from constants in [vectors.py](vectors.py). **Do not use these values for funds,
live chains, production randomness or actual disclosures.** No runtime fixture
credentials or real guardian shares were used.

The fixture contains:

* A 54,628-byte two-asset TAC2 packet, full statement and expected opening.
* Exact envelope/range/consistency transcript digests.
* TAG1/TAP1 handoff from a fixed 2-of-3 sharing to a fixed 3-of-4 sharing of the
  same public test secret, with native BIP340 readiness signatures.
* A separately authorized registry append from version 0 to version 1.
* A fixed incoming-quorum decryption result and partial-point fingerprints.

These are synthetic statement vectors. Their `tx_digest_raw` is explicitly
synthetic, not an asserted real Elements txid. Real transaction-template
derivation, wallet integration, block ancestry, process isolation and lifecycle
behavior require the native functional/settlement acceptance tests. The vector
committee is directly constructed from public polynomials; it is not evidence
of a secure distributed key-generation ceremony.

Use the library built by the one-command verifier, or the bundled library:

```sh
python3 contrib/threshold-audit/review/vectors.py \
  --library /path/to/libsecp256k1.so --check
```

`--check` parses/verifies the packet and readiness in Python and regenerates the
entire fixture byte-for-byte. `--output FILE` regenerates a public fixture. It
temporarily replaces randomness inside that standalone test process; it does
not alter service code or install a deterministic production RNG. Deterministic
range-proof bytes are pinned to the bundled libsecp256k1-zkp behavior. A library
upgrade needs an explicit reviewed fixture update, not an automatic overwrite.

## Native expected-result checker

Configure the ordinary native build with `BUILD_FUZZ_BINARY=ON` and
`BUILD_FOR_FUZZING=OFF`, then:

```sh
cmake --build /path/to/native-build --target threshold_audit_vectors -j 4
/path/to/native-build/bin/threshold_audit_vectors \
  contrib/threshold-audit/review/vectors/public-v1.json
```

This C++ executable calls the actual native TAC2 verifier, TAG1 decoder,
configuration/policy binding functions and TAP1 proposal validator. It asserts
positive acceptance and negative rejection, including mutated chain/template/
script/index/registry, changed readiness, insufficient readiness, trailing bytes
and repeated warm-cache validation. It exits nonzero on any mismatch and prints
machine-readable counts on success. It does not implement threshold decryption
in C++; the Python check performs that part.

`threshold_audit_replay` remains useful parser corpus replay, but its fuzz target
intentionally ignores verification return values. A successful replay means no
parser crash for those inputs; it is not a positive proof-acceptance assertion.
Coverage-guided fuzzing still requires its separate fuzz build and campaigns.

## What a review report should deliver

Record the source inventory, toolchain/library hashes, inspected paths, modeled
adversaries, checked security properties, test commands/results, limitations and
each finding's severity/reproduction/remediation. Separate the algebra/proof
review, native consensus integration, implementation/side-channel review and
institutional control-plane review. Do not label automated subagent review or
successful acceptance runs as an independent cryptographic audit.
