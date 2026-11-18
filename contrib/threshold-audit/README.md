# Threshold audit recovery experiment

This is an **unaudited research prototype**, with an opt-in native consensus
experiment for custom Elements test chains. It exercises verifiable recovery
against **real Elements asset and value commitments** using this checkout's
libsecp256k1-zkp. The native experiment adds output recovery witnesses, node
validation, native wallet/PSET generation and dedicated DynaFed governance fields.
Separate guardian processes exercise historical-key handoff and disclosure. It is not a production
cryptosystem. See [NATIVE-INTEGRATION.md](NATIVE-INTEGRATION.md) for the native
scope, build instructions and two-node functional test.

The [settlement sandbox](SETTLEMENT-SANDBOX.md) adds a local
bank/corporate wallet GUI, independent operator approval windows and actual
federation-multisig UNITED EUR/USD test-token issuance, redemption and refunds. Its reserve
accounts and bank payments are explicitly simulated; the redemption obligor is
undecided. Run it separately from the cryptographic-only examples below.
Its demo manager provides one selected runtime with `status`, `stop` and
idempotent `start` commands, so superseded milestone stacks can stay offline.
The [same-chain federation rotation milestone](FEDERATION-ROTATION.md) connects
native DynaFed block signing, 7-of-10 to 11-of-15 historical-share handoff,
treasury migration, in-flight redemptions and the lifecycle GUI.
It also supports repeated A-to-B-to-C handovers, preserving confirmed escrow
migration history and access to earlier recovery packets. The
[verification runner](VERIFICATION.md) builds and tests a private runtime with
restarts and failure recovery, and exports a clean-apply review patch series.
The [cryptographic review package](review/README.md) describes the exact wire
protocol, trust assumptions and deterministic public test vectors.

The original `TAR1` bitwise scheme remains the reference. The additional `TAC2`
scheme in `chunked.py` preserves complete-opening recovery while reducing the
two-asset recovery package from 111,940 to **54,628 bytes**. It uses 36 encrypted
16-bit chunks, native range proofs, and representation proofs linking those
ranges to the ciphertexts. See [OPTIMIZATION.md](OPTIMIZATION.md) for equations,
measurements, review findings, alternatives and remaining limitations.

A chain can also require a quorum of the federation's operators to authorize
every transaction; see [TRANSACTION-AUTHORIZATION.md](TRANSACTION-AUTHORIZATION.md).

[DYNAFED-AUDIT-SPEC.md](DYNAFED-AUDIT-SPEC.md) specifies the proposed public
governance and historical-key lifecycle. `governance.py` is an executable model
of it. The native implementation ports TAG1 manifests and TAP1 readiness into
header validation; see [NATIVE-GOVERNANCE.md](NATIVE-GOVERNANCE.md).
`lifecycle_demo.py` connects TAC2,
signed disclosure, simulated 7-of-10 to 11-of-15 handoff, genuine key rollover
with historical-key retention, and reorg policy rollback. Native governance
requires a signed share-possession quorum for every retained historical key.
Wallet/PSET generation is integrated for supported single-owner workflows; see
[NATIVE-WALLET.md](NATIVE-WALLET.md). The node tests independently check its
packets using Python. Separate mutual-TLS guardian processes generate and hand
off shares without returning them to the public coordinator, persist all keys,
and record authorized disclosures; see [GUARDIAN-SERVICES.md](GUARDIAN-SERVICES.md).

The experiment demonstrates:

- Public verification that encrypted recovery information matches an output.
- Recovery of amount, asset ID, and both blinding factors by 7 of 10 members.
- Recipient range-proof rewinding using the existing Elements ECDH nonce scheme,
  without contacting the federation.
- A simulated handoff to an entirely new 11-of-15 committee, preserving the public
  audit key and access to the unchanged historical recovery packet.
- Signed, narrowly scoped approvals using separate BIP340 signing keys and an
  in-memory hash-chained disclosure log containing no recovered openings or
  partial decryptions.
- Adversarial rejection tests, including false openings with otherwise valid
  bit-encryption proofs.

The tests also demonstrate two limits: retained old quorum shares still decrypt,
and a quorum can bypass the demonstration approval/logging workflow.

## Run

Use Python 3.10 or later and CMake 3.22 or later. No Python packages, downloaded
dependencies, daemon, Bitcoin peg, or running chain are required. From the repo
root, build the bundled library in a scratch directory:

```sh
cmake -S src/secp256k1 -B /tmp/elements-audit-secp \
  -DBUILD_SHARED_LIBS=ON \
  -DCMAKE_BUILD_TYPE=Release \
  -DSECP256K1_BUILD_TESTS=OFF \
  -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF \
  -DSECP256K1_BUILD_CTIME_TESTS=OFF \
  -DSECP256K1_BUILD_BENCHMARK=OFF \
  -DSECP256K1_ENABLE_MODULE_BPPP=OFF
cmake --build /tmp/elements-audit-secp -j 4
python3 contrib/threshold-audit/demo.py \
  --library /tmp/elements-audit-secp/lib/libsecp256k1.so
python3 contrib/threshold-audit/lifecycle_demo.py \
  --library /tmp/elements-audit-secp/lib/libsecp256k1.so \
  --output /tmp/elements-audit-measurements.json
env THRESHOLD_AUDIT_SECP256K1=/tmp/elements-audit-secp/lib/libsecp256k1.so \
  python3 -m unittest discover -s contrib/threshold-audit -v
```

On macOS use the corresponding `.dylib` path. Generator, rangeproof, extrakeys,
and schnorrsig modules must be enabled; this checkout enables them by default.
Both demos print JSON results and local timings, never secret shares or openings.
Its timings include Python/ctypes overhead and are not distributed-system or
full-node throughput measurements.

## Construction

All group operations use secp256k1, with generator `G` and order `q`. Let the
federation's public audit key be `Y = x G`. The native library generates the
asset-specific point `H(asset_id)` using Elements' actual generator derivation.
An output has public points:

```text
A = H(asset_id) + a G       asset commitment, asset blinder a
V = amount A + b G         value commitment, value blinder b
```

`curve.py` uses public native generator/commitment APIs and translates their
quadratic-residue point encodings to ordinary compressed SEC points. It does not
depend on the in-memory representation of opaque native structures. Asset IDs
are raw 32-byte IDs in Elements internal byte order, not RPC display-order hex.

### Bitwise encryption

The recovery packet encrypts 64 amount bits, 256 asset-blinder bits, and 256
value-blinder bits. Each bit uses independent random nonzero `r`:

```text
R = r G
S = r Y + bit B
```

The message base `B` is `A` for amount bits and `G` for blinder bits. A
Fiat-Shamir OR-composed Chaum-Pedersen proof establishes either:

```text
log_G(R) = log_Y(S)        bit = 0
log_G(R) = log_Y(S - B)    bit = 1
```

Thus each decryption is either infinity or its public message base. This avoids
having to recover an arbitrary scalar from a group element by solving a large
discrete logarithm. It deliberately favors a transparent baseline over size.

For each field, combine its ciphertexts with little-endian weights `2^j`:

```text
(R_m, S_m) = encryption of amount A
(R_a, S_a) = encryption of a G
(R_b, S_b) = encryption of b G
```

### Binding the asset

The caller supplies a trusted, sorted registry of distinct asset IDs. An OR
proof over the registry proves, for one hidden candidate `asset_j`:

```text
log_G(R_a) = log_Y(S_a - A + H(asset_j))
```

Together with the bit proofs, this establishes that the encrypted asset blinder
opens `A` to a registered asset. After threshold decryption, compute `A - a G`
and look up the unique matching native generator to recover the asset ID.

This is an explicit design choice to avoid proving the nonlinear asset-generator
derivation inside a general-purpose circuit. Proof size and verification grow
with registry size. The experiment caps the registry at 256 entries; this is
NOT an Elements protocol limit. A production design must define an authenticated
registry root, issuance eligibility and any private candidate-set selection. A
small candidate set can itself leak asset information. This proof does not
replace Elements' existing surjection proofs or establish input provenance.

### Binding the amount and value blinder

A further Chaum-Pedersen proof establishes:

```text
log_G(R_m + R_b) = log_Y(S_m + S_b - V)
```

Hence the encrypted amount and value blinder open the actual value commitment.
Blinder bit vectors may encode an integer >= `q`; recovery normalizes them
modulo `q`. The amount is an unambiguous uint64 because `2^64 < q`. Existing
chain monetary limits and range-proof rules remain separate checks.

### Transcript binding and parsing

Every proof is domain-separated and bound to a digest of the externally supplied
statement and the ENTIRE ciphertext vector. Per-bit labels include the bit
index. The statement includes chain ID, transaction-template digest, output
index, script, native commitments, audit public key, and full registry. Hash
inputs are length-prefixed. Proof scalars must be canonical and points must be
on the curve. Infinity is forbidden for public audit keys and ciphertext `R`.

`Packet.from_bytes` requires the exact expected size, rejects trailing bytes and
unknown versions, and derives branch counts from the trusted statement. The
wire experiment uses 33 zero bytes to represent infinity; this is not an
Elements wire encoding. Packets contain no secret witnesses or master keys.

The transaction-template digest must exclude the recovery packet to avoid
circular hashing. Standalone demos use a synthetic caller input. The native
experiment defines it as the double-SHA256 of the transaction's nonwitness
serialization with all input scriptSigs cleared. All output commitments, nonces
and scripts remain bound. The native node derives the audit key and registry
from chain state, includes recovery data in witness hashes, and retains existing
transaction signing rules; see the native integration document for limits.

## Threshold operations and rotation

`threshold.py` simulates additive contributions of degree `t-1` Shamir
polynomials with Feldman commitments. For handoff, a selected old quorum
computes Lagrange coefficients `lambda_i` at zero. Each old member contributes
a new random degree `t_new-1` polynomial with constant `lambda_i * old_share_i`.
Its public constant commitment is checked against the old verification key,
and every recipient's private evaluation is checked against its commitments.
Adding the contributions gives fresh shares of the same secret. The code never
explicitly interpolates the master scalar, but one process sees all private
contributions: **this is not distributed key generation or secure transport**.

For each ciphertext first component `R`, a member produces `D_i = share_i R`
and a Chaum-Pedersen proof against its committee verification key. A distinct
quorum combines `sum(lambda_i D_i) = x R`; the plaintext is `S - x R`.
The returned amount, ID and blinders are checked again with the native library.

Partial proof transcripts bind the committee epoch/roster, exact ciphertext
context and request digest. API checks reject mixed epochs and wrong requests.
These checks do not cryptographically revoke copied old quorum shares or make
already released decryption points expire. With the same public key, a retained
old quorum can also decrypt future packets. Refresh assumes obsolete shares
are securely erased; Python cannot provide this property.

## Approval and audit demonstration

Each institution has an independent BIP340 signing key for approvals, separate
from its decryption share. A request binds the policy, output statement, exact
packet bytes, opaque case reference, intended recipient key, and expiry. The
service validates a threshold of distinct approval signatures before producing
decryption shares. The log records signed approval evidence and authorized,
completed or failed events; it does not publish partial decryptions, openings,
or private handoff contributions. A verifier needs the request and trusted
policy separately to verify the logged approval signatures.

The standalone `disclosure.py` log is in memory. A separately retained head detects alteration/truncation
relative to that checkpoint; the code does not supply independent witnesses,
durable storage, anti-fork guarantees, or log inclusion enforced by hardware.
Recipient identity binding is metadata only: authenticated encrypted delivery
is not implemented. The low-level threshold primitives intentionally remain
callable without this service. A colluding quorum can decrypt without a log.

The separate guardian service adds durable fsynced logs, signed checkpoints,
independent institutional approval credentials and recipient-pinned mutual-TLS
delivery. It still cannot force a colluding quorum to use that service, and
independent checkpoint retention remains an operating requirement.

## Size baseline and next engineering decisions

For `k` registry assets, an original TAR1 packet is exactly:

```text
4 + 576 * (66 + 128) + 64*k + 64 bytes
```

With two assets this is **111,940 bytes per output**, additional to the ordinary
transaction and its existing proofs. Each private partial response also contains
576 points and 576 DLEQ proofs. This is a feasibility baseline, not an acceptable
production fee/weight proposal. Optimize/review the proof construction before
considering consensus deployment; the bitwise design is not presumed optimal.

Before a production fork, required work includes:

1. Independent cryptographic review and a formal security/composition analysis,
   including Fiat-Shamir assumptions, adversarial keys, ciphertext malleability,
   and the authorized decryption interface. This is not a general-purpose
   authenticated/CCA-secure encryption API.
2. A concrete optimized proof construction with verification/proving benchmarks,
   denial-of-service limits, test vectors, and fuzzing of native-facing inputs.
3. An actively secure DKG/refresh/handoff protocol with authenticated confidential
   channels, reliable broadcast, complaints, recovery and erasure assumptions.
   Decryption threshold alone does not establish a handoff fault tolerance bound.
4. Hardware/key-service integration, independent backups, checkpointed durable
   disclosure records, approved-recipient authentication and encrypted delivery.
5. Production review and optimization of the experimental consensus checks,
   witness/hash semantics and block resource limits; wallet/PSET support and
   complete federation governance.
6. Recovery support for confidential issuance/reissuance amounts (currently
   rejected by the native experiment), broader output modes, and operational
   historical-key retention across every committee change.
7. A separately specified identity credential/registry layer if legal-party or
   underlying customer identification is required.

Python scalar operations and public-key tweak operations in this experiment do
not provide constant-time secret handling, process isolation or zeroization.
Never load production federation shares, wallet keys or customer data into it.

## References

- [Elements confidential transactions](https://elementsproject.org/features/confidential-transactions)
- [SLIP-0077: recipient blinding key and nonce derivation](https://github.com/satoshilabs/slips/blob/master/slip-0077.md)
- [ElectionGuard specifications: encrypted-bit and Chaum-Pedersen proof patterns](https://www.electionguard.vote/spec/)
- [Camenisch–Shoup: verifiable encryption of commitment openings](https://www.shoup.net/papers/verenc.pdf)
- [CHURP: proactive secret sharing in dynamic environments](https://www2.eecs.berkeley.edu/Pubs/TechRpts/2019/Archive/EECS-2019-62.pdf)
- [Kroll et al.: accountable cryptographic access control](https://www.cs.yale.edu/homes/jf/kroll-paper.pdf)

These references motivate the components. They do not constitute a proof of
security or endorsement of this particular composition or implementation.
