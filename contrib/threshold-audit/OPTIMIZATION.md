# Full-opening recovery optimization

Status: executable research design, not a cryptographic audit. An opt-in native
Elements integration is described in [NATIVE-INTEGRATION.md](NATIVE-INTEGRATION.md).
The original TAR1 scheme remains the reference. TAC2
preserves recovery of the amount, asset ID, asset blinding scalar, and value
blinding scalar; it does not silently switch to a financial-only capability.

## Choice and alternatives

The original uses 576 independent encrypted bits and zero/one proofs. TAC2 uses
36 encrypted 16-bit limbs. A small limb is efficiently recoverable from its
group encoding using bounded baby-step/giant-step (BSGS). The existing native
Elements range-proof implementation proves that each encrypted limb is in the
required range, with an additional representation proof linking that commitment
to the ciphertext. No new native proof library or dependency was introduced.

The important subtlety is that an ordinary native range proof alone does NOT
prove anything about an accompanying ElGamal ciphertext. A separate linking
proof is required. Nor can we use `m G + u G` as a binding range commitment:
the message and blinding bases must have unknown discrete-log relation.

Other candidates considered:

- **Financial-only recovery:** omit encrypted blinding scalars, encrypt the asset
  generator directly and prove its relationship to the asset commitment. With
  four 16-bit amount limbs this could be roughly 6.4 KB for two registry assets,
  but does not recover complete openings. This is an explicit capability choice,
  not an apples-to-apples optimization. It is not implemented here.
- **Larger limbs:** native 32-bit proofs reduce per-limb overhead further, but
  bounded DLog recovery needs materially more memory and work. The 16-bit choice
  bounds each decoder at 256 baby and 256 giant steps. It is not claimed optimal.
- **General-purpose ZK or specialized verifiable scalar encryption:** potentially
  much smaller; requires selecting and reviewing a concrete proof/encryption
  stack, including cross-group/circuit costs, setup and threshold key lifecycle.
- **Bundled Bulletproofs++:** this checkout's public BPPP header exposes generator
  APIs, not a ready-to-use range-proof API. It is not a drop-in optimization.

## TAC2 statement and equations

Use the same public `Statement` and actual Elements commitments as TAR1:

```text
A = H(asset_id) + a G
V = amount A + b G
Y = x G                         public audit key
```

Split amount into four 16-bit limbs and each blinding scalar into sixteen.
For each limb `m`, choose independent fresh encryption randomness `r` and
range-commitment randomness `u`. Let `B=A` for amount limbs and `B=G` for scalar
limbs. A fixed domain-derived asset ID produces an independent native NUMS
generator `H_range`; do not substitute a point with known discrete log to `G`.

```text
R = r G
S = m B + r Y                   ordinary exponential ElGamal ciphertext
T = m H_range + u G             independent native Pedersen range commitment
```

The native range proof for `T` must verify with EXACT bounds `(0, 65535)` under
`H_range`. Valid range proofs with other bounds are insufficient. A Schnorr-style
representation proof establishes knowledge of `(m,r,u)` satisfying ALL three
equations. Its responses `(z_m,z_r,z_u)` reconstruct the prover commitments:

```text
Q1 = z_r G - c R
Q2 = z_m B + z_r Y - c S
Q3 = z_m H_range + z_u G - c T
```

The challenge hashes the complete statement and these reconstructed points.
Under commitment binding and the proof-of-knowledge assumptions, the scalar in
the ciphertext is the small scalar committed by `T`.

The scalar normalization convention is unchanged: the two 256-bit limb vectors
may encode integers >= curve order `q`; recovery reduces them modulo `q`. The
64-bit amount is never reduced modulo a smaller application limit. Existing
Elements monetary/range/transaction rules remain independent requirements.

Weight each field's ciphertexts by `2^(16*j)`. The resulting aggregates have
exactly the same meanings as TAR1. Retain the registry OR proof linking the asset
blinder to `A`, and the value consistency proof linking amount and value blinder
to `V`. Both are bound to the new scheme domain and transcript. Recovery uses
threshold partial decryptions, bounded DLog per limb, field reconstruction,
registry resolution, and final native commitment checks.

## Transcript, encoding and resource boundaries

Transcript layering is intentionally acyclic:

1. Prepare every ciphertext `(R,S)` and native range commitment `T`.
2. Hash the scheme, full public statement, fixed range generator and entire
   `(R,S,T)` vector into an envelope context.
3. Each native range proof uses an `extra_commit` containing the envelope and
   chunk index.
4. Each representation proof also binds every actual native range-proof byte
   string and its chunk index.
5. Aggregate asset/value proofs additionally bind all representation proofs.
6. Partial-decryption proofs bind the complete serialized packet, the current
   committee and the disclosure-request digest.

`TAC2` is a distinct four-byte magic, with exactly 36 chunk records. Each record
has `(R,S,T)` (99 bytes), a two-byte proof length, a bounded native proof and four
canonical representation-proof scalars (128 bytes). Final proofs contain two
scalars per registry asset plus two for value consistency. The parser rejects
unsupported magic, truncation, trailing bytes, noncanonical scalars, invalid
points, infinite `R`, invalid commitments and overlarge range proofs before
passing proof data to the native verifier. Range-proof lengths are capped at
1,536 bytes as an experiment bound; generated 16-bit proofs measure 1,283 bytes.

For `k` registry assets and these generated proof lengths:

```text
4 + 36 * (66 + 33 + 2 + 1283 + 128) + 64*k + 64 bytes
```

The two-asset package is **54,628 bytes**, versus TAR1's 111,940 bytes: a 51.2%
reduction with the same complete-opening capability. It remains too large to
assume a production fee/weight policy. Registry scaling remains linear.

## Verification and measurements

Run `lifecycle_demo.py` using the README's command. It measures both schemes
against the same actual output commitments and quorum, verifies both full
openings, and exercises recipient rewind, governance handoff, authorized current
committee disclosure, genuine key rollover retaining historical keys, stale
pending-output rejection and public-policy rollback after a reorg.

[measurements.example.json](measurements.example.json) records one local run.
Sizes are deterministic for the stated configuration. Timings are one sample
of Python/ctypes operations in one process, not statistical performance claims,
network ceremony times, node throughput or production HSM measurements.

The adversarial tests cover valid native ranges with invalid links, valid links
with wrong native ranges, well-formed limbs with false aggregate openings,
zero/max limbs and amounts, scalar aliases, both asset registry branches,
more-than-threshold quorums, malformed native-facing inputs, cross-output
splicing, replay under changed statements, membership handoff, independent
approval signatures, key rollover and reorg lifecycle behavior.

## Independent reviews and resulting fixes

Two independent agents reviewed algebra and implementation, including a fresh
reviewer without the implementation discussion. This is not an external expert
audit or a formal security proof.

- The fresh reviewer reproduced a substantive accepted-manifest issue:
  `f(X)=17*(X-1)` advertises a degree-one 2-of-3 sharing but has a publicly known
  zero share at member 1. A caller could fabricate that member's partial. The
  committee validator now rejects infinite member verification keys, with a
  regression test. This protects both schemes and the governance model.
- The algebra reviewer identified weaker standalone TAC2 partial-verifier
  validation. It now validates the public statement and explicitly rejects
  invalid/infinite ciphertext first components. Combined recovery already
  verified the complete packet before accepting partials.
- Review requested successful recovery from the non-first registry branch and
  quorums larger than `t`; both are now tested.

Manifest checks do NOT prove threshold privacy for arbitrary adversarial
polynomials. Known/correlated coefficients or deliberately leaked shares can
lower effective secrecy. The promised privacy threshold depends on an actively
secure, correctly randomized distributed ceremony and its corruption model;
it cannot be inferred from a polynomial's degree or readiness certificate alone.

## Native integration and remaining work

The opt-in custom-chain patch now verifies TAC2 in C++, requires recovery
witnesses in mempool and block validation, binds an actual transaction template,
and carries a dedicated audit key/version through DynaFed. A separate budget of
16 confidential outputs per block bounds experimental verification work, and
the miner respects it. Existing networks retain their original serialization.
The native functional test constructs and signs actual wallet transactions
using an external Python package constructor.

Native wallet/PSET generation now supports single-owner final blinding. Native
governance includes committee manifests and signed readiness for every retained
key. Separate guardian processes demonstrate all-key handoff and durable
authorized disclosure. The public transition specification is in
[DYNAFED-AUDIT-SPEC.md](DYNAFED-AUDIT-SPEC.md). Collaborative PSET staging,
dynamic asset registries and production distributed key management remain open.

Before deployment, this composition needs specialist security review, an
authorized-decryption security model, a reviewed distributed DKG/refresh/handoff
protocol, protected key services, authenticated recipient delivery and durable
independently witnessed audit infrastructure. The encryption remains malleable
and is not presented as a general-purpose authenticated/CCA-secure API. Python
secret arithmetic is not constant-time and does not provide secure erasure.
Copied old quorums and already released decryptions are not revoked by governance.
