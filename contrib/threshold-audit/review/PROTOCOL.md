# Protocol and native binding reference

This document specifies the current experiment for review. Source and the
snapshot inventory take precedence if the document and code differ; report such
disagreement. No security proof for this composition is supplied here.

## Domains, byte order and points

Let `q` be the secp256k1 group order, `G` its standard generator, and
`H(asset)` the native Elements asset generator. Hash transcripts use:

```text
D(label, parts...) = SHA256(
  u64BE(len(DOMAIN)) || DOMAIN || u64BE(len(label)) || label ||
  concat(u64BE(len(part)) || part for each part))
DOMAIN = ASCII("Elements/threshold-audit/experiment/v1")
challenge = intBE(D(...)) mod q
S(label, parts...) = D(ASCII("TAC2/") || label, parts...)
```

Fixed scalars are canonical 32-byte big-endian values below `q`. Native integer
fields explicitly described below use their stated width/endianness. Curve
points use compressed SEC bytes (prefix 02/03); 33 zero bytes represent infinity
only where explicitly allowed. Elements asset/value commitments use their
native quadratic-residue encodings (asset 0a/0b; value 08/09), not SEC parity.
The verifier checks coordinates and converts that encoding to curve points.

Chain/transaction hashes and asset IDs in the cryptographic statement use raw
32-byte internal order. RPC uint256 display hex reverses those bytes. Native
blind scalars are big-endian; RPC hash-style blinder encodings also require
explicit conversion. Review callers, not only cryptographic helpers.

## Output statement and transaction template

The trusted statement is:

```text
(chain_id, tx_digest, output_index, scriptPubKey, asset_commitment,
 value_commitment, audit_public_key, ordered_asset_registry)
statement_binding = D("statement", chain_id, tx_digest, u32BE(output_index),
  scriptPubKey, asset_commitment, value_commitment, audit_public_key,
  concat(raw32 asset IDs))
```

The registry is 1..256 nonzero IDs, sorted and unique in raw-byte order. Native
transaction integration computes `tx_digest` as double-SHA256 of nonwitness
transaction serialization after clearing every input scriptSig. It retains all
prevouts, input sequences, issuance fields, outputs/commitments/nonces/scripts,
version and locktime. It excludes all witnesses, including TAC2 packets, to
avoid circularity and permit subsequent signing. Synthetic reference vectors
do not substitute for testing this native derivation.

For a candidate block, validation selects the policy from the authenticated
predecessor/DynaFed context governing that block. Mempool, new wallet outputs
and PSET use the next-block snapshot. Historical disclosure reconstructs the
statement with the output's creation-block registry and retained public audit
key, then uses that key's current share committee. A registry append requires
pending confidential proofs to be regenerated, even for unchanged asset IDs.

## TAC2 equations

An opening is `(asset_id, v, a, b)` with `v` a uint64 and `a,b` canonical scalars:

```text
A = H(asset_id) + a G
V = v A + b G
Y = x G
```

Split `v` into four 16-bit limbs and each scalar into sixteen, least significant
limb first. For each of 36 limbs `m`, choose fresh `r,u`; set `B=A` for amount
limbs and `B=G` for scalar limbs:

```text
R = r G; S = m B + r Y; T = m H_range + u G
RANGE_ASSET = SHA256(ASCII("Elements/threshold-audit/TAC2/range-generator"))
H_range = H(RANGE_ASSET)
```

Native Pedersen range proofs must verify with **exact** bounds `[0,65535]` for
each `T`. Merely accepting a valid proof with another range is insufficient.
A representation proof `(c,z_m,z_r,z_u)` binds the same witnesses to all three
equations. Verification reconstructs `Q1=z_r G-c R`,
`Q2=z_m B+z_r Y-c S`, `Q3=z_m H_range+z_u G-c T`, and hashes those points with
the complete context and bases. The unknown discrete-log relation of the range
generator to `G` is required; substituting a known-log point breaks the intended
binding argument.

Weighted ciphertext sums with weights `2^(16*j)` reconstruct each field. An
OR-of-DLEQ proof shows that the encrypted asset blinder opens `A` to one listed
asset generator. A DLEQ proof connects encrypted amount plus value blinder to
`V`. The two recovered 256-bit integers are reduced modulo `q`; the amount is
not reduced. Existing Elements monetary balance, range, issuance, script and
transaction validity checks remain required.

Transcript order is acyclic:

1. `envelope = S("envelope", statement_binding, RANGE_ASSET, u32BE(16), concat(R||S||T))`.
2. Each native range proof binds `S("range", envelope, u32BE(index))` as extra commitment.
3. `proof_context = S("range-proofs", envelope, each range-proof byte string)`.
4. Each representation proof uses `S("bridge-index", proof_context, u32BE(index))`.
5. `consistency = S("consistency", proof_context, concat(all bridge scalars))`.
6. Asset/value consistency proofs use `S("asset",consistency)` and `S("value",consistency)`.

`TAC2` bytes are four magic bytes, then 36 records of `R[33],S[33],T[33],
range_length[u16BE],range_proof[1..1536],bridge_scalars[4*32]`, then two scalars
per registry entry and two value-proof scalars. There is no trailing data or
embedded registry. Infinite `R`, noncanonical scalars, malformed commitments,
oversized fields and unsupported magic fail. Two-asset generated proofs are
54,628 bytes. The conservative 256-asset maximum is **79,992 bytes**, within the
80,000-byte native witness/PSET field cap.

## Current committee recovery

Feldman coefficient commitments describe a degree `t-1` sharing polynomial
`f`, with public constant `Y=f(0)G` and member verification key
`Q_i=sum(i^j C_j)`. Coefficients' first/highest commitments and member public
shares must not be infinity. Those shape checks do not prove arbitrary dealer
coefficients hide the secret or establish a malicious-secure DKG.

Each participant computes `D_i=f(i)R` for every limb and supplies DLEQ knowledge
proofs linking `Q_i` and `D_i`. Context binds statement, complete packet digest,
current committee binding, disclosure-request binding, member and limb index.
The combiner rejects duplicate/insufficient members and invalid partials,
interpolates `xR`, obtains `mB`, solves the bounded 16-bit discrete log and
rechecks the full opening against `A,V`. No master scalar is required by that
combiner API. A copied old quorum can perform the same operation independently.

## TAG1, TAP1 and DynaFed

TAG1 layout, all integers big-endian:

```text
"TAG1" || generation[u32] || active_version[u32] || signer_policy[32]
identity_count[u8] || identity_count*(member_id[u32] || BIP340_xonly_key[32])
key_count[u8] || for each key:
  version[u32] || scheme[u16] || share_epoch[u32] || threshold[u8] || members[u8]
  member_ids[members*u32] || Feldman_commitments[threshold*33]
```

Members/identities are ordered and distinct; every retained key uses the current
roster; versions are contiguous from 1. At most 16 keys and 32 identities are
accepted; native recovery accepts only scheme 2. TAG1 is at most 20,334 bytes.
`config_binding=D("audit-config", TAG1_bytes)`.

The initial `signer_policy` is double-SHA256 of standard Elements serialization
of block signing script, witness limit, fedpeg program/script and extension
vector. Registry version zero is immutable genesis configuration and omitted
from that digest to avoid the default-policyasset/genesis/config hash cycle.
Its concrete IDs still enter DynaFed roots and output statements. For registry
versions greater than zero, append `ser_string("threshold-audit-assets-v1")`,
`u32LE(version)`, `CompactSize(count)` and raw IDs to that preimage. Updates must
be strict sorted supersets and increment version once; unchanged IDs must keep
the exact version. Overflow/deletion/substitution/reordering fail before cache
lookup. See [exact serialization](../NATIVE-GOVERNANCE.md).

TAP1 is `"TAP1" || previous_config_binding[32] || activation_height[u32BE] ||
count[u16BE] || count*readiness[136]`, bounded at 69,674 bytes. Each readiness is
`key_version[u32BE] || member[u32BE] || DLEQ(c,z)[64] || BIP340_signature[64]`.
It binds `D("audit-transition",chain,previous,u32BE(height),new_config_binding)`
and the particular key/member. This DLEQ specializes both bases to `G`; the
challenge transcript retains the duplicate bases/points from the reference
construction. The identity signature covers the complete possession proof.
Every retained key needs its own distinct threshold of readiness entries.

Generation increments once; key public identities and schemes are retained.
Changed committees increment share epoch once. A rollover may append one fresh
public key at epoch zero and makes it active; historical-only versions cannot
be reactivated. The prepared transition targets the native expected DynaFed
boundary, and the boundary block uses the winning current policy.

Full DynaFed entries append public key, version, TAG1, TAP1, registry version and
registry; the extra/full roots authenticate all fields. Compact entries must
match the expected elided root. Native validation enforces the complete public
history; it does not perform a key ceremony or make an unwilling quorum live.

## Native acceptance and caches

On an enabled custom chain, every paired confidential asset/value output needs
a valid TAC2 witness. Explicit asset+value outputs are public and carry none.
Mixed explicit/confidential modes, confidential coinbase outputs, confidential
issuance/reissuance amounts and unexpected proofs on explicit outputs fail.
There are at most 16 confidential outputs per block in addition to normal weight
limits. Registration authenticates IDs, not issuer identity or reserve facts.

The audit transaction-success cache binds genesis, actual key bytes, registry
version/list and full witness transaction hash; it stores success only and
clears at 128 entries. Governance successful config/proposal caches are bounded
at 32 entries and include exact bytes, chain, activation height, actual metadata
and both registries. Review warm/cold behavior and mutation cases, not just hash
function strength. Ordinary range/surjection caches are separate consensus code.

Header sync additionally bounds retained audit-chain allocations at 64 MiB per
peer without reducing the 14,827-header commitment lookahead. Dense valid
governance history may exceed the cap and abort sync: this is a prototype
availability limit, not a cryptographic safety proof.
