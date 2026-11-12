# Native wallet and PSET recovery package generation

The experimental custom chain now has a C++ TAC2 prover in
`src/threshold_audit.cpp`. It creates packets from the final output commitments,
an amount, an asset ID and both output blinders. It never needs guardian secret
shares. The constructor checks its opening against the actual native commitments
and rejects assets outside the registry effective for the candidate next block.

`AttachTransactionProofs` derives the same complete-transaction statement used
by native consensus. It stages every new output packet before modifying the
transaction. An output whose opening is unavailable must already have a packet
that verifies against that exact final transaction template, current key and
complete current registry.

## Supported native paths

- Wallet `blindrawtransaction` and node `rawblindrawtransaction` generate packets
  after ordinary asset/value blinding has finalized every commitment and nonce.
- Ordinary signed wallet transaction creation creates packets after final fees,
  outputs and locktime are fixed, before input signing.
- Wallet coin selection includes a conservative packet-size allowance. Initial
  blinding for fee calculation includes actual packets, so the final fee estimate
  measures their witness weight.
- `walletprocesspsbt` supports a wallet that can blind every pending confidential
  output in one operation. It generates packets against the complete final
  template, then preserves them through PSET serialization, merging, unsigned
  transaction construction and final extraction.
- PSET wallet signing verifies mandatory packets against the current next-block
  audit key and registry. Missing, invalid or stale packets return a specific signing error.
  Final extraction refuses confidential outputs missing a packet.
- Node `finalizepsbt` also verifies complete transactions' audit packets against
  next-block policy before reporting completion or returning transaction hex.
- `decodepsbt` exposes packets as `audit_recovery_proof` in output objects.

The trusted audit public key, registry IDs and registry version come from one
atomic `getAuditPolicy()` chain-interface snapshot, selected from next-block
DynaFed policy under the chain lock. The genesis hash comes from chain
parameters. Wallet-supplied data cannot override this policy. Fee estimation
uses the same snapshot's registry size. Concurrent key rollover or registration
can still make a just-constructed transaction stale; mempool and block validation
reject it under the new policy.

## PSET extension

The proprietary output key uses the separate identifier `threshold-audit` and
subtype `1`, with no additional key bytes. Its value is the TAC2 packet, bounded
to 80,000 bytes before allocation. Duplicate, empty and oversized recognized
fields are rejected. This avoids allocating an upstream `pset` subtype. The
extension is recognized on audit chains; ordinary clients can preserve it as an
unknown proprietary field.

Merging two different nonempty audit packets fails. The packet itself binds all
transaction inputs and outputs, so changing another output's commitment or a
locktime invalidates it even if that output's ordinary proof is unchanged.

## Current boundaries

Partial collaborative PSET blinding is explicitly rejected on audit chains.
With a proof bound to every final output commitment, an earlier blinder cannot
finish its packet before later participants choose their commitments. Supporting
that workflow requires a staged protocol in which all commitments are fixed
first and each owner subsequently creates its own packet. This implementation
does not put output blinders into public PSET metadata to work around that
requirement. Failed audit PSET operations leave the caller's PSET unchanged.

After an audit-key rollover or registry append, rebuild from a retained unblinded
template/openings and regenerate packets under the new key and registry. Every
packet binds the entire registry, so even outputs of existing assets become
stale when a different asset is registered. The node evicts pending confidential
transactions and their descendants when next-block policy changes. This patch does not automatically
replace already pending wallet transactions or recover a recipient's opening
from an old transaction. Existing wallet rewinding can recover only outputs
whose blinding keys it knows.

Confidential issuance/reissuance amounts and mixed explicit/confidential output
pairs remain unsupported. To bootstrap an issued asset, first create a public
issuance with explicit asset/token amounts and explicit outputs, determine its
IDs, then approve the complete registry update through DynaFed readiness/voting.
Confidential distribution can begin after that registration becomes next-block
policy. Reissuance-token IDs must also be registered before making token outputs
confidential. An unregistered confidential output fails proof construction;
explicit outputs already disclose their financial contents and need no packet.
Native wallet integration does not create guardian shares, perform handoff,
validate fiat backing or enforce disclosure authorization.

Historical outputs retain the registry effective in their creation block.
Recovery tools must obtain that authenticated historical context rather than
substitute the current registry. Registry additions do not rewrite old packets.

Secret scalar arithmetic uses native secp256k1 scalar APIs, and arbitrary-point
secret multiplication uses its ECDH implementation rather than the verifier's
variable-time public-key tweak multiplication. Openings and major witness buffers
receive best-effort cleanup. This remains an unreviewed research prover with
data-dependent control flow; it is not a claim of end-to-end constant-time
execution, guaranteed zeroization, HSM protection or production readiness.

## Interoperability evidence

A standalone native prover generated packets for amounts `0` and `2^64-1`, using
each branch of a two-asset registry. The native verifier accepted both packets;
the independent Python TAC2 verifier also accepted them, and Python 7-of-10
threshold recovery reproduced the complete original openings. These exercise
proof-library uint64 bounds, not chain monetary-policy acceptance of those
amounts. Native node/wallet lifecycle validation is recorded separately in the
main integration guide.

## Public commitment decoding optimization

The verifier/prover now uses Boost `cpp_int` exact modular exponentiation only
for translating public quadratic-residue commitment encodings into compressed
SEC points. Coordinates still require `x < p`; the curve square-root check,
quadratic-residue sign selection and final native point parse are unchanged.
Unbounded intermediate integers avoid truncating products before modular
reduction. Secret scalar arithmetic and secret point multiplication do not use
Boost. The repository already requires Boost headers.

An isolated differential run checked 1,598 encodings, comprising 799 valid and
799 invalid cases, against the previous C++ decoder and the independent Python
decoder. The corpus included native asset/value commitments, both QR signs,
wrong prefixes and lengths, random coordinates and field-boundary coordinates.
Every accepted SEC point and rejection outcome matched exactly. Batch decoding
took 18.41 seconds before and 0.370 seconds after this change.

For two unchanged Python-produced packet vectors, median native verification
times over three runs decreased from 0.978 to 0.131 seconds and from 0.885 to
0.0810 seconds, respectively. These were local measurements during concurrent
build/test activity, not throughput guarantees. All 14 existing malformed or
tampered native packet vectors remained rejected. Fresh optimized native packets
also passed native/Python verification and 7-of-10 full-opening recovery for both
uint64 amount extremes and a zero-blinder edge case. Packet encoding, proof
equations and the experimental 16-confidential-output block budget are unchanged.

Local measurement evidence is in
`/tmp/threshold-audit-native/optimization-results.json`.
