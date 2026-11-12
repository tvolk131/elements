# Native historical-key governance experiment

The audit custom-chain experiment now requires a complete genesis committee
configuration and transition-bound readiness for every retained historical key.
This ports the public rules from `governance.py` into native header validation.
It does not implement or prove secure distributed key generation, exclusive
possession, share erasure, future availability or enforced disclosure logging.

This changes the experimental audit chain's genesis and full-header format.
Start fresh test data. Non-audit networks retain their existing wire formats.

## Genesis and full DynaFed parameters

`-con_audit_config=<TAG1 hex>` is required when `-con_threshold_audit=1`.
`-con_audit_pubkey` is optional; if supplied, it must match the active key in
the configuration. A genesis configuration must have generation 0, one active
key at version 1/share epoch 0, and the correct initial DynaFed policy binding.
The complete configuration participates in the genesis argument commitment.

TAG1 uses exactly the encoding in `AuditConfig.to_bytes()` in `governance.py`,
with a maximum of 16 historical keys and 32 institutions. Native recovery
currently permits only TAC2, scheme ID 2. Key versions are contiguous from 1.
Every retained key lists the complete current institution roster. Scalar
polynomial commitments must have a non-infinite constant and highest
coefficient, and no member may have an infinite public share verification key.
These checks reject obvious invalid manifests; they do not prove threshold
privacy for arbitrary malicious or correlated coefficient choices.

Full DynaFed parameters now append these experiment-only fields, in order:

```text
audit_pubkey       CompactSize bytes, exactly 33 after contextual checking
audit_version      uint32 little endian
audit_config       CompactSize bytes, exact TAG1, at most 20,334 bytes
audit_prepared     CompactSize bytes, exact TAP1, at most 69,674 bytes
audit_assets_version uint32 little endian, zero for the initial registry
audit_assets       CompactSize count, then count raw 32-byte asset IDs; at most 256
```

The two existing key fields are redundant metadata and must match TAG1's active
descriptor. All six fields participate in the DynaFed extra root. Compact
current entries keep their existing shape and authenticate the complete omitted
data through the elided root. On activation, the accepted configuration and
prepared certificate become part of the full current entry.

The initial registry uses version zero. Its native policy binding is the raw
32-byte double-SHA256 of this concatenation:

```text
ser_string(signblockscript)
uint32LE(max_block_witness)
ser_string(fedpeg_program)
ser_string(fedpegscript)
ser_vector(ser_string(extension) for extension in extension_space)
```

This digest must equal `AuditConfig.signer_policy`. It binds the entire
non-audit DynaFed proposal, including fedpeg and PAK parameters. It uses raw
hash bytes, without RPC uint256 display reversal. For genesis, use DynaFed's
converted P2WSH block-signing program and its initial fedpeg program, not the
legacy `signblockscript` alone. The initial fedpeg program is P2WSH when
`-con_start_p2wsh_script=1`, otherwise P2SH-P2WSH.

The version-zero registry is fixed by genesis chain configuration: explicit
`-con_audit_asset` IDs, or the default policy-asset marker. Its concrete IDs still
participate in DynaFed roots and every output proof. They are omitted from this
initial TAG1 policy digest because the default policy-asset ID depends on the
genesis hash, which itself commits TAG1. Proposal validation cannot change the
version-zero registry without incrementing its version.

For every registry version greater than zero, append this exact encoding to the
policy-binding preimage above:

```text
ser_string("threshold-audit-assets-v1")
uint32LE(audit_assets_version)
CompactSize(asset_count)
concatenation of raw 32-byte asset IDs
```

`native_governance.policy_binding(..., audit_assets=raw_ids,
audit_assets_version=version)` implements both encodings. IDs must be nonzero,
distinct and sorted by raw byte order, which differs from RPC display order.
Registration is an append-only set operation: the proposed canonical list must
be a strict superset of the current list and increment the version exactly once.
No removal, replacement, duplicate, reordering or version-only update is valid.
The complete set has at most 256 IDs; uint32 version overflow is rejected.
Retaining the same registry requires retaining its exact version. Registration
also increments TAG1 generation and requires existing TAP1 readiness for every
retained audit key. A certificate for a different registry cannot authorize it.

These are recovery asset IDs. Consensus does not interpret EUR/USD labels,
identify an issuer, attest to bank reserves or establish redemption rights.

## Prepared transition encoding

Every non-null audit-chain proposal must supply `audit_config` and
`audit_prepared`. A key/version-only proposal cannot bypass governance.
TAP1 encodes:

```text
"TAP1"                        4 bytes
previous_config_binding       32 bytes
activation_height             uint32 big endian
readiness_count               uint16 big endian, 1..512
readiness entries             readiness_count * 136 bytes
```

Each readiness entry is exactly `Readiness.to_bytes()` from `governance.py`:
key version and institution ID (each uint32 big endian), two canonical 32-byte
scalars for the share-possession proof, and a 64-byte BIP340 institution
signature. Entries are strictly ordered and unique by `(key_version, member)`.
Every retained key, including a new active key, requires at least its advertised
threshold of distinct valid entries. Certificates contain no secret shares.

Digest domains, length prefixes and proof/signature transcripts exactly match
the Python model. They bind genesis hash bytes as chain ID, previous complete
configuration, the proposed complete configuration and exact activation height.
The native expected boundary for a proposal in candidate block height `h` is
`(h // epoch_length + 1) * epoch_length`. A certificate voted during an epoch
cannot be reused as a new proposal at the next boundary. Mine that boundary
with a null vote unless a separately prepared following transition exists.

Successful proposal verification is cached with all public context, actual
configuration/certificate bytes and DynaFed policy metadata. Both config and
proposal caches are bounded to 32 entries. Cache inputs include both complete
registries and their versions, including version zero. Failed verifications are not cached
as successful. Each full entry's configuration plus certificate has a fixed
90,008-byte maximum; normal block and message resource rules still apply.

## Historical continuity rules

- Configuration generation increments exactly once.
- Every existing key version remains present with its original public key and
  proof scheme. A transition cannot delete or replace a historical key.
- A changed committee increments its share epoch exactly once. Public key and
  historical ciphertexts remain unchanged during that handoff.
- A rollover can append exactly one fresh key at share epoch 0 and makes that
  newest version active. A historical-only key cannot be reactivated.
- Readiness is required for every retained key under the proposed current
  roster. Readiness only for the latest key is insufficient.

Missing valid readiness therefore prevents the proposal's blocks from being
accepted, so those votes cannot activate it. This establishes evidence of
present share possession, subject to the proof assumptions. Operators must
still ensure a secure ceremony, online cooperating members and durable storage.
Reorgs restore public configuration through existing DynaFed ancestry; they do
not recreate erased shares. Preserve operational rollback state according to
the chosen reorg policy.

## RPC and verification evidence

`getnewblockhex` takes complete TAG1/TAP1 hex in `audit_config` and
`audit_prepared`. Optional `audit_pubkey`/`audit_version` must agree with TAG1.
Optional `audit_assets` (RPC display hex IDs in raw-byte canonical order) and
`audit_assets_version` default to the candidate block's current registry. An
update must supply the complete resulting registry and the incremented version.
`getblockchaininfo` returns `audit_config` and `audit_config_hash` for the
next-block policy, alongside the audit key/version and
`audit_assets`/`audit_assets_version`. Full block parameter
JSON exposes configuration/certificate bytes. The configuration hash is raw
digest hex, without uint256 display reversal.

Direct contextual failures return `invalid-audit-governance` with a diagnostic.
Existing invalid audit key/version checks can reject inconsistent metadata
first. RPC rejects absent or malformed bounded arguments before assembling a
proposal.

The isolated native cross-language harness accepted a Python-produced 7-of-10
to 11-of-15 handoff and a rollover retaining both historical and fresh keys. It
rejected 18 adversarial vectors, including insufficient historical readiness,
wrong chain/boundary/predecessor, bad signatures and possession proofs,
noncanonical scalars, duplicate entries, historical key deletion/replacement/
reactivation, wrong signing-policy bindings, zero shares and insufficient
polynomial degree. Local evidence:
`/tmp/elements-audit-governance-check/results.log`.

The two-node `feature_threshold_audit_assets.py` additionally exercises explicit
EUR/USD and token issuance, authenticated registration, rejection of unregistered
confidential outputs, malformed registries, readiness/registry substitution,
next-block mempool eviction, native wallet/PSET construction, historical proof
recovery, full-chain verification and registry rollback. Run it using the command
in [NATIVE-INTEGRATION.md](NATIVE-INTEGRATION.md).

These are research validations, not an independent cryptographic audit.
