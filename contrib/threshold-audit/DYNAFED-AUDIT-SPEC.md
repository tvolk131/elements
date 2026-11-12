# Proposed DynaFed and audit-key lifecycle

Status: executable research specification. `governance.py` and
`test_governance.py` implement a bounded public-policy model, not an Elements
consensus patch, production key service, wire protocol, or security proof.
The Python files remain the reference model. The native custom-chain patch now
implements output proof enforcement, TAG1 historical committee manifests and
TAP1 transition readiness; see [NATIVE-INTEGRATION.md](NATIVE-INTEGRATION.md)
and [NATIVE-GOVERNANCE.md](NATIVE-GOVERNANCE.md). Separate guardian services
execute an experimental distributed ceremony; this specification does not
establish an actively secure DKG/handoff protocol.

## Existing DynaFed behavior

Current Elements DynaFed changes public authorization parameters. The relevant
entry fields in `src/primitives/block.h` are `m_signblockscript`,
`m_signblock_witness_limit`, `m_fedpeg_program`, `m_fedpegscript` and
`m_extension_space`. Ordinary multisignature members have separate private
keys; DynaFed does not generate or reshare one federation master scalar.

`NextBlockIsParameterTransition` in `src/dynafed.cpp` counts blocks carrying
identical non-null proposals. A proposal needs `L - floor(L/5)` votes during
the preceding `L`-block epoch, and takes effect at an epoch boundary. This is
four-fifths of blocks rounded up, not four-fifths of institutions signing an
extra certificate. Each block still needs to satisfy the applicable block-signing
script. A new epoch alone does not rotate keys. The custom-chain parameters in
`src/kernel/chainparams.cpp` support an always-active DynaFed deployment.

`m_extension_space` is interpreted as PAK entries when PAK enforcement is
enabled; `ContextualCheckDynaFedHeader` rejects invalid PAK changes. Audit
configuration must not be encoded as arbitrary extra PAK bytes. A fork needs a
dedicated versioned field or a newly specified typed extension with explicit
consensus parsing, limits and commitment semantics. This proposal uses a
dedicated logical audit field, leaving PAK semantics separate.

Peg custody is a separate lifecycle: changing a sidechain header does not rewrite
Bitcoin UTXOs protected by previous scripts. A Bitcoin-backed deployment must
coordinate old-key spending into the new custody policy independently. The
historical peg-in acceptance window in `GetValidFedpegScripts` is not audit-key
retention and must not be reused as a rule for deleting historical audit keys.

## Intended invariant

Every confidential output requiring recovery must include a recovery package
whose proof verifies against its actual commitments, using the audit key and
proof scheme required at the output's creation block. The current audit
committee must retain threshold capability for every historical audit key.

These are distinct requirements. Public proof validity does not establish that
institutions remain online or cooperate. A governance vote cannot erase copied
secrets, revoke an already disclosed opening, or force a colluding decryption
quorum to leave a log.

## Public configuration

An `AuditConfig` consists of:

- Monotonically increasing configuration generation, starting at zero.
- A digest identifying the associated block-signing policy.
- A canonical institution roster: nonzero uint32 IDs in strictly increasing
  order, each with a distinct independent BIP340 identity public key.
- The active audit-key version for new outputs.
- An ordered list of EVERY retained audit-key descriptor.

Each key descriptor has a positive uint32 key version, a positive uint16 proof
scheme ID, and its **current** `Committee` manifest. The manifest includes a
share epoch, member IDs and Feldman coefficient commitments. The first
coefficient commitment is the public encryption key; the number of commitments
determines the decryption threshold. Each retained key uses the current
institution roster, although different keys may have different thresholds.

The block-signing script and audit roster are explicitly associated by the
configuration. The model does not extract institutional identities from an
arbitrary witness script. A production specification must define this association
and who may change it; it must not assume that a script public key alone names a
legal institution or uniquely identifies its audit endpoint.

Key versions are contiguous starting at one. Genesis initializes one active
key at share epoch zero. A new key version means a fresh public encryption key.
Retained descriptors cannot change public key or proof scheme. Routine handoff
updates their committee manifests without changing the public key. An unchanged
committee may be retained; a changed committee must increment its share epoch
exactly once.

Proof scheme IDs are checked against an explicit supported-scheme set. Scheme 1
identifies the TAR1 reference experiment and scheme 2 identifies the TAC2 chunked
full-opening experiment. The model defaults to `(1,)`; callers must explicitly
enable `(1, 2)` to accept TAC2. The integrated lifecycle demo does so. Assigning
an ID is not an endorsement of a production construction. A proof-scheme
upgrade retaining the same public key needs additional explicit rules; this
model does not silently treat it as a routine committee handoff.

### Experimental encoding and limits

`AuditConfig.to_bytes` and `from_bytes` use an exact bounded encoding:

```text
"TAG1"                    4 bytes
generation                uint32 big endian
active_key_version        uint32 big endian
block_signing_policy      32 bytes
identity_count            uint8, 1..32
identities                identity_count * (uint32 ID, 32-byte x-only key)
retained_key_count        uint8, 1..16
for each retained key:
    version               uint32
    scheme                uint16
    share_epoch           uint32
    threshold             uint8
    member_count          uint8
    member_IDs            member_count * uint32
    coefficient_points    threshold * 33 bytes
```

The maximum config size is `MAX_CONFIG_BYTES` in `governance.py` (20,334 bytes).
All counts are bounded before allocation; truncated data, trailing bytes,
unordered/duplicate IDs or versions, unknown points, invalid scalar-proof
encodings and unsupported active semantics are rejected. Internal infinity
encoding follows the reference experiment for coefficient commitments and is
forbidden for the public encryption key. This encoding is not an Elements
transaction or header format. The 16-key limit is an experiment resource bound,
not a recommendation to delete old keys after 16 rollovers. A production archive
will need a scalable authenticated representation and a lifetime policy.

## Prepared transitions and readiness

A transition binds the chain ID, current configuration hash, proposed complete
configuration and exact activation height. Its generation must be current + 1.
The activation height must be the next applicable DynaFed boundary. These
bindings prevent replay across chains, branches with different predecessor
configurations, activation heights or proposed block-signing policies.

Before voting, a proposed new committee runs the appropriate private key
ceremonies and prepares a public readiness certificate. A certificate has a
distinct quorum for **each retained key**, including both historical-only keys
and a newly generated key. Each entry contains:

```text
key_version               uint32
institution_ID            uint32
share-possession proof    two canonical scalars (64 bytes)
institution signature     BIP340 signature (64 bytes)
```

The proof establishes knowledge of the discrete logarithm of that institution's
public share verification key, using the reference Schnorr/DLEQ machinery.
The independent institution key signs the exact transition-bound proof. Entries
must be ordered by `(key_version, institution_ID)` and unique. The model caps a
certificate at 16 * 32 entries. No private shares, private ceremony evaluations,
output openings or partial decryptions are in this certificate.

The prepared proposal's vote root commits to both the transition and the exact
certificate. Different certificate bytes are different proposals, even if they
prepare the same configuration. Operators should agree on and distribute one
canonical certificate before voting. The separate unsigned transition binding
avoids circularity between the readiness proofs and the certificate commitment.

A ready quorum plus a valid polynomial manifest establishes present knowledge
of shares mathematically consistent with the public key. It does not prove
exclusive possession, honest execution of the private ceremony, key erasure,
future availability, protected hardware, legal authorization or log enforcement.
Nor does checking degree, curve points and readiness establish threshold privacy
for arbitrary malicious coefficient choices. Known/correlated coefficients and
leaked shares can lower effective secrecy. The threshold guarantee requires a
reviewed distributed ceremony with the appropriate randomness and corruption
assumptions. The model rejects publicly known zero member shares as one obvious
bad case; it cannot prove that every accepted manifest came from a secure DKG.
Institutions should additionally exercise a challenge decryption before voting;
the public model does not replace that operational check or its threat model.

### Routine handoff

1. Prepare new shares of each retained secret, preserving each public audit key.
2. Verify private handoff evaluations using a reviewed actively secure protocol.
3. Collect threshold readiness entries per key under the proposed manifests.
4. Vote for the exact prepared proposal in DynaFed blocks.
5. Activate the new public policy only at a successful epoch boundary.
6. Retire obsolete shares subject to the reorg/rollback policy and secure erasure
   assumptions; this cannot revoke a copied old quorum.

The current Python private ceremony is only a single-process VSS simulation.
It is not an implementation of the reviewed protocol required by step 2.

### Genuine key rollover

Rollover appends a fresh key at version `max_version + 1`, with share epoch zero,
and makes it active for future outputs. All earlier descriptors remain present
with the same public keys and schemes. Each historical key must be handed to
the proposed institution roster and have its own ready quorum. Changing only the
latest key while abandoning historical shares is invalid in this model.

An old key becomes **historical-only**, not deleted. Its ciphertexts remain on
chain and its recovery capability is retained. A prior version cannot silently
become the active encryption key again. Public policy rollback through a reorg
is a different case and is addressed below.

## Output validity and disclosure selection

New-output validation uses the audit policy effective for the **candidate
block**, including a change taking effect at that boundary. Mempool validation
must look ahead consistently with block validation. This model chooses strict
key rollover: no acceptance grace period for new outputs using an old active
key. Such pending transactions must be rebuilt and their recovery proofs
regenerated. An ordinary membership handoff preserving the key and scheme does
not invalidate a pending output merely because its share epoch changed.

Historical output proof validation uses the configuration at its creation
block. It must not substitute the latest public configuration and thereby
invalidate unchanged history. For a disclosure, select the **current** committee
manifest for that historical key version. That is how new members can recover
an old ciphertext while historical proof inputs remain unchanged.

`OutputReference` in the executable model anchors a key version, scheme and
public key to a creation-block ID. It is only a public-policy reference. It is
not proof that a transaction or output exists, is valid, or is unspent. Production
code must derive these facts from chain data and authenticated indexing, never
trust a requester-supplied creation height or audit key.

## Reorganizations

The model mirrors DynaFed epoch voting with height zero as a genesis null vote.
Only fully accepted prior blocks count. A failed proposal leaves the current
configuration unchanged. Header block-signature validation is assumed to have
already occurred; the model does not interpret or verify actual block scripts.

Disconnecting blocks restores previous public audit policy and removes their
votes. Removing a boundary block alone may leave the approving epoch intact,
so the next candidate block can still enact the transition. Removing enough
approving votes can remove the transition. Outputs anchored only to disconnected
creation blocks cease to be part of the active chain.

This rollback does not restore erased shares or revoke copied shares, completed
private handoffs, partial decryptions, output openings or off-chain log entries.
Do not blindly erase the old committee state on first observing a boundary
block. The production deployment must choose a reorg safety policy, retained
rollback state and recovery procedure, while recognizing that retaining old
shares increases the period of exposure. There is no perfect combination of
immediate erasure, arbitrary reorg recovery and revocation of all prior quorums.
Disclosure services also need a chain-stability policy and must record the
creation-block and authorization/configuration anchors used for each disclosure.

## Proposed Elements integration

The following are the integration points. The native experiment implements
configuration and prepared-certificate header commitments, historical-key
continuity, readiness verification, genesis binding, output witness serialization,
consensus verification, transaction-template hashing, single-owner wallet/PSET
generation and node lifecycle tests. Production deployment of the separate
guardian service, reviewed distributed ceremonies and protected secret handling
remain unfinished:

1. **Header/governance serialization:** add a versioned dedicated audit-config
   and prepared-certificate commitment in `src/primitives/block.h`; update
   `DynaFedParamEntry::Serialize/Unserialize`, equality, `CalculateRoot` and
   `CalculateExtraRoot` in `src/primitives/block.cpp`. Compact entries must
   retain an authenticated commitment to omitted audit data. Define whether the
   full manifests/certificates are in headers or authenticated block data.
2. **Transition checks:** extend `ContextualCheckDynaFedHeader` in
   `src/validation.cpp` to validate configuration continuity, scheme support,
   certificate signatures, share-possession proofs and explicit payload limits.
   Extend `src/dynafed.cpp` parameter selection without changing the distinction
   between block-vote threshold and decryption threshold. Preserve PAK parsing.
3. **Chain parameters/indexing:** initialize the audit root and activation rules
   in `src/kernel/chainparams.cpp`; store/retrieve historical key and manifest
   data with the same contextual/reorg discipline as other consensus state.
   Index lookups must not require scanning every block during transaction checks.
4. **Output recovery witness:** add key-version/scheme identifiers, ciphertexts
   and proofs to the designated output witness structure in
   `src/primitives/txwitness.h`, with canonical serialization, weight/resource
   accounting and explicit exceptional cases. Confidential issuance/reissuance
   input amounts require corresponding coverage; do not overlook those fields.
5. **Transaction consensus checks:** extend `VerifyAmounts` and its call path in
   `src/confidential_validation.cpp` / `src/consensus/tx_verify.cpp` to select the
   candidate-block audit policy, require each applicable recovery package and
   verify its binding to the actual output commitments. Node policy alone is
   insufficient. Update proof caches to commit to the entire relevant statement.
6. **Wallet/PSET and signatures:** generate recovery packages in the blinding
   path (`src/blind.cpp`, `src/blindpsbt.cpp`), carry fields through PSET, and
   define transaction-template hashing and signature commitment semantics. The
   standalone demos' synthetic template hash is not a consensus definition;
   the native experiment supplies its own explicit definition.
7. **Lifecycle tests:** exercise activation, missing/invalid packages, genuine
   key rollover, strict stale-key rejection, handoff with unchanged historical
   ciphertexts, boundary lookahead, historical-key disclosure, and reorg undo
   in the native functional test suite. The model tests are an executable
   specification; they do not replace those node tests.

Proof-verifier optimization, native memory handling, DKG/refresh transport,
hardware key policy, legal-party credentials, disclosure approvals, durable
independently witnessed logs and authenticated encrypted delivery remain
separate implementation work. Key-size and certificate bounds here are
experimental choices requiring review before becoming consensus rules.
