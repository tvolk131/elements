# Native custom-chain integration experiment

This checkout contains an opt-in Elements consensus experiment for mandatory
TAC2 recovery witnesses. It includes a C++ prover, wallet/PSET integration and
native historical-key readiness checks. Separate Python guardian processes
exercise distributed sharing, handoff and authorized disclosure over mutual TLS.
This remains an unaudited research patch.

## Implemented scope

With `-con_threshold_audit=1` on a fresh custom chain:

- Every output with confidential asset and value commitments must carry a
  valid TAC2 packet. Both the mempool and block connection check the packet
  against the actual output and candidate block's audit key. Block connection
  performs these checks independently of script-validation/assumevalid flags.
- Explicit asset/value outputs need no packet and reject an unexpected packet.
  This includes ordinary explicit fee outputs. Mixed explicit/confidential
  pairs, confidential coinbase outputs and confidential issuance/reissuance
  amounts are rejected in this first implementation.
- The full amount, asset ID and both blinding factors are recoverable by a
  threshold possessing shares for that output's creation key. Ordinary recipient
  range-proof rewinding continues to work.
- DynaFed full parameters contain a dedicated audit public key and uint32 key
  version. Compact parameters commit to omitted fields through the existing
  elided root. PAK extension-space parsing keeps its existing meaning.
- A public-key change requires exactly the next key version. An unchanged key
  requires the same version. The first key version is 1. Normal DynaFed voting
  selects the replacement; neither voting nor these fields generates secret
  shares or performs a handoff.
- Every non-null DynaFed proposal also supplies a complete TAG1 configuration
  and TAP1 readiness certificate. All historical keys must remain present, with
  consistent incoming committee manifests and a signed share-possession quorum
  for each key. Readiness binds the chain, previous configuration, full proposed
  authorization policy and exact activation boundary. See
  [NATIVE-GOVERNANCE.md](NATIVE-GOVERNANCE.md).
- Native wallet sends and blinding generate packets. Single-owner PSET blinding,
  signing, merging and extraction preserve them; finalization checks complete
  packets against next-block policy. Fee estimation budgets recovery witnesses.
  See [NATIVE-WALLET.md](NATIVE-WALLET.md).
- The initial asset registry has version zero and 1..256 unique IDs. Omitting
  explicit IDs selects the chain's policy asset. Later DynaFed proposals can
  append IDs, requiring exact version increments, TAG1 binding and TAP1 readiness.
  The canonical registry remains a sorted set of at most 256 nonzero IDs; it
  cannot remove an old ID. Initial configuration participates in the genesis
  argument commitment, including the DynaFed epoch length. The default-policy
  marker avoids circular derivation of the policy asset ID.

Existing networks reject the audit configuration flags. With the feature off,
the added witness and DynaFed fields are absent from serialization. Existing
databases and wallets must not be reused to change this setting.

## Wire format, hashing and resource limits

`CTxOutWitness` appends a CompactSize-prefixed `vchAuditProof` vector after the
existing surjection and range proofs, only when the process's chain configuration
enables the experiment. Parsing caps it at 80,000 bytes. TAC2 has its own strict
parser, bounded limb proofs and canonical scalar/point checks. Its format and
equations are specified in [OPTIMIZATION.md](OPTIMIZATION.md).

Full DynaFed parameters append the CompactSize-prefixed compressed 33-byte
`m_audit_pubkey`, little-endian uint32 `m_audit_version`, and bounded
`m_audit_config` / `m_audit_prepared` vectors, followed by uint32
`m_audit_assets_version` and a CompactSize-counted vector of raw 32-byte asset
IDs. Registry parsing caps the count at 256 before allocation. Header parsing bounds
the key length, and contextual validation requires a valid compressed point and
the key/version continuity rule. The fields participate in parameter roots and
equality. The TAG1 configuration supplies every retained key's current roster,
threshold and public polynomial commitments. Compact current headers must match
the expected elided root exactly on audit chains.

The native TAC2 statement binds:

1. Raw internal bytes of the genesis block hash.
2. A transaction-template hash: double-SHA256 of nonwitness serialization after
   clearing every input scriptSig and all transaction witnesses.
3. Output index, script, native asset/value commitments, active audit key and
   the complete registry effective for the candidate block, sorted by internal bytes.

The template retains all inputs, sequences, issuance fields, outputs, nonces,
version and locktime. The constructor can therefore attach proofs before input
signing, without circular hashing. Existing input signing rules are unchanged;
recovery packets participate in witness hashes and the block witness commitment.
The packet does not carry an independently selectable policy key or key version.
Its key is selected contextually from the candidate block's predecessor.

A bounded cache holds 128 successful complete-transaction audit checks. Its key
commits to genesis, the approved key, registry/version and the entire wtxid, including
recovery packets. Invalid packets are not cached as successful. Ordinary CT
validation remains independently required.

The experimental block limit is **16 confidential outputs**, in addition to
ordinary transaction/block weight limits. Transactions cannot exceed that
budget, block connection enforces the aggregate, and block assembly skips
packages that would exceed it. A standalone initial native measurement was
approximately 0.63 seconds per output on this machine. Exact public-field modular
exponentiation subsequently reduced two measured complete-verification vectors
to approximately 0.08..0.13 seconds. The optimized decoder matched the old C++
and independent Python across 1,598 valid/malformed encodings. These are local
measurements under concurrent load, not throughput guarantees. One-asset packets
are still 54,564 bytes per output; the optimization changes no packet equations
or wire bytes. See [NATIVE-WALLET.md](NATIVE-WALLET.md).

## Rotation and reorg behavior

Block signing keys and audit decryption shares have independent lifecycles.
Changing only the signing policy preserves the audit public key and existing
packets. To move decryption responsibility, institutions must separately reshare
the same secret into the new committee. The separate guardian services distribute
private evaluations directly over authenticated encrypted channels. The public
coordinator receives commitments and readiness, without receiving a quorum's
secret shares. This is an experimental Feldman ceremony, not a reviewed actively
secure distributed key-generation/handoff protocol.

Changing the audit public key applies to newly created outputs. Pending
transactions carrying proofs for the previous key must be rebuilt. Mempool
validation uses DynaFed's next-block policy, and tip connection evicts confidential
transactions when that policy changes. Reorg handling rechecks admission under
the restored policy. Historical blocks remain valid under their creation keys
and registries: block connection derives policy from that block's predecessor.
Appending any asset invalidates pending confidential proofs because their
statements bind the whole registry. Wallets must rebuild those packets under the
new registry; historical packets remain unchanged.

Historical ciphertexts are not rewritten at rollover. To give the current
committee access to all history, every retained historical key must be handed
over too. Native consensus requires incoming share-possession readiness for
every retained key before accepting the proposal. It cannot enforce continued
availability or protected storage after activation. A colluding old quorum retaining shares can still decrypt;
neither key metadata nor an authorization log cryptographically revokes it.

`getblockchaininfo` exposes `threshold_audit`, `audit_pubkey`, `audit_version` and
`audit_assets`/`audit_assets_version`, plus the authenticated `audit_config` and its binding. These describe
the policy for the next block, which
can change at an epoch boundary. `getnewblockhex` accepts `audit_pubkey` and
`audit_version` plus optional `audit_assets`/`audit_assets_version` in its DynaFed
proposal object, with mandatory `audit_config` and
`audit_prepared` for non-null proposals. Redundant key/version metadata must
match the configuration. Block JSON exposes audit fields in full parameter entries.

## Build and run the native test

Use the checkout's ordinary daemon build prerequisites, including Boost,
libevent and SQLite development headers. Build the shared secp256k1-zkp library
as described in [README.md](README.md), then build the daemon and CLI:

```sh
cmake -S . -B /tmp/elements-audit-native-build \
  -DCMAKE_BUILD_TYPE=Release -DBUILD_GUI=OFF -DBUILD_TESTS=ON \
  -DWITH_BDB=OFF -DWITH_ZMQ=OFF -DWITH_MULTIPROCESS=OFF
cmake --build /tmp/elements-audit-native-build \
  --target elementsd elements-cli -j 4
env THRESHOLD_AUDIT_SECP256K1=/tmp/elements-audit-secp/lib/libsecp256k1.so \
  python3 test/functional/feature_threshold_audit.py \
  --configfile=/tmp/elements-audit-native-build/test/config.ini \
  --descriptors \
  --portseed=500
env THRESHOLD_AUDIT_SECP256K1=/tmp/elements-audit-secp/lib/libsecp256k1.so \
  python3 test/functional/feature_threshold_audit_guardians.py \
  --configfile=/tmp/elements-audit-native-build/test/config.ini \
  --descriptors --portseed=600
```

The first test creates two actual daemons, temporary chain data and fresh test wallets.
Both P2P and RPC bind to loopback, automatic peer discovery is disabled, and the
nodes connect only to one another. The test stops its servers when finished.
It does not require a Bitcoin node or backing asset. It explicitly enables
always-active DynaFed and confidential addresses, overriding test-harness
defaults. For an independently launched custom chain, the relevant options are:

```text
-chain=auditregtest
-con_threshold_audit=1
-con_audit_config=<genesis TAG1 configuration hex>
-evbparams=dynafed:-1:::
-dynamic_epoch_length=10
```

The genesis configuration must bind the exact converted initial DynaFed policy.
Use the helper in `native_governance.py` and the genesis preparation pattern in
the functional tests. Optional `-con_audit_pubkey` must match TAG1's active key.
The guardian-backed test starts 25 isolated guardian services, creates two audit
keys, transfers both to a new 11-of-15 committee, stops the outgoing services,
and exercises historical disclosure and restart persistence. OpenSSL is required
to generate ephemeral test TLS certificates.

Use `-con_audit_asset=<32-byte RPC asset hex>` repeatedly for a fixed explicit
registry instead of the default policy asset. The chain must use signed Elements
genesis, height-bearing headers and an epoch length between 2 and 100,000. The
functional test is invoked directly because it requires the separately built
shared library used by the Python proof constructor.

## Validation and hardening

The expanded native test passes mandatory historical-key readiness, malformed
transition bindings, compact-header commitments, node restart persistence,
rollover/reorg behavior, native wallet sends and native PSET extraction. It also
rejects a tampered packet at PSET finalization. The complete existing
`feature_dynafed.py` regression passes with legacy-wallet support enabled.

Three independently reproduced review findings were fixed: compact policy roots
were omitted by legacy parameter equality; duplicate guardian writers could
fork private state/logs; and an idle TCP peer could stall TLS accept. The fixes
are an audit-only contextual root check, a lifetime exclusive private-directory
lock, and bounded worker-thread TLS handshakes/request reads.

Further transport/failure checks enforce a shared network deadline, exclude
certificate and validation failures from retries, bound shutdown, recover lost
acknowledgements only for idempotent ceremony messages, and stop key operations
after a failed private-state or audit-log write. Secret-free failure diagnostics
survive test-fixture cleanup. No transport retry can acknowledge an unpersisted
cached private mutation.

The native `threshold_audit` fuzz target accepts public statement/packet vectors,
TAG1 configurations and TAP1 proposal envelopes. To generate and replay seeds:

```sh
cmake -S . -B /tmp/elements-audit-native-build -DBUILD_FUZZ_BINARY=ON
cmake --build /tmp/elements-audit-native-build --target threshold_audit_replay -j 4
env THRESHOLD_AUDIT_SECP256K1=/tmp/elements-audit-secp/lib/libsecp256k1.so \
  python3 contrib/threshold-audit/make_fuzz_corpus.py \
  --output /tmp/elements-audit-fuzz-corpus
/tmp/elements-audit-native-build/bin/threshold_audit_replay \
  /tmp/elements-audit-fuzz-corpus
```

The separate replay driver executes the registered public-parser target in an
ordinary build. The full `fuzz` executable requires `BUILD_FOR_FUZZING=ON`;
use a separate compiler-instrumented libFuzzer build for coverage-guided mutation,
as described in the repository's fuzzing instructions. A successful seed replay
is not a sustained coverage-guided campaign.
Seed envelopes use big-endian uint32 lengths and public data only. Packet seeds
encode genesis32, template32, index4, length-prefixed script, three 33-byte
commitment/key encodings, registry-count4/IDs32 and a length-prefixed packet.
Governance seeds start `TAPF`, then chain32, boundary4 and length-prefixed current
TAG1, proposed TAG1 and TAP1. Their test authorization policy is P2WSH OP_TRUE,
witness limit 108, P2WSH OP_TRUE fedpeg, and one empty extension.

## Validation recorded on 2026-11-11

- Release daemon, CLI, native unit tests, fuzz target and replay driver build.
- 73 core Python proof/threshold/disclosure/governance tests and 16 guardian
  service/runtime/startup tests pass. The startup regression now covers a child
  that sends only a partial startup line; diagnostics survive fixture cleanup.
  All 89 current cases are covered by the passing 88-case full run and the final
  outgoing-TLS-handshake case, which was added while that run was in progress.
- The final two-node native lifecycle test passes, including C++ wallet proof
  generation, recipient access, malformed packets in mempool/direct blocks,
  signed readiness for every historical key, compact-root authentication,
  rollover, restart/reorg, mining budget and native PSET tampering rejection.
- The final guardian-backed native test passes with 25 separate services. It
  creates native transactions across two key eras, transfers both keys from
  7-of-10 to 11-of-15, stops all outgoing guardians, recovers both eras using only
  incoming guardians, then restarts the incoming guardians and a node and
  recovers both again. It independently verifies public log chains/checkpoints,
  reconstructs authorized request scopes, checks each approval signature and
  matches public output references to the actual transaction statement.
- 32 native unit cases across blinding, blockchain, DynaFed, mining, wallet and
  wallet PSET suites pass. Existing `feature_dynafed.py` (legacy wallet) and
  `rpc_psbt.py` (descriptor wallet) regressions pass. The earlier unchanged-chain
  `feature_assumevalid.py` regression also passed.
- Native/Python governance interoperability accepts handoff/rollover and rejects
  18 adversarial cases. Native-created packets pass independent Python
  verification and 7-of-10 full-opening recovery at both uint64 extremes and a
  zero-blinder edge case. Fourteen malformed/tampered packet vectors reject.
- Public decoding matches old C++ and Python on 1,598 encodings. The registered
  native public-parser target successfully replays 84 valid/adversarial corpus
  seeds. Python syntax, whitespace and default-format checks pass.
- Eleven fail-fast configuration checks reject known-network audit flags,
  absent/malformed genesis manifests, disabled configuration, mismatched keys,
  invalid/duplicate assets, delayed activation, invalid genesis generation,
  unsupported proof schemes and incorrect initial policy binding.

Local evidence includes:

```text
/tmp/elements-audit-v2-native-run2/test_framework.log
/tmp/elements-audit-v2-guardian-run2/test_framework.log
/tmp/elements-audit-v2-guardian-recheck.log
/tmp/elements-audit-v2-final-python-tests.log
/tmp/elements-audit-v2-final-python-additional.log
/tmp/elements-audit-v2-transport-deadline.log
/tmp/elements-audit-v2-guardian-runtime-final.log
/tmp/elements-audit-v2-final-unit-tests.log
/tmp/elements-audit-v2-baseline-dynafed.log
/tmp/elements-audit-v2-baseline-psbt.log
/tmp/elements-audit-v2-fuzz-replay.log
/tmp/elements-audit-v2-startup-checks.log
/tmp/elements-audit-governance-check/results.log
/tmp/threshold-audit-native/optimization-results.json
```

These temporary artifacts are local evidence, not repository fixtures. All
owned test nodes and guardians were stopped after the completed runs. The audit
tests sign headers directly with a test key so they can submit deliberately
invalid candidates. The existing DynaFed regression additionally requires a
legacy-wallet-enabled build; use `WITH_BDB=ON` with a suitable Berkeley DB library
only for fresh compatible test wallets.

## Work still required

Native integration covers versioned append-only asset registration, paired
confidential outputs and single-owner PSET blinding. Register real issued asset
IDs after explicit issuance and before confidential distribution. Asset
registration authenticates recovery policy; it does not prove fiat reserves,
issuer status or redemption obligations. Partial collaborative PSET coordination,
automatic stale-transaction reconstruction and confidential issuance-amount
recovery remain unfinished.

The guardian services persist all retained keys, require signed scoped approvals,
deliver partials only to a configured recipient over mutual TLS, and fsync a
hash-chained log before release. Signed checkpoints can be retained independently.
Their chain activation/reorg observer is still trusted external orchestration;
production needs authenticated chain-derived output/history lookup and monitoring.
Historical transaction and recovery-witness archives must remain available;
retaining secret shares cannot recover ciphertexts discarded by every archive.

Specialist review of the proof composition and actively secure DKG/handoff
protocol, protected key storage/HSM integration, rollback-resistant storage,
independent disclosure witnesses and institutional operating procedures remain
necessary. Python secret arithmetic and ordinary file permissions do not supply
hardware protection or secure erasure. Legal participant identities require a
separate identity layer. See [GUARDIAN-SERVICES.md](GUARDIAN-SERVICES.md).

## Issued-asset registry regression

Run the two-node native EUR/USD registry test against a fresh temporary chain:

```sh
env THRESHOLD_AUDIT_SECP256K1=/tmp/elements-audit-secp/lib/libsecp256k1.so \
  python3 test/functional/feature_threshold_audit_assets.py \
  --configfile=/tmp/elements-audit-native-build/test/config.ini
```

It bootstraps explicit EUR/USD asset and reissuance-token IDs, approves all four
through the normal DynaFed readiness/vote flow, checks native wallet/PSET proofs
under the resulting five-ID registry, and exercises malformed proposals,
uncertified registry substitution, stale pending transactions, historical
threshold recovery, full verification and invalidate/reconsider rollback.
Currency names are test metadata and do not establish fiat backing.
