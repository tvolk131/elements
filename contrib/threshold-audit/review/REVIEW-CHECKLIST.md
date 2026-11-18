# Independent review worklist

Record each item as inspected, tested, proven under stated assumptions,
unresolved or out of scope. Link findings to inventory source hashes and exact
commands/test evidence. A checked box is not a security certification.

## Source and reproducibility

- [ ] Verify `base_commit`, submodule versions and `source_tree_digest`; inspect
      all overlay files and identify unreviewed dependencies/toolchain inputs.
- [ ] Reproduce public Python vectors and native expected-result checks. Confirm
      positive acceptance as well as negative rejection; distinguish parser
      replay from semantic assertions and coverage-guided fuzzing.
- [ ] Rebuild from a clean exported patch bundle and run the selected native,
      wallet, guardian and settlement tests. Preserve failures and cleanup only
      processes created by that run.
- [ ] Confirm test-only deterministic RNG and known public scalars cannot enter
      service/wallet code paths. Confirm runtime credentials/state are absent
      from source/review archives and reports.

## Cryptographic construction

- [ ] State an exact security definition and adversary/oracle model for complete
      opening recovery; assess passive privacy, malleability and chosen inputs.
- [ ] Analyze TAC2 representation-proof knowledge/soundness and Fiat-Shamir
      composition with native range proofs, OR and DLEQ aggregate consistency.
- [ ] Verify generator derivation/independence and Elements commitment-to-SEC
      conversion, including noncanonical coordinates, zero/infinity and parity.
- [ ] Verify `[0,65535]` exact range bounds, all 36 limbs, endianness, uint64
      limits, scalar reduction semantics and recovered commitment checks.
- [ ] Check transcript length delimiting, domain separation, complete context,
      byte order and acyclic construction. Attempt packet/transcript splicing
      between chains, outputs, scripts, keys, assets and transactions.
- [ ] Review random-scalar sampling, entropy failures, native secret operations,
      private branches, memory lifetime, cleansing and cross-process interfaces.

## Sharing, readiness and historical recovery

- [ ] Separate honest/malicious/mobile/adaptive guardian models. Define the
      minimum honest setup/refresh assumptions and required erasure schedule.
- [ ] Analyze dealer equivocation, malformed/correlated polynomials, private
      evaluation consistency, qualification/complaints, reliable broadcast and
      denial of service. Do not treat shape checks as a secure DKG proof.
- [ ] Verify TAG1 canonicality, full history retention, fresh rollover keys,
      share-epoch increments, complete current rosters and no zero public shares.
- [ ] Verify every retained key has its own distinct ready quorum; identity
      signatures bind chain/predecessor/proposed config/height/key/member/proof.
- [ ] Exercise multiple consecutive handovers and key eras, restart/backup
      restoration, incoming decryption of oldest outputs, retired-service
      exclusion and honest failure without enough shares.
- [ ] Explicitly assess copied old quorum shares and explain why revocation of
      retained knowledge is outside the current guarantee.

## Native consensus, wallet and cache integration

- [ ] Trace actual candidate/creation/next-block policy selection through block
      validation, mempool, wallet blinding, PSET extraction and historical lookup.
- [ ] Confirm disabled chains retain their original wire format/behavior.
- [ ] Check all confidentiality modes, coinbase, issuance/reissuance and explicit
      output rules. Check consensus proof enforcement independently of assumevalid.
- [ ] Mutate template fields, nonce, packet, key/version, registry and scripts;
      test mempool/direct block paths and native/Python verifier agreement.
- [ ] Compare cold/warm/disabled-cache outcomes for ordinary range/surjection
      checks and new audit/governance checks. Review every cache preimage field,
      length prefix, successful-only insertion and contextual invalidation.
- [ ] Check version-zero registry/genesis circularity exception cannot authorize
      mutation; test append-only/version-overflow/certificate substitution cases.
- [ ] Check compact DynaFed elided roots and activation boundary semantics,
      resource limits, parser bounds and header-memory accounting/DoS behavior.
- [ ] Check wallet/PSET fee sizing, proof preservation and stale-policy failure
      behavior; collaborative unsupported cases must fail explicitly.

## Control plane, evidence and the settlement sandbox

- [ ] Verify separate TLS/approval/spending/block keys, authenticated roles,
      tenant isolation, session revocation, CSRF/origin checks and credential
      renewal/backup procedures across independent administrative domains.
- [ ] Verify scoped disclosure request, exact packet/committee/member bindings,
      recipient-only delivery, replay/expiry behavior and independent checkpoints.
- [ ] Test coordinator attempts to obtain approval signatures using bearer
      tokens; test malicious/duplicate/insufficient operator approvals.
- [ ] Verify exact proposal/template binding and independent native-activation
      checks before migration. Test stages/expiry before and after commitment.
- [ ] Verify original economic certificates/bank escrow IDs remain immutable;
      follow every confirmed migration link to the current spending outpoint.
- [ ] Test duplicate/out-of-order bank events, ambiguous payouts, no second
      payment, independently confirmed escrow, failed-payment refund and
      independent bank/chain/customer-liability reconciliation.
- [ ] Test crash/restart at each durable boundary, partial signing, unchanged
      block candidate retry, ledger reservations, post-settlement reorg policy
      and stale/rolled-back signer databases.
- [ ] Specify block-quorum safety/finality assumptions; do not equate two
      offline-service tolerance with two Byzantine-fault tolerance.

## Report and release gates

- [ ] Assign each claim to a mathematical argument, implementation check,
      deployment assumption or open question; list contradictory evidence.
- [ ] Separate verified defects from hypotheses and note negative-test scope.
- [ ] Provide minimal reproduction and regression tests for each accepted fix.
- [ ] Require a new inventory/review delta after relevant source, library,
      parameter, wire-format or trust-model changes.
- [ ] Define production gates for reviewed cryptography/ceremonies, independent
      operations, hardware custody, bank/legal arrangements, finality, monitoring,
      performance and an incident-response exercise.
