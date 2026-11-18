# Threat model, trust boundaries and claim limits

This is the model an independent review should refine. Statements under
"intended" describe design goals, not established theorems or deployment
guarantees. The review inventory and verification report identify which source
and evidence were actually inspected.

## Assets and principals

Protected information includes amounts, asset IDs, complete openings, audit
secret shares, guardian identity keys, wallet keys, treasury/block signing keys,
bank payment credentials and disclosure results. Integrity includes absence of
unauthorized minting/payout, correct ledger conservation, policy ancestry,
transaction/context binding, current control of escrow and consistent block
validation across cache states. Availability includes retained historical-share
access, quorum operation, bounded verification and restart recovery.

Distinct roles are the sender/recipient wallet, audit guardian, operator
approval signer, block/treasury signer, settlement coordinator, bank/custodian,
disclosure requester/recipient, chain observer and independent audit-log
observer. Code may colocate roles for a fixture; that does not make their trust
assumptions equivalent. An operator or guardian ID/public key is not evidence of a legal
identity, regulatory authorization or reserve ownership.

## Adversary classes to analyze separately

* A sender constructs malicious commitments, proof bytes, scripts, nonce fields,
  issuance fields or asset registries, including context-reuse/cache collisions.
* An observer sees public chain history, traffic timing and asset registration.
* A requester or coordinator replays approvals, supplies another chain/epoch,
  equivocates public plans, changes an escrow locator or retries after uncertainty.
* Some guardians return invalid partials, withhold service, retain old shares,
  submit malicious dealer commitments/evaluations or coordinate adaptively.
* A signing operator equivocates or its private key/state backup is compromised.
* The host or its administrator reads memory/files, rolls state back, alters entropy,
  interferes with clocks/storage/network or replaces native library binaries.
* A bank/custodian reports a false credit/finality outcome or violates its own
  reserve/payment mandate. Cryptographic evidence cannot make that report true.

Do not collapse these into a single phrase such as "fewer than threshold
compromised": thresholds protect different functions under different models.

## Intended cryptographic properties and evidence limits

TAC2 intends public consistency between encrypted complete-opening information
and the exact asset/value commitments and native statement. Threshold recovery
intends that a valid current quorum for a retained public key can recover the
same opening after membership handoff. Packet, scalar, point and transcript
mutation tests, native/Python differential vectors and actual chain tests are
evidence about implementation behavior. They are not proofs of extractability,
zero knowledge, simulation security, adaptive security or privacy under every
malicious coefficient choice.

Intended arguments depend on secp256k1 discrete-log/DDH assumptions, independent
generator relations, native range-proof security and a justified Fiat-Shamir
composition. This package does not supply a reduction or prove that all these
assumptions compose for TAC2. It is not authenticated/CCA-secure general-purpose
encryption. Review proof malleability, related-input behavior, oracle access and
the effect of exposing complete blinders, not only passive ciphertext privacy.

Shape validation rejects zero public shares, infinite constant/highest
coefficients, bad degree/roster and noncanonical encodings. A correctly shaped
polynomial can still be deliberately known or correlated. Readiness proves
present knowledge of an advertised share, under the proof assumptions; it
does not establish a secure initial ceremony, independent entropy, exclusive
possession, future cooperation or durable availability.

## Historical rotation and retained information

Resharing preserves the public key and historical ciphertexts while changing
committee/threshold and coefficient commitments. Rollover creates a new public
key for future outputs while retaining old key identities and current committees.
Every retained key needs readiness. Native validation prevents deleting or
substituting that public history; a trusted operational process must actually
perform and retain the corresponding private handoffs.

A copied old quorum can decrypt the old ciphertexts after retirement. Rotation
does not erase knowledge, revoke copied shares or prove physical erasure. Secure
proactive refresh against mobile/adaptive compromise requires explicit erasure,
timing and protocol assumptions that are not established by this experiment.
Reorging public policy cannot reconstruct shares that operators erased.

The process-based guardian implementation performs research Feldman-style
distribution/handoff with pinned mTLS and per-process storage. It is **not an
independently reviewed malicious-secure DKG/DPSS implementation**. Reliable
broadcast, complaints/qualification, malicious dealer exclusion, liveness and
adaptive compromise arguments require separate design and proof/review.

## Authorization, results and logs

Cryptographic partials bind the complete packet, current committee and scoped
request. Services restrict approved requests and recipient TLS identities.
Their normal workflow records attributable evidence and signed checkpoints.
An independent observer must retain checkpoints to detect rewriting/truncation.
The locally stored hash chain is not immutable simply because its links verify.

A quorum holding shares can intentionally run the low-level decryption primitive
outside the approval/logging service. Neither an application nor a hash chain
cryptographically forces colluding guardians to record every disclosure. A
recipient receiving complete openings can copy and disclose them. Operational
controls and legal obligations are separate from a mathematical privacy claim.

The disclosure test harness holds fixture approver/recipient credentials and can
automate approvals. The settlement GUI's separate operator windows exercise
an independent credential interface, but same-user local processes share host
administration. Neither is proof of organizational independence under a fully
compromised coordinator host. Private participant identity/KYC mapping and
data exchange between member banks are additional systems, not a consequence of
recovering an amount and asset ID.

## Key handling and hardware

Python scalar arithmetic, allocations, garbage collection, exception paths,
serialization and test fixtures are unsuitable as production key custody. Native
secret operations use libsecp256k1 scalar/ECDH paths and best-effort cleansing;
public commitment decoding uses arbitrary-precision arithmetic. There is no
complete side-channel, entropy, crash-dump, memory-lifetime or secure-erasure
review of the overall prover/service composition. Check private branch behavior
and callbacks even where an individual library operation is constant-time.

An HSM-backed ECDSA signing API does not by itself implement threshold
decryption. This protocol requires secret-share multiplication of varying curve
points, proof-of-knowledge responses, secure key-generation/refresh evaluation
and durable policy. Hardware support, isolation, attestation, backup/rollback
and protocol policy need their own design; do not assume moving a signing key
into a device moves the audit-share protocol with it.

## Operator/chain/settlement boundaries

The 3-of-5 operational fixture demonstrates liveness with two offline services.
It does not prove Byzantine fork safety against an equivocating signer: two
3-of-5 quorums can intersect only in one malicious member. Per-service signed
height records stop an honest service from signing two headers, but do not
create stronger quorum intersection. Production block consensus/finality and
reorg handling must be specified independently of audit-decryption thresholds.

The coordinator has public policies and service tokens; tokens cannot obtain
independent approval signatures. Treasury services check exact transaction
templates, source openings, whole-output migration, native activation and signed
bank evidence. Reissuance authority/escrow UTXOs enforce actual on-chain spending
quorums. Customer wallets in the fixture are bank-managed on one local node;
transfer approval policy is not a new consensus rule over every possible wallet.

The simulated custodian's separately keyed credit/payout/cancellation evidence
lives in the local launcher/web process. A real bank must independently enforce
credits, unique receipt/template binding, mandates, payment limits and reliable
final/unknown outcomes. A signed false receipt is still false. Account
segregation, insolvency priority, reserve eligibility and redemption obligations
are unresolved product/legal arrangements, not attested by registry membership.

## Availability and unresolved failure cases

The pilot pauses settlement and automatic block production during a prepared
handover so epoch-bound authorization remains stable. Source-expiry, conflicting
external transitions, late payments to retired scripts and unmanaged wallet
activity may require explicit operator reconciliation. A real completed bank
payment cannot be undone by a chain reorg. Threshold readiness does not guarantee
that a quorum will be online when disclosure or settlement is needed.

The 80,000-byte proof field, 16 confidential outputs/block, 256 registered assets,
16 retained audit keys, 32 identities and 64 MiB retained-header budget are
prototype constraints. Valid dense histories can exceed the header budget and
abort synchronization. Long-term key/asset growth, fees, throughput, DoS and
bounded-memory behavior must be reviewed against an actual workload.
