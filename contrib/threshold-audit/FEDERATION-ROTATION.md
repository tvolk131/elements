# Same-chain institutional federation rotation

This milestone replaces the block-signing functionaries, audit guardians and
treasury institutions on one existing Elements chain. Genesis, asset IDs,
customer addresses, balances and historical transactions remain on that chain.
The local scenario moves from 7-of-10 audit guardians to a wholly new 11-of-15
committee, and from one 3-of-5 block/treasury group to another 3-of-5 group.

Bank balances, payments, institutional identities and credentials remain test
fixtures. The protocol and Python key handling remain research software.

## Procedure

Start or resume the [settlement sandbox](SETTLEMENT-SANDBOX.md). Startup upgrades
its bootstrap OP_TRUE block policy through DynaFed to actual federation P2WSH
signing before enabling the web application. Each institution holds a separate
block-signing key, treasury spending key and BIP340 approval key.

The guardian interface has a **Federation lifecycle** view. A bank administrator
can prepare a handover. Preparation refuses unconfirmed execution transactions
and unfinished credited deposits; they must finish first. Up to six confirmed
outstanding redemption escrows can carry across this sandbox transition.

1. **Prepare and hold.** Pause new financial execution, the settlement worker
   and automatic block production. Generate/reload incoming identities and
   distribute new shares for every retained audit key without reconstructing a
   master scalar in the coordinator. Prepare exact authority and escrow
   migration transactions. Persist their bytes, public summaries and hashes.
2. **Obtain outgoing approval.** Three outgoing institutions independently
   approve the full manifest through their own service windows and credentials.
   The domain-separated certificate binds genesis, source/target policies,
   exact DynaFed proposal, target audit configuration, epoch and migration
   transaction templates. The coordinator's bearer credentials cannot approve.
3. **Activate the native policy.** Outgoing functionaries sign voting blocks.
   Each service independently checks the exact approved proposal and native
   candidate validity. At the boundary, incoming functionaries sign the first
   block under the new policy. Activate the incoming audit shares.
4. **Migrate treasury control.** Outgoing institutions independently verify the
   incoming native policy is active before signing migrations. Each authority
   token or tracked escrow moves in full to one incoming output. Confirm each
   exact transaction on the same chain before proceeding.
5. **Activate settlement policy.** Preserve historical approval public keys,
   install the incoming operational group, record confirmed escrow mappings,
   and require fresh approvals for queued unexecuted requests. Keep already
   executed redemption authorizations and bank references unchanged.
6. **Retire and resume.** Stop outgoing audit/institution services, revoke
   outgoing application sessions and logins, then resume block production and
   settlement under the incoming membership.

During the overlap, the UI reports actual block/audit policy separately from
treasury ownership; it does not imply that all three switch atomically.
Incoming credentials are appended to the private runtime `credentials.json`.
After the demonstrated handover, use `institution-b-1` through
`institution-b-5` for guardian logins; outgoing `institution-1` through
`institution-5` logins are revoked. Bank and corporate accounts remain usable.

## Pending redemptions

Bank receipts and economic approval certificates retain their original
`escrow_txid`. A separate `current_escrow` locator points to the migrated output.
Incoming spending services verify the complete signed migration record and its
confirmed native transaction, including original case, asset, amount, source
outpoint and target script. Updating a coordinator locator alone grants no
spending authority.

An unresolved bank payment keeps its one payment ID through rotation. A definite
success authorizes burning the migrated escrow. A definite failure permits a
new cancellation case and fresh incoming approval quorum before refund. An
unknown or pending payment remains locked and cannot be refunded.

## Restart, expiry and chain changes

The coordinator writes stages atomically with fsync before external actions.
Migration and financial outboxes reuse exact transaction bytes on retry. Block
production also persists its exact unsigned candidate before asking any signer;
after partial signing or restart it retries that candidate, avoiding an
accidental second signature request at the same height.
Private launch configurations are versioned and written atomically; unknown
versions and missing active signing keys fail startup. Institution readiness has
a single deadline even if a child emits only a partial response. The launcher
tracks the process handles it owns and closes its workers, databases and servers
on shutdown.
Block services run full native consensus proposal validation with the RPC's
optional relay-policy filter disabled; that filter rejects the intentional
OP_RETURN burns used here. Treasury services separately verify exact authorized
burn amounts, escrow references and signed bank payment evidence.

Resume restores the required outgoing and incoming services for an incomplete
handover. A completed handover restores only current audit and institution
membership. Incoming native policy and activation ancestry are rechecked before
migration and settlement activation; disagreement holds the transition for
reconciliation. Source signing services independently perform native activation
checks too.

Expired authorization cannot start a new rotation. Once the exact incoming
native policy is independently verified as committed, the already approved
migration may finish after its original expiry. Expiry before commitment or a
conflicting external chain transition may still require operator reconciliation;
there is no general automatic rollback or reauthorization engine.

## Acceptance scenario

With a fresh running sandbox, use the same runtime for all phases:

```sh
PYTHONPATH=contrib/threshold-audit:test/functional \
  python3 -u -m settlement.rotation_smoke /tmp/ROTATION-RUNTIME --phase seed
PYTHONPATH=contrib/threshold-audit:test/functional \
  python3 -u -m settlement.rotation_smoke /tmp/ROTATION-RUNTIME --phase stage
```

The seed phase issues real TestEUR/TestUSD and creates two confirmed escrows
with ambiguous simulated payments. The stage phase rejects advancement without
a quorum, checks the financial hold, obtains independent outgoing signatures and
activates incoming native policy/shares. It stops before treasury migration.
Stop the sandbox and resume that same runtime:

```sh
PYTHONPATH=contrib/threshold-audit:test/functional \
  python3 -u -m settlement.sandbox --resume /tmp/ROTATION-RUNTIME
```

Then finish:

```sh
PYTHONPATH=contrib/threshold-audit:test/functional \
  python3 -u -m settlement.rotation_smoke /tmp/ROTATION-RUNTIME --phase finish
```

Completion checks unchanged genesis and asset IDs, confirmed authority/escrow
migrations, old-session revocation, an incoming-authorized new issuance,
completion of the original payout, a fresh-quorum refund, historical EUR
recovery using eleven incoming guardians after outgoing services stop, and
wallet/reserve reconciliation. The driver records actual txids in private
`rotation-smoke.json`. Guardian attachment for this test reuses fixture operator
credentials and does not start or stop live services; it is not a production
disclosure-approval UI.

The [full verification command](VERIFICATION.md) runs a fresh A-to-B-to-C
scenario using `settlement.repeated_rotation_smoke`, with the phases `seed`,
`stage-b`, `stage-c` and `finish`. It restarts after each native membership
activation, before the corresponding treasury migration, and once after C
completes. A's two ambiguous escrows remain unresolved through B. C verifies
both confirmed migration links before completing their original payout and
refund, and recovers outputs created under A and B. Completed public handover
records are retained in write-once archives and a hash-linked checkpoint journal;
these local files are not externally anchored audit evidence.

`settlement.runtime_faults` separately exercises a restored stale workflow
database, an unsupported configuration version and a missing active signing key.
New settlement is held when a customer wallet balance differs from its internal
ledger; restoring the correct backup preserves the original chain and issuance
transactions. This does not replace a production backup or reconciliation design.

Focused tests:

```sh
PYTHONPATH=contrib/threshold-audit:test/functional \
  python3 -m unittest settlement.test_settlement \
    settlement.test_treasury_rotation settlement.test_federation_helpers -v
```

## Pilot boundaries

This is a deliberately quiescent handover. Pausing block production preserves
epoch-bound preparation while humans approve; an online production protocol
needs a separate scheduling/renewal design. The 3-of-5 fixture demonstrates
operation with two services offline. It does not establish Byzantine fork
safety against an equivocating signer under a network partition. Production
requires explicit quorum-intersection, finality and rollback assumptions.

Only tracked settlement escrows and the complete known issuance authorities are
migrated. Late payments to retired scripts and arbitrary unmanaged wallet/RPC
activity require separate reconciliation. A copied historical audit quorum can
still decrypt; rotation does not revoke information already retained.

Real bank signer mandates are outside Elements. The simulator changes its
operational approval policy, but no conventional bank account is changed by
this software. HSM custody, malicious-secure resharing, production deployment,
external audit anchoring and post-payment reorg compensation remain open.
