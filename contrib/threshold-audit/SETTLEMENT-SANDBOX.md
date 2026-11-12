# Institutional settlement sandbox

This local pilot connects the experimental native Elements recovery protocol to
an authenticated bank/corporate wallet and an institution approval interface.
It creates **TestEUR and TestUSD**, with simulated custodian balances. There is
no real bank connection, reserve account, licensed issuer or redemption promise.
The legal entity owing redemption remains an open product/legal decision.

## Run and resume

For everyday use, select one existing runtime and control it through the demo
manager. These commands resume the same chain and preserve wallets, keys,
credentials, cases and handover history:

```sh
python3 contrib/threshold-audit/manage.py select /path/to/existing-runtime
python3 contrib/threshold-audit/manage.py start
python3 contrib/threshold-audit/manage.py status
python3 contrib/threshold-audit/manage.py stop
```

The selection is a private pointer at `/tmp/elements-audit-demo-<uid>.json`.
Leave the selected demo stopped while idle and start it on demand.
`--registry` overrides that file; `--runtime` before the action overrides the
selected directory for one command. Start is idempotent. Stop validates the
coordinator's executable, checkout, arguments and PID birth identity, then lets
it close its services. Orphan cleanup is limited to recognized server roles
pointing inside that exact runtime. Commands never delete runtime data or stop
an unrelated process merely because it reuses an old PID. Concurrent manager
start/stop commands on one runtime are refused. Failed startup retains a private
`manager.log` and cleans up only the process tree it just launched.

A rotated demo normally has 22 processes/listeners: one web app, one Elements
node, 15 audit guardians and five institution signers. The isolated guardians
and signers deliberately retain separate key custody. Wallet and guardian
consoles share the one app port. Additional stacks are needed only for explicit
test scenarios; stop superseded demos rather than keeping every milestone live.

Keep one native build and one shared-library build for reuse. Reports, review
patches and private historical runtimes should be retained independently of
running processes. The ignored `test/cache` is regenerable. Stopped block/undo
files can also have zero-filled allocation reclaimed with `fallocate --dig-holes`
on Linux, provided no node is using them and byte hashes and lengths are checked
before and after. Never remove wallet databases, shares, credentials or chain
state as though they were a build cache.

Build the native daemon and shared secp256k1 library using
[NATIVE-INTEGRATION.md](NATIVE-INTEGRATION.md). From the repository root:

```sh
PYTHONPATH=contrib/threshold-audit:test/functional \
  python3 -u -m settlement.sandbox \
  --daemon /tmp/elements-audit-native-build/bin/elementsd \
  --library /tmp/elements-audit-secp/lib/libsecp256k1.so
```

The command prints the loopback URL and the path to a private `credentials.json`
file. Open `/wallet` for bank/corporate work and `/guardian` for institution
approvals. The same application routes by authenticated role. Each institution
also has a separate approval window and approval passphrase. Never enter that
passphrase into the central wallet application.

The runtime is a new private directory under `/tmp`. `--directory` accepts an
empty directory; existing state is never overwritten. Stop with Ctrl-C or
SIGTERM. To resume the same chain, users, wallet keys, guardian state and outbox:

```sh
PYTHONPATH=contrib/threshold-audit:test/functional \
  python3 -u -m settlement.sandbox --resume /tmp/elements-institutional-EXAMPLE
```

The fixture CA certificates last two days. Resuming after expiry requires a
proper credential-renewal procedure; the launcher does not silently regenerate
guardian identities or replace the chain. Runtime contents contain test keys,
RPC credentials and user passwords. Keep them private. This is a same-user
local process fixture, not isolation from a compromised host administrator.

## Components and authority

* One actual Elements daemon, with Bitcoin peg-in verification disabled. Its
  bootstrap OP_TRUE policy upgrades to real federation P2WSH block signatures
  before serving the GUI. It normally mines a block about every three seconds.
* Ten isolated audit guardian processes, with research distributed key generation
  and 7-of-10 recovery. Historical handoff remains available through the existing
  guardian service protocol; this web interface does not administer ceremonies
  or request disclosure.
* Five institution services. Each has its own ECDSA spending key, separate
  BIP340 approval identity, durable signing bindings and independent approval
  passphrase. Three signatures authorize treasury spends in this fixture.
* The full reissuance-token balance for each currency is held in a real
  3-of-5 P2WSH output. The coordinator wallet imports the script and blinding
  key for observation; it has no federation spending private keys.
* Bank-managed customer wallets hold the test currency and a separate policy
  asset for transaction fees. Customer transfers/escrows use those wallet keys;
  maker/checker and institution approval are application policy for these spends.
* A SQLite workflow, double-entry reserve journal, transaction outbox, hash-linked
  evidence and explicitly simulated bank payment gateway.

The 3-of-5 operational fixture does not change the 7-of-10 audit threshold.
Operational spending membership is separate from DynaFed block-signing and
audit-key membership. The [same-chain handover](FEDERATION-ROTATION.md) coordinates
these policies, migrates treasury authority and pending escrows, and revokes
outgoing sessions through an explicit, quorum-approved staged procedure.

## Asset registration and confidential outputs

Bootstrap creates zero currency supply and explicit reissuance tokens. A
DynaFed transition registers both currency IDs and both token IDs in the native
append-only recovery registry. Tokens then move to the federation's confidential
multisig address. Initial default registry version is 0; this first append is 1.

The native wallet creates mandatory TAC2 recovery proofs for confidential
currency, token and fee/change outputs. Ordinary recipient unblinding remains
available. Historical verification uses the registry at the output's creation
block. Appending registry entries invalidates pending confidential proofs, which
must be regenerated under the new policy. This pilot does not automatically
replace already approved pending treasury transactions across such a change.

Registration authenticates asset IDs. Currency labels, reserve facts, issuer
names and redemption terms are off-chain configuration. Explicit outputs remain
permitted by this experiment; it mandates recovery for confidential outputs,
not confidentiality of every transfer. EUR/USD cents are an application policy:
Elements still supports eight decimal places. Reconciliation reports unsupported
sub-cent wallet amounts rather than truncating them.

## Issuance and redemption

For issuance, a bank maker creates a deposit case. A bank administrator supplies
an explicit simulated cash-credit event with a stable receipt ID. Another user
checks the case. Before institution approval, the adapter creates and durably
stores the exact native issuance template; the simulated custodian seals that
receipt to the one case and template. Each institution independently reviews the
amount, beneficiary, chain, receipt and template in its own service window.
Three BIP340 approvals authorize that exact transaction. Independent services
then produce ECDSA signatures after checking its mint amount, destination,
authority return, previous-output openings and fee bound. The coordinator
persists signed bytes before broadcasting. Retries inspect/rebroadcast those
bytes, using the same txid and authority input.

For redemption, the customer and checker approve a bank beneficiary and three
institutions authorize the request. The customer's tokens first move into
federation escrow. The gateway verifies the currently confirmed escrow and
threshold certificate before creating one durable payout ID. A definite signed
payment receipt authorizes the federation to spend that exact escrow into an
OP_RETURN burn. The customer never receives a payout merely because the API
asserts a chain transaction confirmed.

`pending` models a bank cut-off/delay; `unknown` models an ambiguous submission.
Neither permits a refund or a second payment ID. An explicit reconciliation event
resolves the existing payment. A definite failure permits a **new** cancellation
case: the bank locks the original payment against future execution and signs
nonpayment evidence; a fresh checker and quorum authorize returning the escrow
to the original customer. Freezing a simulated reserve account blocks new
issuance and payouts while preserving escrow.

Quorum approval requires distinct authenticated institutions. The coordinator's
transaction-service bearer tokens cannot obtain approval signatures. Bank
receipts are independently keyed, but the simulated bank key lives in the local
launcher/web process: this is not security against a malicious custodian or
compromised bank simulator. A real bank adapter must independently enforce
receipt uniqueness, one-template authorization, account mandates, payment
approvals and reliable final/ambiguous outcomes. Real joint account control is a
bank mandate and operational arrangement; Elements signatures alone cannot
control a conventional bank account.

## Validation and remaining boundaries

Run the failure-oriented backend suite:

```sh
PYTHONPATH=contrib/threshold-audit:test/functional \
  python3 -m unittest settlement.test_settlement -v
```

Against a fresh running pilot, exercise actual Elements issuance, confidential
transfer, escrow/payout/burn, failed-payment return and unknown-payment resolution:

```sh
PYTHONPATH=contrib/threshold-audit:test/functional \
  python3 -u -m settlement.smoke /tmp/elements-institutional-EXAMPLE
```

This driver reads all fixture credentials; the web application does not. It
records actual txids and reconciliation in the runtime's `smoke-result.json`.
Unit-test fake chain hashes are confined to `test_settlement.py`.

The durable evidence is attributable sandbox evidence, not an immutable audit
system: a privileged database writer can rewrite and rehash its history. There
is no external anchoring, HSM, reviewed production cryptography, malicious-secure
resharing, bank integration, fee sponsorship economics, business-day calendar,
production finality policy or post-settlement reorg compensation engine. Wallet
reconciliation can flag divergence; it cannot undo a real completed bank
payment. Approval expiry and policy/registry changes may require operational
reconciliation of a stranded case. Beneficiaries are configured test fixtures;
the GUI does not pretend to save unimplemented account-management changes.

The audit-chain header-sync fixture has a 64 MiB per-peer retained-header budget
that preserves the full commitment lookahead. Dense valid governance histories
can exceed it and abort sync; production needs deduplication or another bounded
representation. See the native documentation for the remaining protocol limits.
