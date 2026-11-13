# Institutional settlement sandbox

This local pilot connects the experimental native Elements recovery protocol to
an authenticated bank/corporate wallet and an institution approval interface.
It creates **TestEUR and TestUSD**, with simulated custodian balances. There is
no real bank connection, reserve account, licensed issuer or redemption promise.
The legal entity owing redemption remains an open product/legal decision.

For a product or leadership walkthrough, see the [live demo runbook](DEMO.md).
It seeds a dedicated runtime with demo sign-in and a reset point.

## Run and resume

Build the [web app](settlement/ui/README.md) first (`npm ci` and `npm run build`
in `contrib/threshold-audit/settlement/ui`, with Node.js 22.12+). Node is only a
build tool: the Python settlement server serves the built files, so the running
demo needs no Node process.

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

A rotated demo normally has 22 processes: one Python settlement coordinator,
one Elements node, 15 audit guardians and five institution signers. The isolated
guardians and signers deliberately retain separate key custody. The coordinator
serves the wallet and guardian consoles and their API from one loopback port.
Additional stacks are needed only for explicit
test scenarios; stop superseded demos rather than keeping every milestone live.

Keep one native build and one shared-library build for reuse. Reports, review
patches and private historical runtimes should be retained independently of
running processes. The ignored `test/cache` is regenerable. Stopped block/undo
files can also have zero-filled allocation reclaimed with `fallocate --dig-holes`
on Linux, provided no node is using them and byte hashes and lengths are checked
before and after. Never remove wallet databases, shares, credentials or chain
state as though they were a build cache.

### Optional Rayfish access

A private `mesh.json` in the selected runtime enables IPv6 HTTP front ends on
one explicit Rayfish interface address, forwarding the app to the settlement
server. Its versioned configuration contains
`bind_address`, an exact `.ray` `hostname`, `port`, and an ordered list of
`institution_ports`. The app and approval-window ports must be distinct. Each
institution keeps a separate browser origin. The sandbox starts and stops the
front ends with its existing lifecycle; `manage.py status` reports their URLs.

The front ends validate the external Host, Origin and browser fetch metadata
before translating requests to the existing localhost services. Dashboard
approval URLs and approval-window return origins are translated for the browser;
coordinator-to-institution URLs remain local. Only the institution's public
review pages and passphrase-authenticated `/approve` are routed. The gateway
does not forward central session cookies to institutions or expose their bearer
signing RPC. Node RPC and audit-share services remain bound to localhost.

Grant the app/approval ports only to the intended laptop peers in the Rayfish
firewall. The encrypted mesh carries HTTP here; these are test interfaces, not a
public Internet or production banking deployment. A disabled Rayfish interface
causes an enabled mesh profile to fail startup rather than bind a wildcard.

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

## Wallet journeys

Select a wallet account first. The **Move funds** actions distinguish the four
routes: **Add funds from bank** (bank to chain / peg in), **Withdraw to bank**
(chain to bank / peg out), **Send on-chain**, and **Receive on-chain**. Requests
show the next actor and separate bank evidence from chain confirmation. Account
balances distinguish the total token balance from amounts reserved for pending
requests. Bank simulator tools and transaction hashes are secondary details.

Funding requests currently require a bank maker or bank administrator. Corporate
makers can request sends and withdrawals; the interface explains role limits
without changing authorization. Approval and execution remain separate actions
subject to the existing maker/checker and institution quorum policy.

On-chain sends support managed accounts, exact bank-qualified beneficiary
references, and confidential wallet addresses for this chain. Receiving provides
a beneficiary reference and fresh confidential addresses. Confirmed external
receipts of supported whole-cent test assets are observed and credited once per
outpoint. Unsupported sub-cent receipts, out-of-band spending and reorged receipts
remain subject to the wallet reconciliation hold. There is no automatic reorg
compensation or general external payment provenance service.

## Components and authority

* One actual Elements daemon, with Bitcoin peg-in verification disabled. Its
  bootstrap OP_TRUE policy upgrades to real federation P2WSH block signatures
  before serving the GUI. It normally mines a block about every three seconds.
* Ten isolated audit guardian processes, with research distributed key generation
  and 7-of-10 recovery. Historical handoff remains available through the existing
  guardian service protocol. The disclosure workspace requests sealed recovery;
  federation lifecycle manages the local handover fixture.
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


## Recipient-directed disclosure and cross-bank demo

This capability milestone leaves Elements consensus and the existing ordinary
payment approval policy unchanged. It adds case management and sealed delivery
around the existing mandatory TAC2 output recovery. The demo still runs one
managed chain and 22 processes after rotation; it adds no recipient server or
extra development web server.

Python now also requires `cryptography` (`pip install -r contrib/threshold-audit/requirements-demo.txt`) for recipient-envelope ECDH,
HKDF-SHA256, AES-GCM, and the native recipient key-file reader. Install a currently
patched release in your Python environment; the native library and OpenSSL fixture
requirements remain. Frontend dependencies are pinned in the npm lockfile.

On starting or resuming, idempotent enrollment adds an Initech customer wallet at
`bank-b`, fee coins for that wallet, and capability roles to the private
`credentials.json`. Existing customer ownership, fiat balances, pending requests,
and reserve accounts are not reset. The receiving bank uses the same simulated
issuer/reserve pool; it is not a second live custodian or independently controlled
bank gateway.

### Named recipient and explicit guardian approvals

1. Sign in as `auditor` at `/wallet/disclosures`. Create a recipient key with a
   **separate local key password** and download the encrypted backup. Only the
   compressed public key is registered. Importing a backup restores recipient
   access on another browser. Losing the key/password requires a new key and a
   newly approved case; the federation does not receive the private key.
2. Sign in as `bank-compliance` and create a case for a confirmed payment. Choose
   one to four exact outputs, the registered recipient/key, requesting authority,
   reason/authorization basis and release deadline. Choose **Payment destination**
   to disclose the payment output; change outputs are identified separately.
   Bank compliance is limited to its bank's payments. A receiving bank can select
   only its destination output. `federation-compliance` can also request confirmed
   outputs outside the application payment list by txid and index.
3. Current audit guardians sign in as `audit-guardian-<member ID>` at
   `/guardian/disclosures` and explicitly approve the named recipient and output
   scope. Use the IDs in the current native committee; the rotated example uses
   201 through 215 and requires eleven approvals. The operational
   `institution-c-*` payment identities remain separate. One guardian declining
   is not a veto if a different quorum approves.
4. After the recovery quorum approves, the requester or named recipient selects
   **Send encrypted contributions**. Each guardian independently validates the
   scoped approvals and TAC2 packet, logs authorization before release, and
   encrypts its output-specific partial and DLEQ proofs to the recipient's key.
   The relay retains signed encrypted envelopes and never combines them.
5. Only the named recipient can download the package or select **Open in this
   browser**. Its key password and private scalar stay local. The client verifies
   guardian approval/envelope signatures, partial proofs, signed log checkpoints,
   asset derivation and the recovered asset/value commitments. It can export
   disclosed openings and blinders deliberately; those exports are plaintext.

The case binding includes its authority, reason, recipient key, deadline, exact
outputs and proof hashes. Changing the native recovery policy or membership invalidates **unreleased** cases;
create a new case for approval by the current committee, including for old
outputs. Delivered packages remain decryptable with their recipient key after
expiry or membership changes. Expiry stops further releases, not copied data.
Partial release is durable and retryable before expiry; it is not an atomic
all-or-nothing disclosure across several outputs.

Envelope encryption is secp256k1 ECDH with a fresh ephemeral key, HKDF-SHA256 and
AES-256-GCM. Request/member/recipient context is authenticated; a separate BIP340
signature authenticates the envelope and release timestamp. No audit secret
scalar is reconstructed or handed to the recipient. The package is an
output-specific recovery capability, not a general federation viewing key.
This new composition and browser implementation remain research code.

Normal-path confidentiality is distinct from institutional isolation. The local
fixture coordinator retains guardian **approver TLS credentials** for test
orchestration, and the shared customer-wallet backend already knows its own
wallet openings. Approvals are explicit authenticated user actions in this demo;
this does not demonstrate security against a malicious coordinator, host root,
or maliciously served browser code. A cooperating audit threshold can recover
outputs outside this application. Independent guardian credential custody and
bank gateways remain production work.

Case metadata, public statements and ciphertexts are visible to authorized case
accounts. Recovered openings are not written to the settlement case database or
normal guardian logs. Downloaded guardian-signed receipts/checkpoints can be
retained by recipients independently. There is no external witness deployment or
ledger anchoring, and the local hash-linked case journal alone is rewritable by
a privileged writer. A case records a claimed authority/basis; it does not verify
legal authority or disclose customer identities/business documents automatically.

### Cross-institution payments and receiving

`initech-main@bank-b` resolves to **Initech · Operating** at the second demo bank.
In **Send on-chain**, choose **Beneficiary at a bank**, look up the exact reference,
confirm its signed destination, and create the normal payment request. The
browser and backend verify the bank routing signature and chain, asset, source
account and expiry bindings. Each lookup confirmation is single-use for payment
creation. It does not revoke an already signed payment after its deadline.

Lookup derives a fresh receiving address from the destination's managed wallet;
no descriptor or private key is given to the sender. The demo bank directory
signing keys are held by the shared backend, not independent bank gateways. A
signature authenticates the configured route, not a verified real-world legal
identity. There is no globally browsable customer directory.

**Confidential wallet address** accepts address-only payments; identity remains
unverified. Use **Receive on-chain** to obtain an address. Known customer-wallet
receipts are matched to their account, including cross-bank payments, without
letting the recipient approve or inspect unrelated sender operations. The normal
second-user and three-institution application payment requirements remain.
Use `initech-maker`, `initech-approver`, `bank-b-maker`, `bank-b-approver`,
`bank-b-admin` and `bank-b-compliance` for the receiving side. Simulator
administrators operate the shared test reserve pool; these are not separate
real bank mandates.

### Verifiable exports and acceptance

The recipient can verify an exported package locally with the native library:

```sh
PYTHONPATH=contrib/threshold-audit:test/functional python3 -m settlement.disclosure_recipient \
  --key /private/recipient-key.json --bundle /private/case-package.json \
  --out /private/verified-openings.json --node-config /private/own-node-config.json
```

The key password is prompted locally. The optional private node configuration
contains `rpc_url`. Supplying it checks creation and approval block ancestry,
creation registry, historical recovery key, native approval committee and actual
transaction packet against that node. Without it, cryptographic package/opening
verification is performed but chain inclusion and committee authenticity are not
independently established. Asset IDs use RPC display order in opening exports;
blinder scalars use canonical big-endian hex, not RPC hash-style reversed hex.

Against an **authorized test runtime**, run the explicit-credential acceptance
harness:

```sh
PYTHONPATH=contrib/threshold-audit:test/functional python3 -m settlement.capability_smoke /path/to/runtime
```

It creates a 1.23 TestEUR cross-bank payment, a 0.01 TestEUR address return,
and a 0.02 TestEUR outside-wallet funding followed by a 0.01 TestEUR observed receipt,
uses individual fixture guardian credentials to approve sealed disclosures,
checks current and historical recovery against the real node, and verifies
recipient account isolation and reserve reconciliation. It preserves any
preexisting pending payment rather than approving it. Its state is resumable;
recipient test keys/passwords and decrypted evidence remain in the private
`capability-smoke/` directory. `demo-recipient` is the harness recipient, separate
from the normal `auditor` browser walkthrough. No real funds or bank are involved.
