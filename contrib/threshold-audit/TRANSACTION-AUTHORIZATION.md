# Federation authorization of every transaction

Research prototype. Once a chain turns this rule on, no transaction confirms
unless a quorum of the federation's operators has authorized it. It is the
ledger-level control that the application-level approvals sit on top of: the
federation decides what moves, and every node checks that it did.

## The rule

The full DynaFed parameters carry `tx_authorization`: empty, or one threshold
byte followed by 1 to 16 distinct 32-byte BIP340 keys. While it is set for a
block, every non-coinbase transaction in that block must carry an
authorization in its witness:

```
expiry_height (4 bytes, little-endian)
threshold × ( key index (1 byte) || BIP340 signature (64 bytes) )
```

Indexes must increase, and there must be exactly `threshold` signatures. Each
signs

```
SHA256( "Elements/tx-authorization/v1" || genesis hash || SHA256(policy)
        || transaction template hash || expiry_height (big-endian) )
```

The template hash is the transaction ID with every `scriptSig` cleared, the
same one recovery packets bind. It covers every input and output, so an
authorization cannot be moved to another transaction. It does not cover
witnesses, so a transaction can be authorized after it is signed and
re-authorized without changing its ID.

A block at height `h` may include the transaction only while
`expiry_height >= h`. The mempool applies the rule for the next block, checks
it before any recovery proof, and drops entries when they expire or when the
policy changes. While the policy is empty, a transaction that carries an
authorization is invalid.

The reject reasons are `bad-tx-authorization-missing`, `-unexpected`,
`-malformed`, `-expired` and `-signature`.

## Turning it on and changing keys

Every audit chain starts with the rule off. A DynaFed proposal sets it with
the `tx_authorization` field of `getnewblockhex`; omitting the field carries
the current policy forward. A proposal can replace the keys but cannot clear
them (`invalid-tx-authorization-policy`).

The audit configuration's `signer_policy` binds the authorizer set once it is
set, so the guardians' signed readiness for a transition covers it too.
Authorizations bind the exact policy bytes: those issued under the old keys
stop being valid at the activation boundary and are issued again.

`getblockchaininfo` and the block's `dynamic_parameters` report the policy.

## What it does not do

- It adds accountability, not a new trust assumption: in the sandbox the same
  five operators sign blocks and authorize transactions, with separate keys.
- Authorizers see what the chain shows. They are not given amounts.
- A node wallet does not request authorizations. `sendtoaddress` on a chain
  with the rule on creates a transaction the node will not relay.
- There is no freeze list. An operator that declines to sign is the only
  refusal, and a single one does not block a 3-of-5 quorum.
- Proposals that replace the authorizer keys need block signers' votes, not
  the outgoing authorizers' signatures.

## In the settlement sandbox

The rule is activated together with federation block signing at startup, with
the five operators' approval keys and a threshold of three. A handover
proposes the incoming operators' keys in the same DynaFed transition.

Each operator's service signs automatically. It refuses unless

- its key is in the policy its own node reports,
- the expiry is within the next 20 blocks, and
- every output is the fee, a burn, its treasury, or an address carrying a
  member bank's signed registration.

The simulated bank registers only addresses held in wallets it runs: its
customers' wallets and the network's own (the sponsor wallet and the
treasuries it watches). A payment to any other address goes without a
registration, and the operators refuse it. The bank's key still sits in
the coordinator process, so a coordinator that chose to could register an
outside address itself; a real bank would hold that key in its own service.

`ElementsAdapter.authorize` collects the quorum and is applied to every
transaction the coordinator sends, including retries. It tells two failures
apart:

- **Refused** (`AuthorizationRefused`): so many operators answered no that
  the rest cannot reach the threshold. A customer payment that is refused
  before anything reached the chain is closed as rejected with
  `declined_by: "institutions"`, and its coins are released.
- **Unavailable** (`AuthorizationUnavailable`): too few operators
  answered. The request waits ("2 of 5 reachable, 3 needed") and the worker
  retries the same transaction until enough are back.

The guardian console's **Ledger** page reads recent blocks from the node and
shows, per transaction, what the chain recorded (hidden amounts, sealed
recovery records, token issuance or burns), which operators authorized it
and until which block, and which operators confirmed its block. The
service checks every signature it shows against the operators' keys. Its
**Send without the operators** button has a bank wallet sign a valid
payment to itself and offers it to the node with and without an
authorization; only the refused copy is broadcast, and the node refuses it.

## Tests

- `test/functional/feature_threshold_audit_authorization.py`: two nodes,
  mempool and block validation, expiry, re-keying, restart.
- `settlement/test_treasury_rotation.py`: what an operator will and will
  not authorize, and how the coordinator tells a refusal from too few
  operators.
- `settlement/test_settlement.py`: a refused payment is declined and
  released; a payment waits while too few operators answer.
- `settlement/ui/src/ledger.test.tsx`: the Ledger page.
