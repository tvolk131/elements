# What the demo shows: real, simulated, not built

One page for anyone presenting or describing the settlement sandbox. If a sentence in a deck or a conversation goes beyond the **Real**
column, it needs one of the qualifiers below. Keep this page current with the
branch; it is the reference when the code and a slide disagree.

Terms: **operators** run the network (they sign blocks, authorize every
transaction and co-sign issuance); **members** are the banks that serve
customers on it. The operators also hold the disclosure key: one federation,
one threshold (5 of 7) for everything. Code, configuration and login IDs still
say `institution` for operators, and `guardian` for the disclosure key services
each operator runs.
The interface calls the network **CEND** and the payment tokens **UNITED EUR**
and **UNITED USD**; in the sandbox these are test tokens with simulated backing.

## Real: running code, enforced where stated

| Claim | Enforced by | Notes |
|---|---|---|
| Payment amounts and assets are hidden on the ledger | Elements consensus | Confidential Transactions with range and surjection proofs |
| Every confidential output carries a recovery packet that only 5 of 7 operators together can open | Elements consensus checks every packet's proofs | Hand-written zero-knowledge proofs; see "not built" for review status |
| Every transaction needs an authorization from 5 of 7 operators | Elements consensus | The policy can be re-keyed through DynaFed but never switched off |
| An authorization is usable for at most 20 blocks | Elements consensus | Withholding new authorizations therefore takes effect within 20 blocks |
| A regulator can freeze named outputs: no operator will authorize or confirm a spend of them | Each operator's own service, enforced through the ledger's authorization and block-signing rules | Holds while 3 of 7 operators honor the order. Takes effect from the next block, even for a spend authorized earlier, which every node rejects once its authorization expires. Checked live on the demo chain |
| The operators can move frozen funds into quarantine and then return them to their owner, without the owner's key | Elements consensus: a recovery authorization from 5 of 7 operators, in its own signature domain; a first move may pay only into quarantine, a burn or the fee; a quarantine output can be moved only by another recovery. Each operator signs only what the regulator's signed quarantine or restore order allows | Every output is recoverable this way; there is no opt-out. Once quarantined, a spend the thief signed and had authorized fails on every node. The operators open the hidden amount with their disclosure key. Checked live on the demo chain |
| The operators refuse payments to addresses no member bank registered | Each operator's signing service | Policy in the operators' software, not a ledger rule. The registration shows operators which member bank stands behind each destination, though not the customer or the amount. In the sandbox one simulated bank key signs every registration, for both banks |
| Blocks need signatures from 5 of 7 operators | Elements consensus | Two quorums share at least three operators, so a fork takes three operators signing competing blocks |
| Issuing or destroying tokens needs 5 of 7 operators to co-sign with their own keys | Elements consensus (5-of-7 treasury script) | Each operator's service checks the request before signing |
| Issued amounts are public, so supply can be checked by anyone with the chain | Elements consensus for issuance; burns are public by construction | |
| The federation, including the disclosure key, can be handed to new operators without a new ledger | DynaFed transitions, checked by consensus | |
| A disclosure opens only the payment it names, after 5 of 7 operators approve, and the amount is checked against the chain in the recipient's browser | Guardian services and the browser | Approval is a guarantee of the guardians' software: 7 colluding guardians could decrypt without it |
| A receiving bank's directory answer is signed and the sender's browser verifies it | Browser verification of a Schnorr signature | |

## Simulated: say so if asked

| What the demo shows | What actually runs |
|---|---|
| Seven independent operators | Seven separate signing processes, each with its own keys, on one machine run by one party. All seven check blocks and transactions against **the same single node** |
| A network of nodes | One elementsd with peer-to-peer networking off |
| Seven operators each holding a disclosure key piece | Seven separate key services on the same machine. Their key setup is a simulated ceremony, not a secure distributed key generation |
| Banks: deposits, payouts, reserves | A simulated bank in the application's database |
| Bank-signed directory answers and address registrations | Real signatures, but every bank's key is held by the central application |
| The operators opening a frozen output's amount for a recovery | The settlement server drives the operators' key services with fixture approval credentials; in production each operator's staff would approve |
| The regulator's freeze key being trusted | Each operator's configuration lists it; in production it would come from the operator-signed member directory |
| Customers controlling their money | Customer wallets live in the central node and are signed by the application. The two-person approval is an application login check, not a cryptographic signature by each person |
| Independent reserve evidence | The simulated bank's own numbers |
| Signing in as anyone, the "add the other operators' approvals" shortcut | Demo mode only. The shortcut does ask each operator's real service to sign |

## Not built: do not claim

- **Replacing quarantined funds** (burn them, then issue to the owner): the
  ledger allows the burn; there is no screen or order for it yet.
- **Recovering funds the federation never froze in time:** if a theft confirms
  and moves on before a freeze, each later output has to be traced and frozen.
- **Serial-numbered notes (M1Coin).**
- **Validation by an independent node or an outside observer,** and behavior
  across real network faults.
- **Customer-held keys.**
- **Independent reserve attestation** (a custodian or central bank signing what
  it holds).
- **External review of the consensus cryptography.** The recovery-packet proofs
  are research code that has not been reviewed outside the team.
- **Byzantine fault tolerance in block production.** With 5 of 7, forking the
  chain takes three operators signing competing blocks, and two can be offline.
  But one coordinator still proposes every block; operators proposing in turn,
  with timeouts, is not built (see `review/THREAT-MODEL.md`).
- **Quantum resistance.** Recovery packets are encryptions on secp256k1. Someone
  who records the chain today could decrypt every amount if that curve is ever
  broken. Signatures are secp256k1 as well.
- **Production custody, legal issuer, or real money.** The issuer and liability
  model are undecided.
