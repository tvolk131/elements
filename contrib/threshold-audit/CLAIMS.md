# What the demo shows: real, simulated, not built

One page for anyone presenting or describing the settlement sandbox. If a sentence in a deck or a conversation goes beyond the **Real**
column, it needs one of the qualifiers below. Keep this page current with the
branch; it is the reference when the code and a slide disagree.

Terms: **operators** run the network (they sign blocks, authorize every
transaction and co-sign issuance); **members** are the banks that serve
customers on it; **guardians** hold the disclosure key. Code, configuration
and login IDs still say `institution` for operators.

## Real: running code, enforced where stated

| Claim | Enforced by | Notes |
|---|---|---|
| Payment amounts and assets are hidden on the ledger | Elements consensus | Confidential Transactions with range and surjection proofs |
| Every confidential output carries a recovery packet that only 7 of 10 guardians together can open | Elements consensus checks every packet's proofs | Hand-written zero-knowledge proofs; see "not built" for review status |
| Every transaction needs an authorization from 3 of 5 operators | Elements consensus | The policy can be re-keyed through DynaFed but never switched off |
| An authorization is usable for at most 20 blocks | Elements consensus | Withholding new authorizations therefore takes effect within 20 blocks |
| The operators refuse payments to addresses no member bank registered | Each operator's signing service | Policy in the operators' software, not a ledger rule |
| Blocks need signatures from 3 of 5 operators | Elements consensus | |
| Issuing or destroying tokens needs 3 of 5 operators to co-sign with their own keys | Elements consensus (3-of-5 treasury script) | Each operator's service checks the request before signing |
| Issued amounts are public, so supply can be checked by anyone with the chain | Elements consensus for issuance; burns are public by construction | |
| The federation can be handed to new operators and new guardians without a new ledger | DynaFed transitions, checked by consensus | |
| A disclosure opens only the payment it names, after guardian approval, and the amount is checked against the chain in the recipient's browser | Guardian services and the browser | Approval is a guarantee of the guardians' software: 7 colluding guardians could decrypt without it |
| A receiving bank's directory answer is signed and the sender's browser verifies it | Browser verification of a Schnorr signature | |

## Simulated: say so if asked

| What the demo shows | What actually runs |
|---|---|
| Five independent operators | Five separate signing processes, each with its own keys, on one machine run by one party. All five check blocks and transactions against **the same single node** |
| A network of nodes | One elementsd with peer-to-peer networking off |
| Ten independent guardians | Ten separate processes on the same machine. Their key setup is a simulated ceremony, not a secure distributed key generation |
| Banks: deposits, payouts, reserves | A simulated bank in the application's database |
| Bank-signed directory answers and address registrations | Real signatures, but every bank's key is held by the central application |
| Customers controlling their money | Customer wallets live in the central node and are signed by the application. The two-person approval is an application login check, not a cryptographic signature by each person |
| Independent reserve evidence | The simulated bank's own numbers |
| Signing in as anyone, the "add the other operators' approvals" shortcut | Demo mode only. The shortcut does ask each operator's real service to sign |

## Not built: do not claim

- **Freezing specific funds.** The lever exists: operators can refuse to
  authorize spends of chosen outputs, and consensus now caps how long an earlier
  authorization stays usable. No freeze order, freeze list or case workflow is
  implemented yet.
- **Reversing or recovering stolen funds,** and serial-numbered notes (M1Coin).
- **Validation by an independent node or an outside observer,** and behavior
  across real network faults.
- **Customer-held keys.**
- **Independent reserve attestation** (a custodian or central bank signing what
  it holds).
- **External review of the consensus cryptography.** The recovery-packet proofs
  are research code that has not been reviewed outside the team.
- **Byzantine fault tolerance.** Any two 3-of-5 signing quorums share one member,
  so a single operator that signs two competing blocks can fork the chain
  (see `review/THREAT-MODEL.md`). The demo tolerates two operators being
  offline; it does not defend against a dishonest one.
- **Quantum resistance.** Recovery packets are encryptions on secp256k1. Someone
  who records the chain today could decrypt every amount if that curve is ever
  broken. Signatures are secp256k1 as well.
- **Production custody, legal issuer, or real money.** The issuer and liability
  model are undecided.
