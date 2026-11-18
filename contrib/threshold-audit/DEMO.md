# Live demo runbook

A 20-minute walkthrough of the settlement sandbox for a product
or leadership audience. Everything runs locally; bank money is simulated.
Before presenting, read [CLAIMS.md](CLAIMS.md): what is real, what is
simulated, and what is not built.

## One-time setup

```sh
cd contrib/threshold-audit/settlement/ui && npm ci && npm run build && cd -
cd contrib/threshold-audit
python3 -m settlement.demo_seed /path/to/runtimes/demo-core \
  [--mesh-from /path/to/existing-runtime/mesh.json]   # optional Rayfish access
python3 -m settlement.demo_seed /path/to/runtimes/demo-core --snapshot
```

The seed takes several minutes. It creates a fresh chain, turns on demo mode
(one-click persona sign-in, prefilled operator passphrases and the
"add the other operators' approvals" shortcut), funds the
accounts, records some payment history, and pre-stages:

| Pre-staged case | Where it stands |
|---|---|
| €500,000 funding request for Acme | Waiting for the bank to confirm the deposit |
| $75,000 Acme withdrawal | Approved by Acme and 2 of 3 operators |
| Disclosure of Acme's €12,750 payment to Initech | Released to the regulator |

`--snapshot` saves this state. Demo mode lets anyone who can reach the app sign
in as anyone; use it only for a local demo runtime.

## Before each run

1. `python3 -m settlement.demo_seed /path/to/runtimes/demo-core --reset`
   restores the snapshot and starts the demo (about a minute).
2. Open the wallet URL it prints, at 1440×900 or larger.
3. In that browser, sign in as **Regulator · disclosures and freezes**, open
   **Disclosures → Create or import a recipient key**, and import
   `demo-recipient-key.json` from the runtime directory. The password is
   `concord-demo`. The key stays in this browser across resets.
4. Allow pop-ups for the site: operator approvals open their own window.

## Script

On each request, **Switch to …** buttons sign in as the next person who needs
to act and reopen the same request. Use them instead of the header's
**Switch user** to keep the story moving.

The demo runtime uses the policies that match the product: the federation
runs the ledger and controls what enters and leaves it, so payments between
customers need only the customer's own approvals. Funding and withdrawals
still need three operators. Funding finishes on its own once they approve;
a withdrawal waits for a person at the company to release it.

1. **Pay another bank's customer (2 min).** As *Acme · creates payments*,
   choose **Send on-chain → A company, by bank reference**, enter
   `initech-main@bank-b` and an amount, and click **Look up**: the receiving
   bank confirms who the reference belongs to. Create the request, then
   **Switch to Acme Approver** → **Review, approve and send**. It settles in a
   few seconds; optionally switch to *Initech* to show it arrived.

   *Point:* you know who you're paying, a second person at the company checks,
   and it settles in seconds. The ledger sees one transaction with the amount
   and parties hidden, carrying an encrypted record the guardians can open if
   needed.
2. **Money in (2 min).** Switch to *Bank · confirms deposits*, open the
   €500,000 request under **Needs your attention** and confirm the deposit;
   that confirmation is the bank's approval. **Switch to Operator 1** and
   sign in its own approval window, then **Add the other operators'
   approvals**. The tokens are issued within seconds: show Acme's balance.
   *Point:* tokens are created only when three independent operators
   co-sign the issuing transaction, after the bank confirms the money arrived.
   Nobody presses a final Send: the operators' co-signature is the moment
   money is created.
3. **Money out (2 min).** As *Acme · approves payments*, open the $75,000
   withdrawal under **Requests**. Acme and two operators have approved:
   click **Add the other operators' approvals** for the third (step 2
   already showed one signing live), then **Review and send**. The payout and
   token burn finish on their own.
   *Point:* unlike funding, money leaving the bank waits for a person at the
   company to release it, so they control the timing and can still stop it.
4. **Private, but accountable (4 min).** As *Bank compliance*, show the
   Disclosures page: a request names one payment and one recipient, and
   guardians approve it. Switch to *Regulator · disclosures and freezes*, enter the
   key password and open the case. The amount is decrypted in the regulator's
   browser and checked against the chain.
   *Point:* this is how the federation intervenes on suspected fraud: payment
   details are not public, yet a named authority can be shown exactly the
   payments it needs, with a guardian quorum's approval, and it is all logged.
   **Freeze (3 min).** Still as the regulator, in the same case, fill in
   **Freeze these funds** (a reason, and the key password again) and send it.
   **Freeze orders** below shows each operator applying it: "Applied by 5 of 5
   operators". Switch to *Initech*: the €12,750 shows as **Frozen by regulator
   order** and is no longer available to send. Back as the regulator, open
   **Release…** on the order to lift it.
   *Point:* the regulator signs the order in its own browser; each operator
   checks that signature itself, and from the next block no operator will
   authorize or confirm a spend of those funds, even one authorized earlier.
   The freeze stops the funds where they are; moving them back to their owner
   is the next step and is not built yet.
5. **Backing (1 min).** Switch to *Bank · reserves and oversight* and open
   **Reserves**: cash held equals tokens in circulation, per currency.
6. **Optional: who runs it (1 min).** In the same console, **Operators** shows
   the independent operators, what each group approves, and how the network
   hands over to new operators without moving to a new ledger.

7. **The ledger's own rule (4 min).** As *Bank · reserves and oversight*,
   open **Ledger**. Each recent transaction shows what the ledger recorded
   (amounts hidden, sealed recovery records) beside what only the bank knows,
   and which three operators authorized it and confirmed its block.
   - Click **Send without the operators**: a bank wallet signs a valid
     payment, the ledger refuses it, and the same payment with the
     operators' authorization would be accepted.
   - Switch two operators off and make a payment as Acme (any destination).
     It settles in a few seconds; back on **Ledger** it shows the other three
     signing. Switch a third off: the next payment waits ("2 of 5 reachable,
     3 needed") and the block height stops. Switch one back on and the waiting
     payment settles by itself. Turn them all back on.
   - As Acme, **Send on-chain → A wallet address**, click **Demo: use an
     address no bank has registered**, check it, and send. After
     **Review, approve and send** it closes as **Declined by the
     operators**, and the balance is unchanged.

   *Point:* the federation's control is a rule of the ledger. Every node
   enforces it, no bank or operator can go around it, two operators can be
   down without stopping payments, and the operators refuse payments to
   addresses no member bank stands behind, without seeing amounts.

   *Caveats if asked:* this sandbox runs a single node, and one party runs
   every operator's service on one machine, so "every node" is one node
   today. The simulated bank's registration key runs inside the coordinator;
   in production each bank holds its own.

## What the ledger enforces

| | Enforced by the Elements ledger | Enforced by the application |
|---|---|---|
| **Every transaction** | An authorization signed by 3 of 5 operators and usable for at most 20 blocks; their services give it automatically, see only what the chain shows, and require each destination to be a bank-registered address | Nothing further |
| **Payments between customers** | The sender's wallet signature (the wallet is held in the node and signed by the application, not by the customer), hidden amounts and assets with valid proofs, the mandatory recovery packet for disclosure, and 3 of 5 operators confirming the block | The customer's second-person check; operator approval only if the payment policy asks for it |
| **Money in and out** (issuing tokens, the withdrawal payout and burn, refunds) | All of the above, **plus** 3 of 5 operators co-signing the transaction with their own keys; each operator's service checks the approval before signing | Funding: the bank's confirmation that the money arrived. Withdrawals: the company's second-person check and release |
| **Disclosures** | The encrypted recovery packet on every payment; only 7 of 10 guardians together can open it | Who may request a disclosure and for whom |

The payment policy is the runtime setting `transfer_institution_approval`:
`"always"` (the default outside the demo), `"never"` (the demo), or
`{"above_minor": N}` to require operator approval only for payments above
N minor units (for example `{"above_minor": 100000000}` for over €1,000,000).

Funding follows `deposit_issuance`: `"manual"` (the default outside the demo)
needs a separate bank approver to approve and send; `"automatic"` (the demo)
counts the bank's deposit confirmation as its approval and issues the tokens
once the operators approve. If the person confirming the deposit also
created the request, a second bank person must still approve. If issuing
cannot start (for example, the wallet does not reconcile), the request shows
why and an approver can issue it by hand.

Intervention means disclosure and freezing. A freeze stops the named funds
where they are, from the next block, including a spend someone had already
authorized. Moving frozen funds back to their owner is not built yet, and
nothing reverses a payment that has confirmed. The simulated bank can hold
issuance and payouts.

The **Add the other operators' approvals** shortcut is demo-only. It asks
each remaining operator's own approval service to sign, exactly as its
window would, so the recorded approvals are real.

## Likely questions

- **"The bank can see these amounts. Isn't it confidential?"** Participants see
  their own and their customers' payments. Confidentiality is against everyone
  else: the shared ledger shows no amounts or parties. Disclosure is how an
  outside authority gets a specific payment's details.
- **"Who are the operators, members and guardians?"** Operators are the
  independent organizations that run the network: three of five confirm
  every block, authorize every transaction and co-sign every token issued or
  destroyed. Members are the banks that serve customers on the network; they
  run their own node but sign nothing for the network. A bank can be both,
  with separate keys for each role. Guardians are a separate 7-of-10 quorum
  that controls disclosures. Everyday payments are authorized automatically;
  nobody at an operator reviews them by hand. In the sandbox all of them are
  simulated on one machine.
- **"What if an operator goes down, or refuses?"** Any two can be offline
  and everything continues. With three down nothing moves, by design, and it
  resumes on its own when one returns. A refusal by enough of them closes the
  payment; nobody can push it through.
- **"Is this real money?"** No. Banks, reserves and payouts are simulated, and
  the legal issuer is undecided.
