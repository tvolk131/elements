# Live demo runbook

A 25-minute walkthrough of the settlement sandbox for a product
or leadership audience: first the recovery test, then how the network runs. Everything runs locally; bank money is simulated.
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

The seed takes several minutes. It creates a fresh chain and an independent
node that keeps its own copy of it, turns on demo mode
(one-click persona sign-in, prefilled operator passphrases and the
"add the other operators' approvals" shortcut), funds the
accounts, records some payment history, and pre-stages:

| Pre-staged case | Where it stands |
|---|---|
| €500,000 funding request for Acme | Waiting for the bank to confirm the deposit |
| $75,000 Acme withdrawal | Approved by Acme and 4 of 7 operators |
| Disclosure of Acme's €12,750 payment to Initech | Released to the regulator; the recovery test steals and recovers this payment |

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
still need five operators. Funding finishes on its own once they approve;
a withdrawal waits for a person at the company to release it.

### Part 1: the recovery test (15 min)

This follows the partner deck's recovery test: mint against a bank
confirmation, send, steal a signed spend, trace and freeze, replay the same
bytes on an independent node, restore. It runs on UNITED EUR; there is no
serial-numbered note.

1. **Money in (2 min).** Switch to *Bank · confirms deposits*, open the
   €500,000 request under **Needs your attention** and confirm the deposit;
   that confirmation is the bank's approval. **Switch to Operator 1** and
   sign in its own approval window, then **Add the other operators'
   approvals**. The tokens are issued within seconds: show Acme's balance.
   *Point:* tokens are created only when five independent operators
   co-sign the issuing transaction, after the bank confirms the money arrived.
2. **Send (2 min).** As *Acme · creates payments*, choose
   **Send on-chain → A company, by bank reference**, enter
   `initech-main@bank-b` and an amount, and click **Look up**: the receiving
   bank confirms who the reference belongs to. Create the request, then
   **Switch to Acme Approver** → **Review, approve and send**. It settles in a
   few seconds. Switch to *Initech*: it arrived, beside the €12,750 Acme paid
   earlier. The rest of the test uses that earlier payment, because the
   regulator already has a disclosure case for it.
   *Point:* you know who you're paying, a second person at the company checks,
   and it settles in seconds. The ledger sees one transaction with the amount
   and parties hidden.
3. **Steal a signed spend (1 min).** Switch to *Bank · reserves and
   oversight* and open **Ledger**. Under **Theft drill**, keep
   *Initech · Operating · 12,750.00 UNITED EUR · regulator has a case* and
   click **Steal it with the customer’s key**. The drill plays a thief who
   has Initech's key: it signs a payment of the €12,750 to an account the
   thief opened at another member bank, and the operators authorize it. The
   **Independent node** panel shows a second node with its own copy of the
   ledger; it says it would accept these bytes.
   *Point:* the operators can't tell this from a real payment. The signature
   is valid and the destination is a registered account at a member bank.
   Note the authorization's expiry block: about a minute away.
4. **Trace and freeze (3 min).** Switch to *Regulator · disclosures and
   freezes*, enter the key password and open the case. The amount is
   decrypted in the regulator's browser and checked against the chain. Fill
   in **Freeze these funds** (a reason, and the key password again) and send
   it. **Freeze orders** shows each operator applying it: "Applied by 7 of 7".
   *Point:* payment details are not public, yet a named authority sees exactly
   the payment it needs, with five operators approving. The regulator signs
   the freeze in its own browser and each operator checks that signature
   itself.
5. **The thief broadcasts (1 min).** Back on **Ledger** as the bank, click
   **Broadcast as the thief** (it stays disabled until the freeze is in
   place). What happens depends on how long the freeze took, and both are
   real:
   - within the authorization's minute, the demo node takes the bytes into
     its waiting pool, but no operator will sign a block containing them, so
     they never confirm and drop out when the authorization lapses;
   - after it, the node refuses them as expired, and the operators refuse
     the thief's request for a fresh authorization because the funds are
     frozen.
6. **Quarantine (2 min).** As the regulator, on the freeze, open
   **Quarantine…**, give a reason and the key password, and send it. Within
   a minute the card reads **Quarantined**: the operators opened the hidden
   amount with their disclosure key and moved the funds into quarantine,
   without Initech's key. On **Ledger**, the drill's quarantine step turns
   green, and the transaction list shows it as a recovery that moves funds
   into quarantine. Optionally switch to *Initech*: its history shows
   "Moved to quarantine · Financial Regulator order", naming the authority,
   case and order, and its balance still matches the chain.
7. **Replay the same bytes on the independent node (1 min).** On **Ledger**,
   click **Submit to the independent node**. It rejects them: the output they
   spend no longer exists on its own copy of the ledger, spent by the
   quarantine.
   *Point:* this is not the demo's own say-so. A node that checks every block
   itself turns down the thief's signed, once-authorized transaction for good.
8. **Restore (2 min).** As the regulator, open **Restore…**, enter
   `initech-main@bank-b`, a reason and the password. The funds return to a
   fresh Initech address and show in its history as "Returned from
   quarantine · Financial Regulator order"; Initech's balance is back and
   still matches the chain.
   *Point:* recovery is a rule of the ledger. Five of seven operators must
   sign it, the first move can only go into quarantine, and a regulator's
   signed order decides each step.

To run the test again, reset the runtime: the restored funds sit in a new
output that no disclosure case covers. **Start over** on the drill clears
only the drill.

### Part 2: how it runs (10 min)

1. **Money out (2 min).** As *Acme · approves payments*, open the $75,000
   withdrawal under **Requests**. Acme and four operators have approved:
   click **Add the other operators' approvals** for the fifth (Part 1
   already showed one signing live), then **Review and send**. The payout and
   token burn finish on their own.
   *Point:* unlike funding, money leaving the bank waits for a person at the
   company to release it, so they control the timing and can still stop it.
2. **The ledger's own rule (4 min).** As *Bank · reserves and oversight*, on
   **Ledger**: each recent transaction shows what the ledger recorded
   (amounts hidden, sealed recovery records) beside what only the bank knows,
   and which operators authorized it and confirmed its block.
   - Click **Send without the operators**: a bank wallet signs a valid
     payment, the ledger refuses it, and the same payment with the
     operators' authorization would be accepted.
   - Switch two operators off and make a payment as Acme (any destination).
     It settles in a few seconds; back on **Ledger** it shows the other five
     signing. Switch a third off: the next payment waits ("4 of 7 reachable,
     5 needed") and the block height stops on both nodes. Switch one back on
     and the waiting payment settles by itself. Turn them all back on.
   - As Acme, **Send on-chain → A wallet address**, click **Demo: use an
     address no bank has registered**, check it, and send. After
     **Review, approve and send** it closes as **Declined by the
     operators**, and the balance is unchanged.

   *Point:* the federation's control is a rule of the ledger. Every node
   enforces it, including the independent one; no bank or operator can go
   around it, two operators can be down without stopping payments, and the
   operators refuse payments to addresses no member bank stands behind,
   without seeing amounts.
3. **Backing (1 min).** In the same console, open **Reserves**: cash held
   equals tokens in circulation, per currency.
4. **Optional: who runs it (1 min).** **Operators** shows the independent
   operators, what each group approves, and how the network hands over to
   new operators without moving to a new ledger.

*Caveats if asked:* both nodes run on one machine, run by one party, and every
operator's service checks against the demo node, not a node of its own. The
thief is simulated by the drill. The simulated bank's registration key runs
inside the coordinator; in production each bank holds its own.

## What the ledger enforces

| | Enforced by the Elements ledger | Enforced by the application |
|---|---|---|
| **Every transaction** | An authorization signed by 5 of 7 operators and usable for at most 20 blocks; their services give it automatically, see only what the chain shows, and require each destination to be a bank-registered address | Nothing further |
| **Payments between customers** | The sender's wallet signature (the wallet is held in the node and signed by the application, not by the customer), hidden amounts and assets with valid proofs, the mandatory recovery packet for disclosure, and 5 of 7 operators confirming the block | The customer's second-person check; operator approval only if the payment policy asks for it |
| **Money in and out** (issuing tokens, the withdrawal payout and burn, refunds) | All of the above, **plus** 5 of 7 operators co-signing the transaction with their own keys; each operator's service checks the approval before signing | Funding: the bank's confirmation that the money arrived. Withdrawals: the company's second-person check and release |
| **Disclosures** | The encrypted recovery packet on every payment; only 5 of 7 operators together can open it | Who may request a disclosure and for whom |

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

Intervention means disclosure, freezing and recovery. A freeze stops the named
funds where they are, from the next block, including a spend someone had
already authorized. A quarantine then moves them, without the holder's key,
where only another recovery can move them, and a restore returns them. Funds
that moved on before a freeze must be traced and frozen where they went. The simulated bank can hold
issuance and payouts.

The **Add the other operators' approvals** shortcut is demo-only. It asks
each remaining operator's own approval service to sign, exactly as its
window would, so the recorded approvals are real.

## Likely questions

- **"The bank can see these amounts. Isn't it confidential?"** Participants see
  their own and their customers' payments. Confidentiality is against everyone
  else: the shared ledger shows no amounts or parties. Disclosure is how an
  outside authority gets a specific payment's details.
- **"Who are the operators and members?"** Operators are the independent
  organizations that run the network: five of seven confirm every block,
  authorize every transaction, co-sign every token issued or destroyed, and
  together can open a specific payment for an approved case. No single
  operator can do any of these alone. Members are the banks that serve
  customers on the network; they run their own node but sign nothing for the
  network. A bank can be both, with separate keys for each role. Everyday payments are authorized automatically;
  nobody at an operator reviews them by hand. In the sandbox all of them are
  simulated on one machine.
- **"What if an operator goes down, or refuses?"** Any two can be offline
  and everything continues. With three down nothing moves, by design, and it
  resumes on its own when one returns. A refusal by enough of them closes the
  payment; nobody can push it through.
- **"What does the independent node prove?"** It is a second Elements node
  with its own copy of the ledger. It receives blocks over the network and
  checks every rule itself: block signatures, the operators' authorizations,
  the proofs for hidden amounts. It has no wallet and no keys, so its verdict
  on the thief's bytes is the ledger's rule, not the demo's say-so. Here it
  runs on the same machine; anyone can run one from a clean checkout.
- **"Why quarantine instead of just freezing?"** A freeze has to be honored
  by the operators for as long as it lasts. A quarantine settles it on the
  ledger: the coin the thief signed for no longer exists, so every node
  rejects those bytes forever, and nothing has to be remembered.
- **"Is this real money?"** No. Banks, reserves and payouts are simulated, and
  the legal issuer is undecided.
