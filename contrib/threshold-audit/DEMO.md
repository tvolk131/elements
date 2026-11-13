# Live demo runbook

A 15-minute walkthrough of the institutional settlement sandbox for a product
or leadership audience. Everything runs locally; bank money is simulated.

## One-time setup

```sh
cd contrib/threshold-audit/settlement/ui && npm ci && npm run build && cd -
cd contrib/threshold-audit
python3 -m settlement.demo_seed /path/to/runtimes/demo-core \
  [--mesh-from /path/to/existing-runtime/mesh.json]   # optional Rayfish access
python3 -m settlement.demo_seed /path/to/runtimes/demo-core --snapshot
```

The seed takes several minutes. It creates a fresh chain, turns on demo mode
(one-click persona sign-in, prefilled institution passphrases and the
"add the other institutions' approvals" shortcut), funds the
accounts, records some payment history, and pre-stages:

| Pre-staged case | Where it stands |
|---|---|
| €500,000 funding request for Acme | Waiting for the bank to confirm the deposit |
| $75,000 Acme withdrawal | Approved by Acme and 2 of 3 institutions |
| Disclosure of Acme's €12,750 payment to Initech | Released to the regulator |

`--snapshot` saves this state. Demo mode lets anyone who can reach the app sign
in as anyone; use it only for a local demo runtime.

## Before each run

1. `python3 -m settlement.demo_seed /path/to/runtimes/demo-core --reset`
   restores the snapshot and starts the demo (about a minute).
2. Open the wallet URL it prints, at 1440×900 or larger.
3. In that browser, sign in as **Regulator · opens disclosures**, open
   **Disclosures → Create or import a recipient key**, and import
   `demo-recipient-key.json` from the runtime directory. The password is
   `concord-demo`. The key stays in this browser across resets.
4. Allow pop-ups for the site: institution approvals open their own window.

## Script

On each request, **Switch to …** buttons sign in as the next person who needs
to act and reopen the same request. Use them instead of the header's
**Switch user** to keep the story moving. Every request follows the same
pattern: one institution signs live in its own window, **Add the other
institutions' approvals** collects the rest, and the second person's
**Approve and send** finishes it.

1. **Pay another bank's customer (4 min).** As *Acme · creates payments*,
   choose **Send on-chain → A company, by bank reference**, enter
   `initech-main@bank-b` and an amount, and click **Look up**: the receiving
   bank confirms who the reference belongs to. Create the request, then:
   - **Switch to Institution 1** and sign in its approval window.
   - **Add the other institutions' approvals** (3 of 3).
   - **Switch to Acme Approver** → **Review, approve and send**. It settles in
     a few seconds; optionally switch to *Initech* to show it arrived.

   *Point:* you know who you're paying, a second person checks, and
   independent institutions sign off. The ledger only ever sees one
   transaction, with the amount and parties hidden.
2. **Money in (3 min).** Switch to *Bank · records bank credits*, open the
   €500,000 request under **Needs your attention** and confirm the deposit.
   Then the same pattern: Institution 1 signs, add the others, Bank Approver
   approves and sends. Show Acme's balance.
   *Point:* tokens are created only when three independent institutions
   co-sign the issuing transaction, after the bank confirms the money arrived.
3. **Money out (2 min).** Open the $75,000 withdrawal (Acme, Requests). Acme
   and two institutions have approved: switch to Institution 3, sign, then
   switch to the approver and send. The payout and token burn finish on their
   own.
4. **Private, but accountable (4 min).** As *Bank compliance*, show the
   Disclosures page: a request names one payment and one recipient, and
   guardians approve it. Switch to *Regulator · opens disclosures*, enter the
   key password and open the case. The amount is decrypted in the regulator's
   browser and checked against the chain.
   *Point:* payment details are not public, yet a named authority can be given
   exactly one payment's details with a quorum's approval, and it is all logged.
5. **Backing (1 min).** Switch to *Bank · reserves and oversight* and open
   **Reserves**: cash held equals tokens in circulation, per currency.
6. **Optional: who runs it (1 min).** In the same console, **Operators** shows
   the independent institutions, what each group approves, and how the network
   hands over to new operators without moving to a new ledger.

## What the ledger enforces

Keep claims accurate if someone asks "what stops the operator from skipping
that?":

| | Enforced by the Elements ledger | Enforced by the application |
|---|---|---|
| **Payments between customers** | The sender's wallet signature, hidden amounts and assets with valid proofs, the mandatory recovery packet for disclosure, and 3 of 5 operators confirming the block | Second-person check and the three institution approvals |
| **Money in and out** (issuing tokens, the withdrawal payout and burn, refunds) | All of the above, **plus** 3 of 5 institutions co-signing the transaction with their own keys; each institution's service checks the approval before signing | Second-person check |
| **Disclosures** | The encrypted recovery packet on every payment; only 7 of 10 guardians together can open it | Who may request a disclosure and for whom |

So "three independent institutions must sign" is literally true for money
entering and leaving the system. For payments between customers it is a
policy the settlement service enforces; making it a ledger rule would mean
holding customer funds under institution co-signing.

The **Add the other institutions' approvals** shortcut is demo-only. It asks
each remaining institution's own approval service to sign, exactly as its
window would, so the recorded approvals are real.

## Likely questions

- **"The bank can see these amounts. Isn't it confidential?"** Participants see
  their own and their customers' payments. Confidentiality is against everyone
  else: the shared ledger shows no amounts or parties. Disclosure is how an
  outside authority gets a specific payment's details.
- **"Who are the institutions and guardians?"** Independent organizations
  that co-operate the network. Three of five approve each settlement and
  co-sign every token issued or destroyed; a separate 7-of-10 quorum controls
  disclosures.
- **"Is this real money?"** No. Banks, reserves and payouts are simulated, and
  the legal issuer is undecided.
