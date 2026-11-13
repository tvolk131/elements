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
**Switch user** to keep the story moving.

The demo runtime uses the payment policy that matches the product: the
federation runs the ledger and controls what enters and leaves it, so
payments between customers need only the customer's own approvals. Funding
and withdrawals still need three institutions.

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
2. **Money in (3 min).** Switch to *Bank · records bank credits*, open the
   €500,000 request under **Needs your attention** and confirm the deposit.
   **Switch to Institution 1** and sign in its own approval window, then
   **Add the other institutions' approvals**. Switch to *Bank Approver* →
   **Review, approve and send**. Show Acme's balance.
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
   *Point:* this is how the federation intervenes on suspected fraud: payment
   details are not public, yet a named authority can be shown exactly the
   payments it needs, with a guardian quorum's approval, and it is all logged.
5. **Backing (1 min).** Switch to *Bank · reserves and oversight* and open
   **Reserves**: cash held equals tokens in circulation, per currency.
6. **Optional: who runs it (1 min).** In the same console, **Operators** shows
   the independent institutions, what each group approves, and how the network
   hands over to new operators without moving to a new ledger.

## What the ledger enforces

| | Enforced by the Elements ledger | Enforced by the application |
|---|---|---|
| **Payments between customers** | The sender's wallet signature, hidden amounts and assets with valid proofs, the mandatory recovery packet for disclosure, and 3 of 5 operators confirming the block | The customer's second-person check; institution approval only if the payment policy asks for it |
| **Money in and out** (issuing tokens, the withdrawal payout and burn, refunds) | All of the above, **plus** 3 of 5 institutions co-signing the transaction with their own keys; each institution's service checks the approval before signing | Second-person check |
| **Disclosures** | The encrypted recovery packet on every payment; only 7 of 10 guardians together can open it | Who may request a disclosure and for whom |

The payment policy is the runtime setting `transfer_institution_approval`:
`"always"` (the default outside the demo), `"never"` (the demo), or
`{"above_minor": N}` to require institution approval only for payments above
N minor units (for example `{"above_minor": 100000000}` for over €1,000,000).

Intervention today means disclosure. The federation cannot freeze or reverse
a payment between customers, because those are signed with the customer's
own key; the simulated bank can freeze issuance and payouts.

The **Add the other institutions' approvals** shortcut is demo-only. It asks
each remaining institution's own approval service to sign, exactly as its
window would, so the recorded approvals are real.

## Likely questions

- **"The bank can see these amounts. Isn't it confidential?"** Participants see
  their own and their customers' payments. Confidentiality is against everyone
  else: the shared ledger shows no amounts or parties. Disclosure is how an
  outside authority gets a specific payment's details.
- **"Who are the institutions and guardians?"** Independent organizations
  that run the network: three of five confirm every block and co-sign every
  token issued or destroyed, and a separate 7-of-10 quorum controls
  disclosures. They don't approve everyday payments between customers.
- **"Is this real money?"** No. Banks, reserves and payouts are simulated, and
  the legal issuer is undecided.
