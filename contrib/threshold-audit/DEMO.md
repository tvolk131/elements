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
(one-click persona sign-in and prefilled institution passphrases), funds the
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

1. **Money in (3 min).** Sign in as *Bank · records bank credits*. Open the
   €500,000 request under **Needs your attention** and confirm the deposit.
   Use the **Switch to** buttons to approve as Bank Approver, sign as three
   institutions (each signs in its own window), then send. Show Acme's balance.
   *Point:* tokens exist only after the bank confirms the money arrived and
   independent institutions agree.
2. **Pay another bank's customer (4 min).** As *Acme · creates payments*,
   choose **Send on-chain → A company, by bank reference** and enter
   `initech-main@bank-b`. The receiving bank confirms who the reference belongs
   to before anything is sent. Create the payment and walk it through the
   approval panel: second person, three institutions, send.
   *Point:* maker-checker controls plus independent sign-off, and you know who
   you're paying.
3. **Money out (2 min).** Open the $75,000 withdrawal (Acme, Requests). One
   institution is still missing: switch to it, sign, then send. The payout and
   token burn complete on their own.
4. **Private, but accountable (4 min).** As *Bank compliance*, show the
   Disclosures page: a request names one payment and one recipient, and
   guardians approve it. Switch to *Regulator · opens disclosures*, enter the
   key password and open the case. The amount is decrypted in the regulator's
   browser and checked against the chain.
   *Point:* payment details are not public, yet a named authority can be given
   exactly one payment's details with a quorum's approval, and it is all logged.
5. **Backing (1 min).** Switch to *Bank · reserves and oversight* and open
   **Reserves**: cash held equals tokens in circulation, per currency.

## Likely questions

- **"The bank can see these amounts. Isn't it confidential?"** Participants see
  their own and their customers' payments. Confidentiality is against everyone
  else: the shared ledger shows no amounts or parties. Disclosure is how an
  outside authority gets a specific payment's details.
- **"Who are the institutions and guardians?"** Independent organizations
  that co-operate the network. Three of five must approve each settlement; a
  separate quorum controls disclosures.
- **"Is this real money?"** No. Banks, reserves and payouts are simulated, and
  the legal issuer is undecided.
