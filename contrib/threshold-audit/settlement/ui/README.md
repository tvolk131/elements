# Concord web application

React and TypeScript, TanStack Router, and TanStack Query power the wallet and
guardian interfaces. Vite builds a static single-page app into `dist/`. The
Python settlement server serves those files and the `/api` endpoints from one
loopback origin. Python, the Elements daemon, and the independent
institution/guardian services keep transaction execution and key custody.

## Build and run

Use Node.js 22.12 or newer (Node 24 LTS is used for local verification):

```sh
cd contrib/threshold-audit/settlement/ui
npm ci
npm test
npm run build
```

Then start the selected demo from the repository root:

```sh
python3 contrib/threshold-audit/manage.py start
```

The server reads `dist/` on each request, so a rebuild takes effect on the next
page load without restarting the demo. Build artifacts and installed packages
are ignored by Git and must be recreated in a fresh checkout.

The `/wallet` and `/guardian` entry points and Rayfish URLs are unchanged.
Navigation uses paths such as `/wallet/payments` and `/guardian/federation`;
the server returns the app for those paths and old hash bookmarks are
redirected in the browser.

## Boundaries

- The settlement server binds only loopback, rejects unrecognized Host/Origin
  and cross-site requests, bounds request bodies, and serves only `index.html`
  for app routes and files under `dist/assets/`. The CSP allows only same-origin
  scripts. The mesh gateway remains the private Rayfish entry point and keeps
  independent institution origins separate.
- Authenticated sessions use an HttpOnly, SameSite=Strict cookie plus a CSRF
  header on every POST. Role checks, approval policy and durable financial
  state stay in Python.
- Query caches are kept in browser memory, scoped by identity, and cleared on
  logout or session expiry. Financial mutations have no automatic
  retry or optimistic balance updates.
- Institution approval passphrases stay in the independent institution windows.
  The callback checks the popup, origin, request ID and institution identity
  before sending a certificate to the engine for verification.

The capability demo adds signed bank-reference routing, confidential-address
sending/receiving, and a disclosure workspace. It retains the existing payment
approval policy. See [the walkthrough](../../SETTLEMENT-SANDBOX.md#recipient-directed-disclosure-and-cross-bank-demo).

Recipient keys are generated and password-encrypted locally using pinned Noble
libraries. The browser registers only the public key. Encrypted key backups are
kept in local browser storage under the signed-in user ID and can be exported or
imported. The disclosure relay sees encrypted guardian contributions; the recipient
browser verifies signatures, DLEQ proofs and recovered commitment openings before
displaying results. This browser client trusts the demo node for chain inclusion
and committee authenticity. The native recipient CLI can independently verify
those against a separately supplied node. A compromised application can serve
malicious JavaScript; this demo is not an isolated trusted client or hardware key
custody system.

## Tests

`npm test` covers user/session transitions, account and currency filtering,
request payloads, stale address and beneficiary checks, recipient key/password
isolation, native-to-browser recovery, Python-compatible canonical JSON, CSRF,
cache isolation and CSV escaping. The Python web test serves a temporary build
to check deep links, asset confinement, CSP, cookies, CSRF and logout:

```sh
cd contrib/threshold-audit && python3 -m unittest settlement.test_web
```

No test issues money or contacts a real bank.

## Visual review coverage

Inspect each changed component at reading size, including the sidebar,
wrapping headings, icons, and supporting text. Whole-page screenshots alone do
not establish that these details were checked. Check wallet and guardian variants
at 1440, 1280, and 1024px widths, a short desktop window, and the mobile breakpoint.
Record the inspected states and unresolved findings before reporting a visual pass.
