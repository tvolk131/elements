# Concord web application

React and TypeScript, TanStack Start/Router, and TanStack Query power the wallet
and guardian interfaces. Vite builds the browser and Node server bundles. The
Python settlement engine, Elements daemon, and independent institution/guardian
services retain transaction execution and key custody.

## Build and run

Use Node.js 22.12 or newer (Node 24 LTS is used for local verification):

```sh
cd contrib/threshold-audit/settlement/ui
npm ci
npm test
npm run build
```

From the repository root, start the selected existing demo normally:

```sh
ELEMENTS_UI_NODE=/absolute/path/to/node python3 contrib/threshold-audit/manage.py start
```

`ELEMENTS_UI_NODE` is optional when Node is on PATH. The launcher remembers its
resolved executable in the runtime's private `start-web.json`; later resumes can
use the manager without the environment variable. Build artifacts and installed
packages are ignored by Git and must be recreated in a fresh checkout.

`manage.py` owns the Node web process along with the settlement engine and its
other services. The launcher snapshots each build into ignored `.releases/<digest>` directories,
so rebuilding cannot replace assets used by a running server. Stop/start after
rebuilding to switch to the new release; stop before changing installed
dependency versions. The existing
`/wallet` and `/guardian` entry points and Rayfish URLs are preserved. Navigation
now uses paths such as `/wallet/payments` and `/guardian/federation`; old hash
bookmarks are redirected in the browser. Deep links are served by Start.

## Boundaries

- Start's server route `src/routes/api.$.ts` exposes an explicit set of existing
  settlement endpoints. Its server-only adapter forwards to one configured
  loopback engine, preserving session cookies and CSRF. Authenticated sessions,
  role checks, approval policy and durable financial state remain in Python.
- The engine listens on a separate loopback port and requires a random gateway
  token. The private engine serves no HTML. The token and engine configuration
  are never included in the browser bundle.
- The Node adapter binds only 127.0.0.1, rejects unrecognized Host/Origin and
  cross-site requests, bounds request bodies, and issues a per-response CSP nonce
  for Start's bootstrap scripts. The existing mesh gateway remains the private
  Rayfish entry point and keeps independent institution origins separate.
- Query caches are kept in browser memory, scoped by identity, and cleared on
  logout or session expiry. Authenticated data is fetched in the browser and is
  not embedded into Start's initial HTML. Financial mutations have no automatic
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
request payloads, recipient key/password isolation, native-to-browser recovery, CSRF, cache isolation, CSV escaping,
and the Node Host/Origin/CSP boundary. The Python suite starts a real built Start
server against a disposable engine to check cookies, CSRF, logout, deep links,
CSP nonces, and private-engine isolation:

```sh
ELEMENTS_UI_NODE=/absolute/path/to/node PYTHONPATH=contrib/threshold-audit \
  python3 -m unittest settlement.test_web
```

No test issues money or contacts a real bank. Running the built web server by
itself requires a launcher-generated private configuration; it is normally
started through `manage.py`, not as an extra development server.

## Visual review coverage

Inspect each changed component at reading size, including the sidebar/footer,
wrapping headings, icons, and supporting text. Whole-page screenshots alone do
not establish that these details were checked. Check wallet and guardian variants
at 1440, 1280, and 1024px widths, a short desktop window, and the mobile breakpoint.
Record the inspected states and unresolved findings before reporting a visual pass.
