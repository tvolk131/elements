# Isolated guardian and disclosure experiment

`guardian_service.py` runs a separate process for each institution. Its private
state contains only that institution's shares, locally generated dealer
coefficients and private evaluations addressed to it. The public coordinator in
`guardian_client.py` receives commitments, signed readiness and acknowledgements;
it never receives a quorum of secret shares or private handoff evaluations.

This is a **distributed research execution of the existing Feldman procedure**,
not an actively secure DKG or dynamic proactive secret-sharing implementation.
Transport encryption alone does not supply reliable broadcast, dealer
qualification, complaint resolution, corruption-threshold guarantees or secure
erasure. Python secret arithmetic remains unsuitable for production keys.

## Run

Build the shared library as described in [README.md](README.md). OpenSSL's
command-line tool is needed to create ephemeral test TLS certificates; the
service uses Python's standard-library TLS and HTTPS implementations.

```sh
env THRESHOLD_AUDIT_SECP256K1=/tmp/elements-audit-secp/lib/libsecp256k1.so \
  python3 -m unittest discover -s contrib/threshold-audit \
  -p test_guardian_services.py -v
```

Run `-p 'test_guardian*.py'` to include the process-startup and service-runtime
regressions. Guardian startup has a total 60-second deadline by default, including
collection of a complete startup line; it cannot hang on partial stdout. Failed
starts terminate their own child and retain mode-0600 stderr diagnostics under
`/tmp/elements-guardian-startup-failure-*`, outside the fixture's temporary data
directory. These files contain startup diagnostics rather than private state or
TLS credentials. Failed fixture requests also retain exception classes and source
locations under `/tmp/elements-guardian-request-failure-*`; they do not retain
request bodies, exception text or private state. The coordinator allows 180
seconds for batch delivery, 60 seconds for ordinary network operations and two
seconds for shutdown before its termination fallback.

The tests start up to 25 guardian processes on ephemeral loopback HTTPS ports,
then stop all processes they created. Test certificates and private state live
in temporary directories. No external peers, Bitcoin nodes or customer keys
are used.

The full historical-recovery test performs distributed 7-of-10 initial key
generation, a fresh audit-key rollover, and a handoff of **both historical keys**
to 11-of-15 guardians. It stops every outgoing guardian and recovers outputs
from both key eras using incoming guardians only, then restarts incoming
guardians and recovers the oldest output again.

Additional checks cover missing readiness for a historical-only key, incomplete
private evaluations, wrong evaluations from an authenticated dealer, session
rebinding, wrong-chain and wrong-boundary readiness replay, independent approval
authorization, request/recipient tampering, per-guardian atomic activation,
restart-safe ceremony state, explicit policy restoration, and independently
pinned log checks against rewriting and truncation.

## Protocol and API

The Python orchestration interface is `GuardianCluster(directory, member_ids,
library, curve, recipient_public_key)`. Its fixture harness centrally issues test
TLS certificates; a deployment must give institutions independent credentials
and protected private storage.

1. `bootstrap_genesis(members, threshold, signer_policy)` returns the initial
   `AuditConfig` and public ceremony plans. Each guardian generates its own
   random contribution and sends private evaluations directly to recipients over
   mutual TLS. This runs before the genesis block hash exists, so plans bind an
   independent random ceremony ID.
2. After installing that public configuration in a fresh chain, call
   `prepare(actual_genesis_hash, config, plans)` and `activate(chain_id, prepared)`.
   Genesis readiness binds the actual chain hash and exact public configuration.
   Every later ceremony is bound to that actual chain hash throughout.
3. `rollover(chain_id, previous_config, signer_policy, activate=False)` prepares a
   fresh key while preserving existing shares and produces readiness for every
   retained key. `handoff(chain_id, previous_config, new_members, new_threshold,
   signer_policy, activate=False)` prepares new shares for **every** retained key.
   Both return `(PreparedTransition, plans)` without activating. The caller can
   submit the exact public configuration and readiness to native DynaFed before
   activating services when its trusted node observes the transition.
4. `activate(chain_id, prepared)` verifies a ready quorum for every key before
   each guardian atomically replaces its complete active configuration and share
   set. The operation is idempotent. A partially delivered commit can be resumed;
   this is not a distributed atomic commit across every service.
5. `recover(config, key_version, statement, packet, recipient_public_key)` is the
   test recipient workflow: collect independent institutional approvals, obtain
   approved partials over recipient-authenticated TLS and combine them locally.
   It returns the opening and signed guardian log checkpoints. The fixture
   harness acts as the authorized recipient for this call; that role must be
   separated from the coordinator in a deployment.

Incoming readiness uses the unchanged `governance.make_readiness` and
`PreparedTransition` formats, so it can feed the native TAG1/TAP1 governance
integration. Native policy determines activation; these guardian services do
not themselves validate blockchain consensus or transaction inclusion. A
trusted chain observer must supply the correct chain/configuration and output
references. The service's low-level `restore` operation can select an explicitly
retained configuration after that observer sees a reorg. It cannot restore
erased or unavailable shares. Snapshot retention and finality policy remain
deployment decisions.

## Transport, storage and authorization

Every listener binds `127.0.0.1`; outbound requests permit loopback HTTPS only.
Mutual TLS validates certificate chains and checks pinned certificate
fingerprints for the expected role and member. Coordinator credentials cannot
request institutional approvals or receive partial decryptions. Separate
per-institution approver credentials authorize each guardian's BIP340 approval
signature, and a separately pinned recipient TLS credential must match the
recipient public key bound into the signed disclosure request.

The approver endpoint is an experimental stand-in for an institution's approval
UI or policy service. It does not evaluate legal authority, independently fetch
the output from chain, or require human review. Request approvals bind the exact
policy, statement, packet, opaque case reference, recipient and expiry. The
guardian checks the current manifest for the selected historical key and uses
its own share. Only supported TAC2 packets are accepted.

Private directories use mode 0700. Atomic state replacement uses mode 0600,
file fsync and parent-directory fsync. A lifetime exclusive directory lock rejects a second writer before reading
state or logs. TLS handshakes run outside the accept loop in at most 32 worker
threads, with a 5-second handshake timeout and 10-second request-read timeout.
The server joins workers before releasing its cryptographic context and lock.
Dealer plans are bound to a random
session ID, chain, old committee, selected old quorum, new roster/threshold,
key version and share epoch. A dealer's polynomial is persisted before sending;
retries reuse its exact public commitments and evaluations. Recipients verify
the signed public transcript, public constant terms and each private evaluation,
then persist incoming state before acknowledging receipt. A different plan
cannot reuse the same session/version.

Each network operation has one monotonic deadline across TCP connection, TLS
handshake, request writes, response headers/body and all retries. The deadline
retains the actual TLS socket even when HTTP/1.0 detaches it from the HTTP client.
Only persisted idempotent ceremony messages can retry, at most three times and
within that same deadline. Certificate/pinning failures, validation errors,
approvals and disclosures are not automatically retried. Transport errors have
a separate type; local credential or storage errors never become retryable
HTTP 503 responses. Dealers stagger their recipient order to avoid a queue of
simultaneous durable writes at the first recipient.

A failed private-state replacement/fsync or audit-log write/fsync marks the
guardian unhealthy. Subsequent key/ceremony/disclosure operations fail closed;
only status and shutdown remain available until explicit recovery. A cached
in-memory mutation cannot be acknowledged after its durable write failed.
Status exposes the storage-fault condition. Tests inject both private-state and
log failures, as well as a lost acknowledgement after a persisted dealer action.

Before producing a partial decryption, the guardian fsyncs its authorization
record. It records the validated request scope, a public output reference,
signed approval evidence and a release event, never shares,
evaluations, partial points or recovered openings. Each returned checkpoint is
signed by the guardian's institution identity. `verify_checkpoint` checks that
signature and `verify_log` checks the independently retained log prefix. A
separate observer must retain checkpoints; a hash chain stored only beside its
own log does not prevent rewriting. The tests retain witness checkpoints outside
private guardian state, on the same test machine.

The experiment retains at most 32 ceremony sessions per guardian and 16 audit
key versions in its public protocol. Safe archival/garbage collection and larger
long-running deployments require an explicit lifecycle; deleting retained
historical decryption keys is not an archival policy.

## Remaining security work

Independent protocol and implementation review, an appropriate actively secure
DKG/handoff protocol, robust failure recovery, authenticated chain observation,
independently operated checkpoint witnesses, encrypted/protected storage,
rollback protection, credential lifecycle, hardware support, rate limits and
operational monitoring remain required. Retaining rollback snapshots retains
old secrets. Local root or a colluding threshold can bypass software approval
and logging; already disclosed plaintexts and retained old quorum shares cannot
be revoked by these services.
