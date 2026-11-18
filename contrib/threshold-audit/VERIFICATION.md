# Reproducible verification and review patches

The verifier builds and tests this experimental fork without relying on fixed
`/tmp` build paths or an already running sandbox. It records the exact source
snapshot, tools, commands, exit codes and logs. This is a repeatable verification
procedure, not a claim of bit-for-bit reproducible release binaries or a security
audit.

## One command from a checkout

Install the normal Elements development prerequisites, including a C++ compiler,
CMake, Boost, libevent, SQLite, Berkeley DB development headers and OpenSSL.
Berkeley DB is required by the current bank-managed legacy wallet fixture and
the legacy DynaFed regression. No Bitcoin daemon or real bank account is needed.

From the repository root:

```sh
python3 contrib/threshold-audit/verify.py --mode full --build
```

The default output is a new private directory selected by the operating system's
temporary-directory mechanism. The command prints its location. For a chosen
new/empty directory and bounded build parallelism:

```sh
python3 contrib/threshold-audit/verify.py --mode full --build \
  --work-dir /path/to/new-private-verification-run --jobs 4
```

Build artifacts default to that run's `build/native` and `build/secp256k1`.
`--native-build` and `--secp-build` can reuse build directories while still running
CMake configure/build. To deliberately use previously built binaries:

```sh
python3 contrib/threshold-audit/verify.py --mode full --no-build \
  --native-build /path/to/elements-build \
  --secp-build /path/to/secp-build \
  --library /path/to/secp-build/lib/libsecp256k1.so
```

`--no-build` records binary hashes, but it cannot attest that operator-supplied
binaries correspond to the current source. The report says so explicitly. Use
the build mode for the complete source/build/test procedure.

The current settlement fixture requires POSIX. Full verification additionally
requires Linux procfs to identify and clean up orphaned servers safely. Use a
separate port seed when running multiple native verification jobs concurrently.

## Quick and full checks

Quick mode (`--mode quick`) runs:

* Python and native verification of deterministic, explicitly public review
  vectors, including expected rejection cases.
* Python research, guardian, settlement and verification-tool tests, plus the
  review-package tests.
* Selected native confidential-transaction, wallet/PSET, DynaFed and header-sync
  tests.
* A source-bound cryptographic review inventory.
* Export and clean application of the complete review patch series.

Full mode also runs:

* Native audit lifecycle, versioned asset registry and isolated guardian handoff
  functional tests.
* Existing non-audit DynaFed and PSET regressions.
* Generation/replay of public parser fuzz seeds. This is seed replay, not a
  coverage-guided fuzz campaign.
* A newly owned settlement sandbox with A-to-B-to-C rotation, intermediate
  restarts and a completed-state restart. C completes A's outstanding cases and
  recovers A/B-era outputs.
* The runtime failure/backup-recovery scenario provided by
  `settlement.runtime_faults`.

The verifier does not use a user's already running application. Tests create
private fixture credentials and simulated bank events. Each command has a
deadline (`--timeout`, seconds). Native functional tests fail if a required
component is missing rather than silently turning a skip into a pass.

Browser verification is separate. The report always records that this command
does not perform visual browser QA; JavaScript parsing or HTTP checks must not
be described as visual testing.

## Report, failure and cleanup

`report.json` records the Git base, source digests, tool versions, binary hashes,
commands, timestamps, exit codes and cleanup result. Full command output is in
`logs/`. The final source snapshot must match the starting one; concurrent source
edits invalidate the run even if individual checks passed.

The work directory is private because `runtimes/` contains test wallet keys,
operator credentials and guardian state. Keep the complete directory private;
share only reviewed reports, public vectors and the exported source patches.
Logs are retained on failure. A failing command's exit status is preserved where
possible; timeout exits 124, interruption exits 128 plus the signal number.

The runner starts commands in owned sessions and tracks descendant birth ticks.
Sandbox children may have their own sessions; cleanup additionally recognizes
only known server roles pointing into this run's fresh private runtime. It uses
PID file descriptors when available and checks process birth identity before
signalling. Success, failure and interruption all clean up the owned servers.
It never uses `killall`/`pkill` or a global Elements process-name match. Baseline
servers using other directories remain untouched.

## Reviewable patch series

Export without staging, committing or changing the checkout:

```sh
python3 contrib/threshold-audit/export_review.py --output /path/to/new-review-bundle
```

The exporter reads the selected Git base (default `HEAD`) and includes the
authorized tracked changes and explicitly allowed untracked research sources.
It groups them into native consensus/wallet code, native tests, cryptographic
models/guardian services, settlement sandbox, and review/tooling/docs.

`series` gives the order. `manifest.json` records the exact base, each patch's
digest, all reconstructed source digests and the apply-check result. The exporter
archives the base into a temporary copy, applies each patch in sequence and
checks the resulting file contents and executable modes. It never writes the
checkout's Git index or history. Unknown tracked changes require explicit review
instead of being silently included.

The groups are review categories. **Intermediate patches are not claimed to
build independently.** The complete series reconstructs the source snapshot;
build/test evidence belongs to the separate verification report.

Runtime JSON, credentials, private shares, TLS keys, databases, logs, Python
caches and build outputs are excluded. The only included JSON fixtures are
`measurements.example.json` and `review/vectors/public-v1.json`, both explicitly
public test material. The export fails if selected source files are symlinks or
change during packaging. Output must be new/empty; prior bundles are never
silently replaced.
