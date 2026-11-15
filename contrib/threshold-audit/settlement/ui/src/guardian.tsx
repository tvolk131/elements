import { WorkspaceLink } from "./navigation";
import { useApp } from "./context";
import {
  Badge,
  Button,
  CopyField,
  Empty,
  Heading,
  Icon,
  KV,
  Metric,
  Panel,
} from "./components";
import {
  date,
  download,
  human,
  isActiveException,
  needsInstitutionApproval,
  isPending,
  money,
  safeFilename,
  settlementHold,
  short,
  thresholdLabel,
} from "./domain";
import { OperationPanel } from "./wallet";
import type {
  FederationPolicy,
  Membership,
  Migration,
  OutstandingCase,
} from "./types";

export function RotationNotice() {
  const app = useApp();
  const federation = app.data.federation;
  const rotation = federation?.rotation;
  const hold = settlementHold(app.data);
  if (!hold && (!rotation || rotation.state === "complete")) return null;
  return (
    <div
      className="rotation-notice"
      id="settlement-transition-hold"
      role="status"
    >
      <Icon name="refresh" />
      <div>
        <strong>
          {hold
            ? "Settlement transition hold"
            : "Federation handover in progress"}
        </strong>
        <p>
          {hold ||
            "A federation handover is in progress. Settlement availability follows the recorded transition policy."}
        </p>
      </div>
      {app.can("view_bank") &&
        (app.guardian ? (
          <WorkspaceLink className="link-button" page="federation">
            View handover
          </WorkspaceLink>
        ) : (
          <a className="link-button" href="/guardian/federation">
            View handover
          </a>
        ))}
    </div>
  );
}
export function NetworkCard() {
  const { data } = useApp();
  const n = data.network;
  return (
    <Panel
      title="Network status"
      className="side-card"
      actions={
        <Badge status={n.connected ? "healthy" : "unavailable"}>
          {n.connected ? "Connected" : "Not connected"}
        </Badge>
      }
    >
      <div className="kv-list">
        <KV label="Elements chain">{n.chain}</KV>
        <KV label="Block height">{n.height}</KV>
        <KV label="Asset registry">Version {n.registry_version}</KV>
      </div>
      <p className="small-note">
        Chain actions use the native Elements adapter. Bank events use a local
        simulator.
      </p>
    </Panel>
  );
}
function AuditCard() {
  const { network } = useApp().data;
  return (
    <Panel title="Audit key" className="side-card">
      <div className="kv-list">
        <KV label="Audit key version">{network.audit_version ?? "—"}</KV>
        <KV label="Recovery threshold">
          {network.audit_threshold} of {network.audit_guardians}
        </KV>
      </div>
      <p className="small-note">
        Historical recovery readiness is attested during each federation
        handover. See the handover’s readiness evidence.
      </p>
    </Panel>
  );
}
export function GuardianOverview({
  approvals = false,
}: {
  approvals?: boolean;
}) {
  const app = useApp();
  const ops = app.data.operations;
  const mine = ops.filter(needsInstitutionApproval);
  return (
    <>
      <Heading
        title={approvals ? "Approval queue" : "Federation overview"}
        actions={
          <Button
            symbol="refresh"
            disabled={app.refreshing}
            onClick={app.refresh}
          >
            Refresh
          </Button>
        }
      >
        Independent oversight, shared responsibility.
        {app.user.institution_id && ` Acting for ${app.user.institution_id}.`}
      </Heading>
      <RotationNotice />
      {approvals ? (
        <div className="guardian-queue-guide">
          <Icon name="shield" />
          <div>
            <strong>
              {mine.length}{" "}
              {mine.length === 1 ? "request awaits" : "requests await"} your
              institution
            </strong>
            <p>
              Review the exact amount and destination. Institution certificates
              and user approvals are separate requirements.
            </p>
          </div>
          <WorkspaceLink page="overview" className="link-button">
            View all settlement activity <Icon name="arrow" />
          </WorkspaceLink>
        </div>
      ) : (
        <div className="metrics">
          <Metric
            title="Awaiting your institution"
            value={mine.length}
            detail="Review before providing an institution certificate"
            symbol="shield"
          />
          <Metric
            title="Active settlement requests"
            value={ops.filter(isPending).length}
            detail={`${ops.filter((o) => o.state === "settled").length} completed in this workspace`}
            symbol="activity"
          />
          <Metric
            title="Unresolved exceptions"
            value={ops.filter(isActiveException).length}
            detail="Bank uncertainty and chain errors"
            symbol="info"
          />
          <Metric
            title="Elements block height"
            value={app.data.network.height ?? "—"}
            detail={
              app.data.network.connected
                ? "Node connected · live adapter"
                : "See network readiness"
            }
            symbol="network"
          />
        </div>
      )}
      {!approvals && (
        <div className="guardian-queue-link">
          <WorkspaceLink page="approvals" className="button primary">
            Open your approval queue{" "}
            <span className="nav-badge">{mine.length}</span>
            <Icon name="arrow" />
          </WorkspaceLink>
        </div>
      )}
      <div className="guardian-queue-layout">
        <section>
          <OperationPanel
            key={approvals ? "institution-queue" : "settlement-history"}
            actionQueue={approvals}
            title={approvals ? "Requests for review" : "Settlement requests"}
            operations={approvals ? mine : ops}
            emptyTitle={
              approvals ? "Your institution is up to date" : undefined
            }
            emptyDetail={
              approvals
                ? "No requests currently need a certificate from your institution. Completed and other requests remain in the overview."
                : undefined
            }
          />
        </section>
      </div>
      {!approvals && (
        <Panel
          title="Confidential disclosure cases"
          subtitle="Recovery authority is distinct from settlement approval."
          actions={
            <Badge
              status={
                app.data.network.disclosure_available ? "ready" : "not_started"
              }
            >
              {app.data.network.disclosure_available
                ? "Recipient-encrypted recovery"
                : "Native service not connected"}
            </Badge>
          }
        >
          <p className="small-note">
            {app.data.network.disclosure_available
              ? "Disclosure cases use separate compliance and audit-guardian accounts. Each required guardian explicitly approves access for a named recipient. Payment approval accounts do not grant disclosure authority."
              : "The native guardian disclosure workflow is separate. This console does not request decryption shares or hold audit keys. Connect its case API before exposing disclosure actions here."}
          </p>
        </Panel>
      )}
    </>
  );
}
export function ReservesPage() {
  const app = useApp();
  return (
    <>
      <Heading
        title="Reserve accounts"
        actions={
          <Button onClick={app.refresh} symbol="refresh">
            Refresh
          </Button>
        }
      >
        Simulated segregated accounts, independently reconciled by currency.
      </Heading>
      {app.can("simulate_bank") && (
        <div className="bank-simulator">
          <div>
            <strong>Local reserve simulator</strong>
            <p>Events are auditable test records. No real money is moved.</p>
          </div>
          <Button onClick={() => app.setDialog({ type: "bank" })}>
            Record bank event
          </Button>
        </div>
      )}
      <Panel
        title="Reserve reconciliation"
        subtitle="Keep issuer liabilities, reserve credits and pending payouts distinct."
        actions={<Badge status="neutral">Simulated accounts</Badge>}
      >
        {app.data.reserves.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Currency</th>
                  <th>Reserve balance</th>
                  <th>Token liabilities</th>
                  <th>Reconciliation</th>
                </tr>
              </thead>
              <tbody>
                {app.data.reserves.map((r) => (
                  <tr key={r.currency}>
                    <td>
                      <span className="cell-primary">Test{r.currency}</span>
                      <span className="cell-secondary">
                        Sandbox issuer · Local test ledger
                      </span>
                    </td>
                    <td className="number">
                      {money(r.cash_minor)} Test{r.currency}
                    </td>
                    <td className="number">
                      {money(r.token_liability_minor)} Test{r.currency}
                      <span className="cell-secondary">
                        Deposit payable {money(r.deposit_payable_minor)} ·
                        Redemption payable {money(r.redemption_payable_minor)}
                      </span>
                    </td>
                    <td>
                      <Badge
                        status={
                          r.frozen ||
                          !r.cash_reconciles ||
                          !r.liabilities_reconcile ||
                          !r.supply_reconciles ||
                          !r.journal_balances
                            ? "mismatch"
                            : "reconciled"
                        }
                      >
                        {r.frozen
                          ? "Issuance frozen"
                          : r.cash_reconciles &&
                              r.liabilities_reconcile &&
                              r.supply_reconciles &&
                              r.journal_balances
                            ? "Fully backed"
                            : undefined}
                      </Badge>
                      <span className="cell-secondary">
                        Escrow {money(r.escrow_minor)} · Test payout mode:{" "}
                        {human(r.payout_mode)}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="No reserve accounts reported" />
        )}
        <div className="panel-footer">
          Operational evidence only · Legal segregation is a separate
          institutional arrangement
        </div>
      </Panel>
    </>
  );
}
export function NetworkPage() {
  const app = useApp();
  return (
    <>
      <Heading
        title="Network & key readiness"
        actions={
          <Button onClick={app.refresh} symbol="refresh">
            Refresh
          </Button>
        }
      >
        Track chain governance, settlement assets and historical audit access
        separately.
      </Heading>
      <div className="panels">
        <section>
          <Panel
            title="Guardian institutions"
            subtitle="Authority is supplied by independently configured institution signers."
          >
            {app.data.guardians.length ? (
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Institution</th>
                      <th>Approval signer</th>
                    </tr>
                  </thead>
                  <tbody>
                    {app.data.guardians.map((g) => (
                      <tr key={g.id}>
                        <td>{g.name}</td>
                        <td>
                          <Badge
                            status={
                              g.approval_url ? "configured" : "unconfigured"
                            }
                          />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <Empty title="Guardian roster not reported" />
            )}
          </Panel>
          <Panel
            title="Settlement assets"
            subtitle="Native registry membership is separate from reserve facts and redemption terms."
          >
            {app.data.assets.map((asset) => (
              <div key={asset.asset_id} className="asset-detail">
                <h3>Test{asset.currency}</h3>
                <Badge status={asset.registered ? "active" : "unconfigured"}>
                  {asset.registered ? "Registered" : "Not registered"}
                </Badge>
                <CopyField label="Native asset ID" value={asset.asset_id} />
                <p className="small-note">{asset.issuer}</p>
              </div>
            ))}
          </Panel>
        </section>
        <aside className="aside-panels">
          <NetworkCard />
          <AuditCard />
        </aside>
      </div>
    </>
  );
}
/** "institution-c-1" → "Institution C-1"; audit member "7" → "Guardian 7". */
export const memberName = (member: string) =>
  /^\d+$/.test(member)
    ? `Guardian ${member}`
    : `Institution ${member.replace(/^institution-/i, "").toUpperCase()}`;
const ROLE_COPY = [
  [
    "treasury",
    "Approve settlements",
    "Release payments, withdrawals and newly issued tokens.",
    "bank",
  ],
  [
    "block_signing",
    "Confirm new blocks",
    "Add confirmed transactions to the shared ledger.",
    "network",
  ],
  [
    "authorization",
    "Authorize every transaction",
    "Check each transaction before the ledger accepts it, and refuse payments to addresses no member bank has registered.",
    "lock",
  ],
  [
    "audit",
    "Approve disclosures",
    "Let a named authority see a specific past payment.",
    "shield",
  ],
] as const;
const STEP_COPY: Record<string, string> = {
  preparing: "Prepare the new operators",
  awaiting_approval: "Current institutions approve the handover",
  voting: "The network switches to the new operators",
  audit_activated: "New guardians take over disclosure keys",
  migrating: "Move held funds to the new operators",
  activating: "New operators start approving settlements",
  retiring: "Retire the previous operators",
  complete: "Settlement resumes",
};
const READINESS_COPY: Record<string, [string, string]> = {
  audit: [
    "Past payments stay disclosable",
    "The new guardians proved they hold the keys for earlier payments.",
  ],
};
function OperatorGroup({
  value,
  incoming = false,
}: {
  value: FederationPolicy;
  incoming?: boolean;
}) {
  return (
    <Panel
      title={incoming ? "Incoming operators" : "Current operators"}
      subtitle={value.label}
      className={`federation-membership ${incoming ? "incoming" : ""}`}
    >
      {value.detail && <p className="small-note">{value.detail}</p>}
      <div className="operator-roles">
        {ROLE_COPY.map(([key, title, detail, symbol]) => {
          const policy = value[key];
          if (!policy) return null;
          return (
            <div className="federation-domain" key={key}>
              <div className="federation-domain-title">
                <Icon name={symbol} />
                <h4>{title}</h4>
                <strong>
                  {policy.threshold} of {policy.count}
                </strong>
              </div>
              <p className="small-note">{detail}</p>
              <details className="federation-members">
                <summary>Who ({policy.count})</summary>
                <ul>
                  {policy.members.map((m) => (
                    <li key={m}>{memberName(m)}</li>
                  ))}
                </ul>
              </details>
              {policy.script && (
                <details className="wallet-technical">
                  <summary>Technical details</summary>
                  <CopyField label="Signing script" value={policy.script} />
                </details>
              )}
            </div>
          );
        })}
      </div>
    </Panel>
  );
}
export function FederationPage() {
  const app = useApp();
  const f = app.data.federation;
  if (!f) return <h1>Operator details are not available to this account</h1>;
  const r = f.rotation && f.rotation.stage !== "complete" ? f.rotation : null;
  const last = f.rotation?.stage === "complete" ? f.rotation : null;
  const actions = [
    ...new Set([...f.allowed_actions, ...(r?.allowed_actions || [])]),
  ];
  const steps = r?.steps || [];
  const done = steps.filter((s) => s.state === "complete").length;
  return (
    <>
      <Heading
        title="Network operators"
        actions={
          <Button onClick={app.refresh} symbol="refresh">
            Refresh
          </Button>
        }
      >
        The independent institutions that run this network, and how they hand
        over to a new group.
      </Heading>
      <div className="federation-chain">
        <span className="federation-chain-icon">
          <Icon name="network" />
        </span>
        <div>
          <strong>One shared ledger</strong>
          <p>
            Operators can be replaced without moving to a new ledger. Balances,
            history and assets stay where they are.
          </p>
        </div>
        <details className="wallet-technical">
          <summary>Technical details</summary>
          <KV label="Ledger">{app.data.network.chain}</KV>
          <CopyField label="Genesis block" value={f.genesis_hash} />
        </details>
      </div>
      <RotationNotice />
      {r ? (
        <div className="metrics federation-metrics">
          <Metric
            title="Handover progress"
            value={`${done} of ${steps.length}`}
            detail={STEP_COPY[r.stage] || human(r.stage)}
            symbol="refresh"
          />
          <Metric
            title="Handover approvals"
            value={`${r.approval_count} of ${r.approval_threshold}`}
            detail="From the current institutions"
            symbol="lock"
          />
          <Metric
            title="Funds to move"
            value={r.migrations.length || "—"}
            detail="Held by the network, moved to the new operators"
            symbol="bank"
          />
          <Metric
            title="Requests carried over"
            value={r.outstanding_cases.length}
            detail="Pending requests continue after the handover"
            symbol="activity"
          />
        </div>
      ) : null}
      <div className={`federation-memberships ${f.incoming ? "" : "single"}`}>
        <OperatorGroup value={f.current} />
        {f.incoming && <OperatorGroup value={f.incoming} incoming />}
      </div>
      {r ? (
        <div className="panels federation-progress">
          <section>
            <Panel
              title="Handover steps"
              subtitle={`Started ${date(r.created_at, true)}`}
              actions={<Badge status={r.stage} />}
            >
              <ol className="rotation-steps">
                {steps.map((s, i) => (
                  <li
                    className={`rotation-step ${s.state === "complete" ? "done" : ""}`}
                    key={s.id}
                  >
                    <span className="rotation-step-number">{i + 1}</span>
                    <div className="rotation-step-title">
                      <strong>{STEP_COPY[s.id] || s.label}</strong>
                      <Badge status={s.state} />
                    </div>
                  </li>
                ))}
              </ol>
            </Panel>
            <Panel
              title="Funds moved to the new operators"
              subtitle="Money the network holds, such as tokens locked for withdrawals, moves with the operators."
            >
              <MigrationTable rows={r.migrations} />
            </Panel>
            <Panel
              title="Requests carried over"
              subtitle="Requests in progress continue under the new operators."
            >
              <CaseTable rows={r.outstanding_cases} />
            </Panel>
          </section>
          <aside className="aside-panels">
            <Panel title="Handover approvals" className="side-card">
              <div className="kv-list">
                <KV label="Current institutions">
                  {r.approval_count} of {r.approval_threshold} approved
                </KV>
              </div>
              {r.error && (
                <div className="inline-warning" role="alert">
                  {r.error}
                </div>
              )}
              <div className="rotation-actions">
                {actions.includes("guardian-approve") && (
                  <Button
                    className="primary"
                    data-testid="rotation-approve"
                    onClick={() =>
                      app.setDialog({
                        type: "rotation",
                        action: "guardian-approve",
                      })
                    }
                  >
                    Review handover
                  </Button>
                )}
                {["advance", "retry"]
                  .filter((a) => actions.includes(a))
                  .map((a) => (
                    <Button
                      key={a}
                      className="primary"
                      data-testid={`rotation-${a}`}
                      onClick={() =>
                        app.setDialog({ type: "rotation", action: a })
                      }
                    >
                      {a === "advance" ? "Next step" : "Retry this step"}
                    </Button>
                  ))}
              </div>
              <p className="small-note">
                Each current institution approves the exact handover in its own
                approval window.
              </p>
              <Button
                onClick={() =>
                  download(
                    JSON.stringify(
                      {
                        document: "Concord same-chain federation handover",
                        exported_at: new Date().toISOString(),
                        viewer: app.user.id,
                        warning:
                          "Local sandbox. Bank reserves and payments are simulated.",
                        federation: f,
                      },
                      null,
                      2,
                    ),
                    `concord-handover-${safeFilename(r.id)}.json`,
                  )
                }
              >
                Download handover record
              </Button>
            </Panel>
            <Panel title="Checks before switching" className="side-card">
              <ul className="rotation-readiness">
                {r.readiness.map((s) => (
                  <li key={s.id}>
                    <div>
                      <strong>{READINESS_COPY[s.id]?.[0] || s.label}</strong>
                      <p>
                        {s.state === "ready"
                          ? READINESS_COPY[s.id]?.[1] || s.detail
                          : s.detail}
                      </p>
                    </div>
                    <Badge status={s.state} />
                  </li>
                ))}
              </ul>
            </Panel>
          </aside>
        </div>
      ) : (
        <Panel
          title="Handing over to new operators"
          subtitle={
            last
              ? `The last handover finished ${date(last.created_at, true)}.`
              : "No handover is in progress."
          }
          actions={
            actions.includes("prepare") ? (
              <Button
                data-testid="rotation-prepare"
                onClick={() =>
                  app.setDialog({ type: "rotation", action: "prepare" })
                }
              >
                Prepare a handover
              </Button>
            ) : undefined
          }
        >
          <p className="federation-explainer">
            To replace the operators, the bank prepares the incoming group, the
            current institutions approve, and the network switches over while
            pending requests carry on. Past payments remain disclosable by the
            new guardians.
          </p>
        </Panel>
      )}
    </>
  );
}
function MigrationTable({ rows }: { rows: Migration[] }) {
  if (!rows.length) return <Empty title="Nothing to move" />;
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>What moved</th>
            <th>Currency</th>
            <th>Transaction</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((item) => (
            <tr key={item.migration_id}>
              <td>
                {item.kind === "authority"
                  ? "Token issuing authority"
                  : item.kind === "escrow"
                    ? "Tokens held for a withdrawal"
                    : human(item.kind)}
              </td>
              <td>{item.currency ? "Test" + item.currency : "—"}</td>
              <td>
                {item.txid ? (
                  <CopyField label="Transaction" value={item.txid} />
                ) : (
                  "Not recorded"
                )}
              </td>
              <td>
                <Badge status={item.state} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
function CaseTable({ rows }: { rows: OutstandingCase[] }) {
  const app = useApp();
  if (!rows.length) return <Empty title="No requests in progress" />;
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Request</th>
            <th>Currency</th>
            <th>Amount</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((item) => (
            <tr key={item.id}>
              <td>
                <button
                  className="link-button"
                  onClick={() =>
                    app.setDialog({ type: "operation", id: item.id })
                  }
                >
                  {human(item.kind)} · {short(item.id)}
                </button>
              </td>
              <td>Test{item.currency}</td>
              <td>{money(item.amount_minor)}</td>
              <td>
                <Badge status={item.state} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
