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
  short,
  thresholdLabel,
} from "./domain";
import { OperationPanel } from "./wallet";
import type { FederationPolicy, Membership, Stage } from "./types";

export function RotationNotice() {
  const app = useApp();
  const federation = app.data.federation;
  const rotation = federation?.rotation;
  const hold =
    rotation?.hold_reason ||
    federation?.hold_reason ||
    app.data.network.settlement_hold;
  if (
    !hold &&
    (!rotation ||
      ["complete", "completed", "cancelled"].includes(rotation.state))
  )
    return null;
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
        <KV label="Block height">{n.height ?? n.block_height ?? "—"}</KV>
        <KV label="Asset registry">
          {n.registry_version === undefined
            ? "Not reported"
            : `Version ${n.registry_version}`}
        </KV>
      </div>
      <p className="small-note">
        {n.error ||
          "Chain actions use the native Elements adapter. Bank events use a local simulator."}
      </p>
    </Panel>
  );
}
function AuditCard() {
  const { data } = useApp();
  const a = data.audit ||
    data.network.audit || {
      threshold: data.network.audit_threshold,
      guardian_count: data.network.audit_guardians,
      roster_id:
        data.network.audit_version === undefined
          ? undefined
          : `Audit version ${data.network.audit_version}`,
    };
  return (
    <Panel title="Audit key readiness" className="side-card">
      <div className="kv-list">
        <KV label="Current roster">{a.roster_id || "Not reported"}</KV>
        <KV label="Recovery threshold">
          {a.threshold
            ? `${a.threshold} of ${a.guardian_count ?? "—"}`
            : "Not reported"}
        </KV>
        <KV label="Historical outputs">
          {a.historical_ready === true
            ? "Recovery attested"
            : a.historical_ready === false
              ? "Readiness not attested"
              : "Not reported in this dashboard"}
        </KV>
      </div>
      <p className="small-note">
        {a.historical_ready === true
          ? "Current guardians report access to historical recovery keys."
          : a.historical_ready === false
            ? "A DynaFed update alone does not demonstrate historical key recovery."
            : "This view has no historical-readiness feed. Consult the recorded handover evidence; no failure is inferred."}
      </p>
      <WorkspaceLink page="network" className="link-button">
        View governance details <Icon name="arrow" />
      </WorkspaceLink>
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
      <div className={approvals ? "guardian-queue-layout" : "panels"}>
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
        {!approvals && (
          <aside className="aside-panels">
            <NetworkCard />
            <AuditCard />
          </aside>
        )}
      </div>
      {!approvals && (
        <Panel
          title="Confidential disclosure cases"
          subtitle="Recovery authority is distinct from settlement approval."
          actions={
            <Badge status="not_started">Native service not connected</Badge>
          }
        >
          <p className="small-note">
            The native guardian disclosure workflow is separate. This console
            does not request decryption shares or hold audit keys. Connect its
            case API before exposing disclosure actions here.
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
                        {r.frozen ? "Issuance frozen" : undefined}
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
                      <th>Audit key access</th>
                    </tr>
                  </thead>
                  <tbody>
                    {app.data.guardians.map((g, i) => (
                      <tr key={g.institution_id || g.id || i}>
                        <td>{g.name || g.institution_id || g.id}</td>
                        <td>
                          <Badge
                            status={
                              g.status ||
                              (g.approval_url ? "configured" : "unconfigured")
                            }
                          />
                        </td>
                        <td>
                          <Badge
                            status={
                              g.historical_ready === true ? "ready" : "neutral"
                            }
                          >
                            {g.historical_ready === true
                              ? "History attested"
                              : g.historical_ready === false
                                ? "Not attested"
                                : "Not reported"}
                          </Badge>
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
                <p className="small-note">
                  {asset.issuer || "Sandbox issuer (legal entity undecided)"}
                </p>
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
function PolicyDomain({
  policy,
  title,
  symbol,
}: {
  policy?: Membership;
  title: string;
  symbol: string;
}) {
  return (
    <div className="federation-domain">
      <div className="federation-domain-title">
        <Icon name={symbol} />
        <h4>{title}</h4>
        <strong>{thresholdLabel(policy)}</strong>
      </div>
      {policy?.detail && <p className="small-note">{policy.detail}</p>}
      {policy?.members?.length ? (
        <details className="federation-members">
          <summary>{policy.members.length} recorded members</summary>
          <ul>
            {policy.members.map((m, i) => (
              <li key={i}>
                {typeof m === "string" ? m : m.name || m.id || m.member}
              </li>
            ))}
          </ul>
        </details>
      ) : null}
      {policy?.script && (
        <details className="wallet-technical">
          <summary>Technical signing policy</summary>
          <CopyField label="Signing script" value={policy.script} />
        </details>
      )}
    </div>
  );
}
function MembershipCard({
  value,
  incoming = false,
}: {
  value?: FederationPolicy;
  incoming?: boolean;
}) {
  return (
    <Panel
      title={
        value?.label ||
        value?.id ||
        (incoming ? "Awaiting a prepared handover" : "Membership unavailable")
      }
      subtitle={`${incoming ? "Incoming" : "Current"} membership${value?.epoch !== undefined ? ` · Epoch ${value.epoch}` : ""}`}
      className={`federation-membership ${incoming ? "incoming" : ""}`}
      actions={
        value?.state || value?.status ? (
          <Badge status={value.state || value.status} />
        ) : undefined
      }
    >
      {value ? (
        <>
          <PolicyDomain
            policy={value.block_signing}
            title="Block signing"
            symbol="network"
          />
          <PolicyDomain
            policy={value.audit}
            title="Historical audit recovery"
            symbol="shield"
          />
          <PolicyDomain
            policy={value.treasury}
            title="Treasury spending"
            symbol="bank"
          />
        </>
      ) : (
        <Empty
          title={
            incoming
              ? "No incoming membership recorded"
              : "Current policy is not available"
          }
        >
          The coordinator supplies membership and readiness evidence.
        </Empty>
      )}
    </Panel>
  );
}
export function FederationPage() {
  const app = useApp();
  const f = app.data.federation || {};
  const r = f.rotation;
  const actions = [
    ...new Set([...(f.allowed_actions || []), ...(r?.allowed_actions || [])]),
  ];
  const steps = r?.steps || [];
  const migrations = r?.migrations || [];
  const readiness = r?.readiness || [];
  const outstanding = r?.outstanding_cases || [];
  const count =
    r?.approval_count ?? r?.guardian_approvals ?? r?.approvals?.length;
  const required =
    r?.approval_threshold ?? r?.guardian_threshold ?? r?.threshold;
  const stage = r?.stage || r?.state || "not_started";
  const genesis = f.genesis_hash || app.data.network.genesis_hash;
  const tables = (rows: Stage[], cases = false) =>
    rows.length ? (
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>{cases ? "Case" : "Authority / escrow"}</th>
              <th>Test currency</th>
              <th>{cases ? "Amount" : "Transaction"}</th>
              <th>State</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((item, i) => (
              <tr key={item.id || i}>
                <td>
                  {cases && item.id ? (
                    <button
                      className="link-button"
                      onClick={() =>
                        app.setDialog({ type: "operation", id: item.id! })
                      }
                    >
                      {human(item.kind)} · {short(item.id)}
                    </button>
                  ) : (
                    item.label || human(item.kind)
                  )}
                </td>
                <td>{item.currency ? "Test" + item.currency : "—"}</td>
                <td>
                  {cases ? (
                    money(item.amount_minor)
                  ) : item.txid ? (
                    <CopyField
                      label="Migration transaction"
                      value={item.txid}
                    />
                  ) : (
                    "Not recorded"
                  )}
                </td>
                <td>
                  <Badge status={item.state || item.status} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    ) : (
      <Empty
        title={
          cases
            ? "No outstanding cases recorded"
            : "No migration transactions recorded"
        }
      />
    );
  return (
    <>
      <Heading
        title="Federation lifecycle"
        actions={
          <>
            <Button onClick={app.refresh} symbol="refresh">
              Refresh
            </Button>
            {actions.includes("prepare") && (
              <Button
                className="primary"
                data-testid="rotation-prepare"
                onClick={() =>
                  app.setDialog({ type: "rotation", action: "prepare" })
                }
              >
                Prepare handover
              </Button>
            )}
          </>
        }
      >
        Coordinate signing, historical recovery and treasury authority on the
        existing chain.
      </Heading>
      <div className="federation-chain">
        <span className="federation-chain-icon">
          <Icon name="network" />
        </span>
        <div>
          <strong>{f.chain || app.data.network.chain}</strong>
          <p>
            Membership changes retain this chain, its history and its asset IDs.
          </p>
        </div>
        <Badge status="neutral">Same-chain handover</Badge>
        <CopyField label="Genesis block" value={genesis} />
      </div>
      <RotationNotice />
      <div className="metrics federation-metrics">
        <Metric
          title="Handover stage"
          value={human(stage)}
          detail={`${steps.filter((s) => ["complete", "completed", "confirmed", "active"].includes(s.state || s.status || "")).length} of ${steps.length} stages complete`}
          symbol="refresh"
        />
        <Metric
          title="Current audit recovery"
          value={thresholdLabel(f.current?.audit)}
          detail="Threshold from the recorded current membership"
          symbol="shield"
        />
        <Metric
          title="Institution authorizations"
          value={count === undefined ? "—" : `${count} / ${required ?? "—"}`}
          detail="Exact source-policy authorization"
          symbol="lock"
        />
        <Metric
          title="Migration transactions"
          value={migrations.length || "—"}
          detail="Prepared and confirmed records"
          symbol="bank"
        />
      </div>
      <div className="federation-memberships">
        <MembershipCard value={f.current} />
        <MembershipCard value={f.incoming} incoming />
      </div>
      <div className="panels federation-progress">
        <section>
          <Panel
            title="Recorded handover stages"
            subtitle={
              r
                ? `Request ${short(r.id, 22)} · ${date(r.created_at, true)}`
                : "The coordinator records every stage before it advances."
            }
            actions={<Badge status={stage} />}
          >
            {steps.length ? (
              <ol className="rotation-steps">
                {steps.map((s, i) => (
                  <li
                    className={`rotation-step ${["complete", "completed", "confirmed", "active"].includes(s.state || s.status || "") ? "done" : ""}`}
                    key={s.id || i}
                  >
                    <span className="rotation-step-number">{i + 1}</span>
                    <div>
                      <div className="rotation-step-title">
                        <strong>{s.label || human(s.id)}</strong>
                        <Badge status={s.state || s.status} />
                      </div>
                      {s.detail && <p>{s.detail}</p>}
                      <CopyField label="Elements transaction" value={s.txid} />
                    </div>
                  </li>
                ))}
              </ol>
            ) : (
              <Empty title="No handover stages recorded" />
            )}
          </Panel>
          <Panel
            title="Treasury migrations"
            subtitle="Reissuance authority and recorded redemption escrows on the existing chain."
          >
            {tables(migrations)}
          </Panel>
          <Panel
            title="Outstanding settlement cases"
            subtitle="Continuity must be preserved through the handover."
          >
            {tables(outstanding, true)}
          </Panel>
        </section>
        <aside className="aside-panels">
          <Panel title="Handover authorization" className="side-card">
            <div className="kv-list">
              <KV label="Source institution approvals">
                {count === undefined
                  ? "Not reported"
                  : `${count} / ${required ?? "—"}`}
              </KV>
              <KV label="Current stage">{human(stage)}</KV>
              {r?.activation_height !== undefined && (
                <KV label="Planned activation height">{r.activation_height}</KV>
              )}
            </div>
            {r?.error && (
              <div className="inline-warning" role="alert">
                {r.error}
              </div>
            )}
            {r?.hold_reason && (
              <div className="inline-warning">{r.hold_reason}</div>
            )}
            <div className="rotation-actions">
              {actions.some((a) =>
                ["guardian-approve", "guardian_approve", "approve"].includes(a),
              ) && (
                <Button
                  className="primary"
                  data-testid="rotation-approve"
                  onClick={() =>
                    app.setDialog({ type: "rotation", action: "approve" })
                  }
                >
                  Review institution authorization
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
                    {a === "advance"
                      ? "Advance handover"
                      : "Retry recorded stage"}
                  </Button>
                ))}
            </div>
            <p className="small-note">
              Source institutions authorize the exact manifest in separate
              approval windows. This console does not receive their passphrases.
            </p>
            {r && (
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
            )}
          </Panel>
          <Panel title="Readiness evidence" className="side-card">
            {readiness.length ? (
              <ul className="rotation-readiness">
                {readiness.map((s, i) => (
                  <li key={s.id || i}>
                    <div>
                      <strong>{s.label || s.id}</strong>
                      {s.detail && <p>{s.detail}</p>}
                    </div>
                    <Badge status={s.state || s.status} />
                  </li>
                ))}
              </ul>
            ) : (
              <p className="small-note">
                No readiness attestations are reported. An incoming roster alone
                does not establish possession of historical recovery shares.
              </p>
            )}
          </Panel>
        </aside>
      </div>
    </>
  );
}
