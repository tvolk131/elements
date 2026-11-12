import { useState } from "react";
import { WorkspaceLink } from "./navigation";
import { useApp } from "./context";
import {
  Badge,
  Button,
  CopyField,
  Empty,
  Heading,
  Icon,
  Panel,
} from "./components";
import {
  csv,
  date,
  download,
  forAccount,
  human,
  isException,
  isPending,
  money,
  nextStep,
  short,
} from "./domain";
import { NetworkCard, RotationNotice } from "./guardian";
import type { Operation } from "./types";

export function AccountContext() {
  const { data, account, setAccount, can } = useApp();
  return (
    <div className="wallet-account-context">
      <label htmlFor="wallet-account">
        <span>{can("view_bank") ? "Customer account" : "Wallet account"}</span>
        <select
          id="wallet-account"
          data-testid="wallet-account"
          value={account}
          onChange={(e) => setAccount(e.target.value)}
        >
          {data.accounts.map((a) => (
            <option key={a.id} value={a.id}>
              {a.name}
              {can("view_bank") ? ` · ${a.tenant}` : ""}
            </option>
          ))}
        </select>
      </label>
      <div>
        <span>Account reference</span>
        <strong>{account || "No account configured"}</strong>
      </div>
    </div>
  );
}
export function WalletPage({
  page,
}: {
  page: "overview" | "payments" | "banking";
}) {
  const app = useApp();
  const home = page === "overview";
  const banking = page === "banking";
  const ops = forAccount(app.data.operations, app.account).filter(
    (op) => !banking || ["deposit", "redemption", "refund"].includes(op.kind),
  );
  const attention = ops
    .filter(
      (op) =>
        isPending(op) &&
        op.allowed_actions.some((a) =>
          [
            "approve",
            "guardian-approve",
            "execute",
            "bank-credit",
            "cancel",
          ].includes(a),
        ),
    )
    .slice(0, 4);
  const tasks = [
    {
      kind: "deposit",
      title: "Add funds from bank",
      direction: "Bank → chain · Peg in",
      description: "Create a funding request for this wallet.",
      icon: "download",
    },
    {
      kind: "redemption",
      title: "Withdraw to bank",
      direction: "Chain → bank · Peg out",
      description: "Request a payout to a configured bank account.",
      icon: "upload",
    },
    {
      kind: "transfer",
      title: "Send on-chain",
      direction: "Wallet → wallet",
      description: "Transfer tokens between approved accounts.",
      icon: "send",
    },
    {
      kind: "receive",
      title: "Receive on-chain",
      direction: "Wallet → this account",
      description: "Share account details for a managed transfer.",
      icon: "wallet",
    },
  ] as const;
  return (
    <>
      <Heading
        title={home ? "Wallet" : banking ? "Bank transfers" : "Requests"}
        actions={
          !home && (
            <WorkspaceLink className="button primary" page="overview">
              Move funds
            </WorkspaceLink>
          )
        }
      >
        {home
          ? "Manage on-chain balances and requests for one account at a time."
          : banking
            ? "Track requests to add funds from a bank or withdraw tokens to a bank."
            : "Track your requests, approvals and completed transactions."}
      </Heading>
      <AccountContext />
      <RotationNotice />
      {home && (
        <>
          <section
            className="wallet-task-section"
            aria-labelledby="wallet-task-heading"
          >
            <div className="wallet-section-heading">
              <h2 id="wallet-task-heading">Move funds</h2>
              <p>Choose where the funds are coming from or going to.</p>
            </div>
            <div className="wallet-tasks">
              {tasks.map((t) => (
                <button
                  key={t.kind}
                  type="button"
                  className="wallet-task"
                  data-testid={
                    t.kind === "receive" ? "receive-funds" : `new-${t.kind}`
                  }
                  onClick={() =>
                    app.setDialog(
                      t.kind === "receive"
                        ? { type: "receive" }
                        : { type: "create", kind: t.kind },
                    )
                  }
                >
                  <span className="wallet-task-icon">
                    <Icon name={t.icon} />
                  </span>
                  <strong>{t.title}</strong>
                  <span className="wallet-task-direction">{t.direction}</span>
                  <span className="wallet-task-description">
                    {t.description}
                  </span>
                  {t.kind !== "receive" && !app.can(`create_${t.kind}`) ? (
                    <span className="wallet-task-permission">
                      View steps and who can request
                    </span>
                  ) : (
                    <span className="wallet-task-link">
                      View details <Icon name="arrow" />
                    </span>
                  )}
                </button>
              ))}
            </div>
          </section>
          <Balances />
        </>
      )}
      {attention.length > 0 && (
        <section className="wallet-attention">
          <h2>
            Needs your attention{" "}
            <span className="count">{attention.length}</span>
          </h2>
          {attention.map((op) => (
            <button
              key={op.id}
              className="wallet-attention-item"
              data-id={op.id}
              onClick={() => app.setDialog({ type: "operation", id: op.id })}
            >
              <span>
                <strong>
                  {human(op.kind)} · {money(op.amount_minor)} Test{op.currency}
                </strong>
                <small>{nextStep(op)}</small>
              </span>
              <span>
                Review <Icon name="chevron" />
              </span>
            </button>
          ))}
        </section>
      )}
      {banking && (
        <div className="wallet-bank-guide">
          <strong>Bank ↔ chain</strong>
          <p>
            <b>Add funds:</b> request → simulated bank credit → separate user
            and institution approvals → token issuance.
            <br />
            <b>Withdraw:</b> request → approvals → tokens locked → simulated
            bank payout → token burn.
          </p>
          <Button
            symbol="download"
            data-testid="new-deposit"
            onClick={() => app.setDialog({ type: "create", kind: "deposit" })}
          >
            Add funds from bank
          </Button>{" "}
          <Button
            symbol="upload"
            data-testid="new-redemption"
            onClick={() =>
              app.setDialog({ type: "create", kind: "redemption" })
            }
          >
            Withdraw to bank
          </Button>
        </div>
      )}
      <OperationPanel
        title={
          home
            ? "Recent requests"
            : banking
              ? "Bank funding and withdrawals"
              : "Account requests"
        }
        operations={ops}
      />
      {banking && app.can("simulate_bank") && (
        <details className="wallet-admin-tools">
          <summary>Bank simulator · administrator tools</summary>
          <p>
            Record test credits and payout results. No real bank payment is
            sent.
          </p>
          <Button
            symbol="plus"
            data-testid="bank-event"
            onClick={() => app.setDialog({ type: "bank" })}
          >
            Record simulated bank event
          </Button>
        </details>
      )}
      <details className="wallet-network-details">
        <summary>Network and account information</summary>
        <div className="aside-panels">
          <Panel title="Your workspace">
            <div className="kv-list">
              <p>
                {app.user.tenant} · {human(app.user.role)}
              </p>
              <p>Separate approver required</p>
            </div>
            <p className="small-note">
              Token issuer and reserve arrangements remain undecided. Test
              tokens do not represent a legal claim to real funds.
            </p>
          </Panel>
          <NetworkCard />
        </div>
        {app.can("view_bank") && (
          <p className="small-note">
            <a href="/guardian">Open guardian and federation console</a>
          </p>
        )}
      </details>
    </>
  );
}
function Balances() {
  const { data, account } = useApp();
  const balances = data.balances.filter((b) => b.account_id === account);
  return (
    <section
      className="wallet-balances"
      aria-labelledby="wallet-balances-heading"
    >
      <div className="wallet-section-heading">
        <h2 id="wallet-balances-heading">On-chain balances</h2>
        <p>Available amounts exclude funds reserved for pending requests.</p>
      </div>
      <div className="balance-grid">
        {balances.map((b) => (
          <article
            className="balance-card"
            key={b.currency}
            data-testid={`balance-${b.currency}`}
          >
            <div className="balance-top">
              <div className="balance-currency">
                <span className="currency-flag">
                  {b.currency === "EUR" ? "€" : "$"}
                </span>
                <strong>Test{b.currency}</strong>
              </div>
              <span className="wallet-asset-label">Test token</span>
            </div>
            <div className="balance-value number">{money(b.balance_minor)}</div>
            <div className="balance-meta">
              <span>Available to send or withdraw</span>
              <strong>{money(b.available_minor)}</strong>
            </div>
            {b.available_minor < b.balance_minor && (
              <div className="balance-meta">
                <span>Reserved for requests</span>
                <strong>{money(b.balance_minor - b.available_minor)}</strong>
              </div>
            )}
            <div
              className={`wallet-balance-status ${b.chain_reconciles === false ? "warning-text" : ""}`}
            >
              <Icon name={b.chain_reconciles ? "check" : "info"} />
              {b.chain_reconciles === true
                ? "Matches the on-chain wallet"
                : b.chain_reconciles === false
                  ? "Balance mismatch · contact your bank operator"
                  : "On-chain balance check unavailable"}
            </div>
          </article>
        ))}
      </div>
      {!balances.length && (
        <Empty title="No balances available">
          Ask your bank administrator to configure this account.
        </Empty>
      )}
    </section>
  );
}
export function Quorum({ operation: op }: { operation: Operation }) {
  return (
    <div className="quorum">
      <span className="quorum-track">
        {Array.from({ length: Math.min(op.guardian_threshold, 15) }, (_, i) => (
          <span key={i} className={i < op.guardian_approvals ? "filled" : ""} />
        ))}
      </span>
      <span>
        {op.guardian_approvals} / {op.guardian_threshold || "—"}
      </span>
    </div>
  );
}
export function OperationPanel({
  title,
  operations,
}: {
  title: string;
  operations: Operation[];
}) {
  const app = useApp();
  const [filter, setFilter] = useState("all");
  const [search, setSearch] = useState("");
  const rows = operations
    .filter(
      (op) =>
        (filter === "all" ||
          (filter === "pending" && isPending(op)) ||
          (filter === "settled" && op.state === "settled") ||
          (filter === "exceptions" && isException(op))) &&
        (!search ||
          [
            op.id,
            op.kind,
            human(op.kind),
            op.currency,
            op.destination,
            op.account_id,
            op.reference,
            app.accountName(op.account_id),
            app.accountName(op.to_account_id),
          ]
            .join(" ")
            .toLowerCase()
            .includes(search.toLowerCase())),
    )
    .sort((a, b) => b.created_at - a.created_at);
  function titleFor(op: Operation) {
    if (!app.guardian && op.kind === "transfer")
      return op.to_account_id === app.account && op.account_id !== app.account
        ? `${op.state === "settled" ? "Received" : "Incoming transfer"} from ${app.accountName(op.account_id)}`
        : `${op.state === "settled" ? "Sent" : "Transfer request"} to ${app.accountName(op.to_account_id)}`;
    return op.destination_name || op.beneficiary_name || human(op.kind);
  }
  return (
    <Panel
      title={`${title} ${operations.length}`}
      subtitle={
        app.guardian
          ? "Approval binds the exact request, destination and evidence."
          : "Open a request to see its next step and who needs to act."
      }
      actions={
        <button
          className="icon-button"
          aria-label="Export visible operations as CSV"
          onClick={() =>
            download(
              csv([
                [
                  "Request ID",
                  "Type",
                  "Currency",
                  "Amount",
                  "Source",
                  "Destination",
                  "Status",
                  "Created UTC",
                  "Elements txid",
                ],
                ...rows.map((op) => [
                  op.id,
                  op.kind,
                  op.currency,
                  money(op.amount_minor),
                  op.account_id,
                  op.destination,
                  op.state,
                  op.created_at,
                  op.txid,
                ]),
              ]),
              "concord-settlement-requests.csv",
              "text/csv;charset=utf-8",
            )
          }
        >
          <Icon name="export" />
        </button>
      }
    >
      <div className="toolbar">
        <div className="tabs" role="group" aria-label="Filter operations">
          {[
            ["all", "All"],
            ["pending", "In progress"],
            ["settled", "Settled"],
            ["exceptions", "Exceptions"],
          ].map(([key, label]) => (
            <button
              key={key}
              type="button"
              className={`tab ${filter === key ? "active" : ""}`}
              aria-pressed={filter === key}
              onClick={() => setFilter(key)}
            >
              {label}
            </button>
          ))}
        </div>
        <label className="search">
          <Icon name="search" />
          <input
            type="search"
            placeholder="Search requests"
            aria-label="Search requests"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            data-testid="operation-search"
          />
        </label>
      </div>
      {rows.length ? (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Request / counterparty</th>
                <th>Amount</th>
                <th>Status</th>
                <th>{app.guardian ? "Institution approvals" : "Created"}</th>
                <th>
                  <span className="sr-only">Review</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((op) => (
                <tr
                  key={op.id}
                  data-testid="operation-row"
                  data-operation-id={op.id}
                >
                  <td>
                    <div className="operation-type">
                      <span className={`type-icon ${op.kind}`}>
                        <Icon
                          name={
                            op.kind === "deposit"
                              ? "download"
                              : op.kind === "redemption"
                                ? "upload"
                                : "send"
                          }
                        />
                      </span>
                      <div>
                        <span className="cell-primary">{titleFor(op)}</span>
                        <span className="cell-secondary">
                          {human(op.kind)} · {short(op.id)}
                        </span>
                      </div>
                    </div>
                  </td>
                  <td className="amount-cell">
                    <span className="cell-primary number">
                      {!app.guardian &&
                        op.state === "settled" &&
                        (op.kind === "transfer"
                          ? op.to_account_id === app.account
                            ? "+"
                            : "−"
                          : ["deposit", "refund"].includes(op.kind)
                            ? "+"
                            : "−")}
                      {money(op.amount_minor)}
                    </span>
                    <span className="cell-secondary">Test{op.currency}</span>
                  </td>
                  <td>
                    <Badge status={op.state} />
                    {!app.guardian && (
                      <span className="cell-secondary wallet-next-summary">
                        {nextStep(op)}
                      </span>
                    )}
                    {op.error && isPending(op) && (
                      <span className="cell-secondary warning-text">
                        Review required
                      </span>
                    )}
                  </td>
                  <td>
                    {app.guardian ? (
                      <Quorum operation={op} />
                    ) : (
                      <>
                        <span className="cell-primary">
                          {date(op.created_at)}
                        </span>
                        <span className="cell-secondary">{op.account_id}</span>
                      </>
                    )}
                  </td>
                  <td>
                    <button
                      className="link-button"
                      data-testid="review-operation"
                      onClick={() =>
                        app.setDialog({ type: "operation", id: op.id })
                      }
                      aria-label={`Review ${op.kind} request ${op.id}`}
                    >
                      Review <Icon name="chevron" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <Empty
          title={
            operations.length
              ? "No matching requests"
              : "No requests for this account yet"
          }
        >
          {operations.length
            ? "Try another filter or search term."
            : "Start with Move funds to create a request."}
        </Empty>
      )}
      <div className="panel-footer">
        <span>{rows.length} requests · Current authorized workspace</span>
        <span>All times UTC</span>
      </div>
    </Panel>
  );
}
export function RecipientsPage() {
  const app = useApp();
  const internal = app.data.accounts.filter((a) => a.id !== app.account);
  const bank = app.data.beneficiaries.filter(
    (b) => b.kind === "bank" && b.account_id === app.account,
  );
  return (
    <>
      <Heading title="Recipients">
        On-chain accounts and bank withdrawal destinations are separate routes.
      </Heading>
      <AccountContext />
      <div className="wallet-recipient-panels">
        <Panel
          title="On-chain accounts"
          subtitle="Destinations available to you in Send on-chain."
        >
          {internal.length ? (
            <ul className="wallet-recipient-list">
              {internal.map((a) => (
                <li key={a.id}>
                  <strong>{a.name}</strong>
                  <span>{a.currencies.map((c) => "Test" + c).join(" / ")}</span>
                  <small>Account reference: {a.id}</small>
                </li>
              ))}
            </ul>
          ) : (
            <Empty title="No other permitted accounts" />
          )}
          <div className="panel-footer">
            <Button
              symbol="send"
              onClick={() =>
                app.setDialog({ type: "create", kind: "transfer" })
              }
            >
              Send on-chain
            </Button>
          </div>
        </Panel>
        <Panel
          title="Bank accounts"
          subtitle="Destinations available for Withdraw to bank."
        >
          {bank.length ? (
            <ul className="wallet-recipient-list">
              {bank.map((b) => (
                <li key={b.id}>
                  <strong>{b.name}</strong>
                  <span>Test{b.currency} · configured bank destination</span>
                  <small>
                    Bank account details are held by the bank operator.
                  </small>
                </li>
              ))}
            </ul>
          ) : (
            <Empty title="No bank destinations configured" />
          )}
          <div className="panel-footer">
            <Button
              symbol="upload"
              onClick={() =>
                app.setDialog({ type: "create", kind: "redemption" })
              }
            >
              Withdraw to bank
            </Button>
          </div>
        </Panel>
      </div>
    </>
  );
}
export function ActivityPage() {
  const app = useApp();
  const rows = app.data.activity;
  return (
    <>
      <Heading
        title="Activity log"
        actions={
          <Button onClick={app.refresh} symbol="refresh">
            Refresh
          </Button>
        }
      >
        An attributable record of requests, reviews and settlement events.
      </Heading>
      <Panel
        title="Recorded events"
        subtitle="Activity is scoped to the records your account can access."
        actions={
          <Button
            onClick={() =>
              download(
                csv([
                  ["Event", "Actor", "Request ID", "Recorded UTC"],
                  ...rows.map((e) => [
                    e.description || e.action || e.event,
                    e.actor_name || e.actor,
                    e.operation_id,
                    e.created_at || e.timestamp,
                  ]),
                ]),
                "concord-activity.csv",
                "text/csv;charset=utf-8",
              )
            }
          >
            Export CSV
          </Button>
        }
      >
        {rows.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Event</th>
                  <th>Actor</th>
                  <th>Request</th>
                  <th>Recorded at</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((e, i) => (
                  <tr key={e.id ?? i}>
                    <td>{e.description || human(e.action || e.event)}</td>
                    <td>{e.actor_name || e.actor || "System"}</td>
                    <td>
                      {e.operation_id ? (
                        <button
                          className="link-button"
                          onClick={() =>
                            app.setDialog({
                              type: "operation",
                              id: e.operation_id!,
                            })
                          }
                        >
                          {short(e.operation_id, 16)}
                        </button>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td>{date(e.created_at || e.timestamp, true)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="No recorded events yet" />
        )}
      </Panel>
    </>
  );
}
export function Receive() {
  const app = useApp();
  const account = app.data.accounts.find((a) => a.id === app.account);
  if (!account) return <Empty title="No receiving account configured" />;
  return (
    <>
      <div className="receive-account">
        <span>Receiving account</span>
        <h3>{account.name}</h3>
        <p>{account.tenant}</p>
        <CopyField label="Account reference" value={account.id} />
      </div>
      <ol className="wallet-flow-list">
        <li>
          Share this account name and reference with your bank operator or an
          authorized sender.
        </li>
        <li>
          The sender opens <b>Send on-chain</b> and chooses this account from
          their permitted destinations.
        </li>
        <li>
          After the required approvals and chain confirmation, your balance
          updates here.
        </li>
      </ol>
      <div className="wallet-receive-limit">
        <strong>Supported in this pilot</strong>
        <p>
          This account reference is not a blockchain address. Transfers are
          limited to accounts available to the sender. Corporate users can
          currently transfer between their own permitted accounts.
        </p>
        <p>
          Receiving from an arbitrary wallet address is not integrated with the
          account ledger yet. No external deposit address is provided here. To
          add funds from a bank, use <b>Add funds from bank</b>.
        </p>
      </div>
    </>
  );
}
