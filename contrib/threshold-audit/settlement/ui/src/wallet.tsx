import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { api } from "./api";
import { WorkspaceLink } from "./navigation";
import { useApp } from "./context";
import {
  Badge,
  Button,
  CopyField,
  Empty,
  ErrorNote,
  Field,
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
  needsAction,
  nextStep,
  viewerNextAction,
  requestSummary,
  short,
} from "./domain";
import { NetworkCard, RotationNotice } from "./guardian";
import type { Currency, Operation } from "./types";

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
  const attention = ops.filter(needsAction).slice(0, 4);
  const tasks = [
    {
      kind: "deposit",
      title: "Add funds from bank",
      direction: "Bank account → wallet",
      description: "Create a funding request for this wallet.",
      action: "Create funding request",
      icon: "download",
    },
    {
      kind: "redemption",
      title: "Withdraw to bank",
      direction: "Wallet → bank account",
      description: "Request a payout to a configured bank account.",
      action: "Request withdrawal",
      icon: "upload",
    },
    {
      kind: "transfer",
      title: "Send on-chain",
      direction: "Wallet → another account",
      description: "Pay a company here or at another bank.",
      action: "Start transfer",
      icon: "send",
    },
    {
      kind: "receive",
      title: "Receive on-chain",
      direction: "Another account → wallet",
      description: "Share a bank reference or confidential receiving address.",
      action: "Show receiving details",
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
      {attention.length > 0 && (
        <section className="wallet-attention">
          <h2>
            Needs your attention
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
                <small>{viewerNextAction(op) || nextStep(op)}</small>
              </span>
              <span>
                Review <Icon name="chevron" />
              </span>
            </button>
          ))}
        </section>
      )}
      {home && (
        <>
          <Balances />
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
                  <span className="wallet-task-link">
                    {t.kind !== "receive" && !app.can(`create_${t.kind}`)
                      ? "See who can request"
                      : t.action}
                    <Icon name="arrow" />
                  </span>
                </button>
              ))}
            </div>
          </section>
        </>
      )}
      {banking && (
        <div className="wallet-bank-guide">
          <strong>Bank ↔ chain</strong>
          <p>
            <b>Add funds:</b> request → bank confirms the deposit → approvals →
            tokens issued.
            <br />
            <b>Withdraw:</b> request → approvals → tokens locked → bank pays out
            → tokens destroyed.
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
            <span className="balance-available-label">
              Available to send or withdraw
            </span>
            <div className="balance-value number">
              {money(b.available_minor)}
            </div>
            <div className="balance-breakdown">
              <div>
                <span>Total on-chain</span>
                <strong>{money(b.balance_minor)}</strong>
              </div>
              <div>
                <span>Reserved</span>
                <strong>{money(b.balance_minor - b.available_minor)}</strong>
              </div>
            </div>
            <div
              data-reconciled={b.chain_reconciles === true}
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
  if (op.kind === "receipt")
    return <span className="small-note">Not required</span>;
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
  emptyTitle,
  emptyDetail,
  actionQueue = false,
}: {
  title: string;
  operations: Operation[];
  emptyTitle?: string;
  emptyDetail?: string;
  actionQueue?: boolean;
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
    if (op.kind === "receipt") return "Received from external wallet";
    if (app.guardian && op.kind === "transfer")
      return `${app.accountName(op.account_id)} → ${app.accountName(op.to_account_id)}`;
    if (!app.guardian && op.kind === "transfer")
      return op.to_account_id === app.account && op.account_id !== app.account
        ? `${op.state === "settled" ? "Received" : "Incoming transfer"} from ${op.source_name || app.accountName(op.account_id)}`
        : `${op.state === "settled" ? "Sent" : "Transfer request"} to ${op.destination_name || app.accountName(op.to_account_id)}`;
    return op.destination_name || op.beneficiary_name || human(op.kind);
  }
  return (
    <Panel
      title={title}
      count={operations.length}
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
          {(actionQueue
            ? [["all", "Awaiting your institution"]]
            : [
                ["all", "All"],
                ["pending", "In progress"],
                ["settled", "Settled"],
                ["exceptions", "Exceptions"],
              ]
          ).map(([key, label]) => (
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
                          : ["deposit", "refund", "receipt"].includes(op.kind)
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
                        {requestSummary(op)}
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
              : emptyTitle || "No requests for this account yet"
          }
        >
          {operations.length
            ? "Try another filter or search term."
            : emptyDetail || "Start with Move funds to create a request."}
        </Empty>
      )}
      <div className="panel-footer">
        <span>
          {rows.length} {rows.length === 1 ? "request" : "requests"}
        </span>
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
        Pay another managed account, look up a beneficiary at another bank, or
        enter a confidential wallet address. Bank withdrawals are a separate
        route.
      </Heading>
      <AccountContext />
      <div className="wallet-recipient-panels">
        <Panel
          title="On-chain accounts"
          subtitle="Your managed accounts. Other banks' customers can be looked up by reference in Send on-chain."
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
                    human(e.event),
                    e.actor,
                    e.operation_id,
                    new Date(e.created_at * 1000).toISOString(),
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
                {rows.map((e) => (
                  <tr key={e.id}>
                    <td>{human(e.event)}</td>
                    <td>{e.actor}</td>
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
                    <td>{date(e.created_at, true)}</td>
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
  const [chosen, setCurrency] = useState<Currency>();
  // Default to the account's first currency; a USD-only account must not
  // request an EUR address.
  const currency =
    chosen && account?.currencies.includes(chosen)
      ? chosen
      : account?.currencies[0];
  const address = useMutation({
    mutationFn: () =>
      api<{ address: string; reference: string }>("/api/receive-address", {
        account_id: app.account,
        currency,
      }),
  });
  if (!account || !currency)
    return <Empty title="No receiving account configured" />;
  return (
    <>
      <div className="receive-account">
        <span>Receiving account</span>
        <h3>{account.name}</h3>
        <p>{account.bank_id || account.tenant}</p>
        <CopyField
          label="Beneficiary reference"
          value={account.payment_reference || account.id}
        />
      </div>
      <ol className="wallet-flow-list">
        <li>Share this beneficiary reference with the sender.</li>
        <li>
          The sender chooses <b>A company, by bank reference</b> in{" "}
          <b>Send on-chain</b>, looks up the reference and confirms your
          receiving details.
        </li>
        <li>
          After approvals and chain confirmation, the receipt appears in this
          wallet.
        </li>
      </ol>
      <div className="wallet-receive-limit">
        <h3>Receive at a confidential address</h3>
        <p>
          You can also share a confidential address for this chain. The address
          itself does not identify or verify you to the sender.
        </p>
        <Field label="Asset">
          <select
            aria-label="Receive currency"
            value={currency}
            onChange={(e) => {
              setCurrency(e.target.value as Currency);
              address.reset();
            }}
          >
            {account.currencies.map((c) => (
              <option key={c} value={c}>
                Test{c}
              </option>
            ))}
          </select>
        </Field>
        <Button
          disabled={address.isPending}
          onClick={() => address.mutate()}
          data-testid="generate-receive-address"
        >
          {address.isPending
            ? "Creating address…"
            : "Generate receiving address"}
        </Button>
        {address.data && (
          <CopyField
            label="Confidential receiving address"
            value={address.data.address}
          />
        )}
        <ErrorNote error={address.error} />
        <p>
          Only supported test assets with whole-cent amounts are credited by
          this demo. Bank funding is a separate action:{" "}
          <b>Add funds from bank</b>.
        </p>
      </div>
    </>
  );
}
