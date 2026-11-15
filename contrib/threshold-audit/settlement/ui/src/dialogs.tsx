import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api, refreshData } from "./api";
import { useApp } from "./context";
import {
  Badge,
  Button,
  CopyField,
  Empty,
  ErrorNote,
  Field,
  KV,
  Modal,
} from "./components";
import {
  SETTLING,
  bankStatus,
  chainStatus,
  date,
  download,
  eligibleDestinations,
  human,
  money,
  nextStep,
  retryable,
  viewerNextAction,
  safeFilename,
  waitingForInstitutions,
  settlementHold,
  transferNeedsInstitutions,
} from "./domain";
import { Quorum, Receive } from "./wallet";
import { ApprovalProgress } from "./approval-progress";
import { DemoNext } from "./demo";
import {
  TransferDestination,
  type TransferTarget,
} from "./beneficiary-routing";
import type { Currency, Kind, Operation } from "./types";

const REVIEW: Record<
  string,
  {
    open: string;
    title: string;
    context: string;
    confirm: string;
    done: string;
  }
> = {
  approve: {
    open: "Review and approve",
    title: "Approve this request",
    context:
      "Your approval is the second-person check. Institution approvals are still needed before it can be sent.",
    confirm: "Approve",
    done: "Approval recorded.",
  },
  "approve-send": {
    open: "Review, approve and send",
    title: "Approve and send",
    context:
      "Your approval is the last one needed, so the request is sent right away and settles in a few seconds.",
    confirm: "Approve and send",
    done: "Approved and sent. It settles in a few seconds.",
  },
  "guardian-approve": {
    open: "Review institution approval",
    title: "Institution approval",
    context: "",
    confirm: "Open approval window",
    done: "",
  },
  execute: {
    open: "Continue",
    title: "Send this request",
    context:
      "All approvals are in place. The request is submitted to the chain and settles automatically.",
    confirm: "Send",
    done: "Submitted. It settles in a few seconds.",
  },
  cancel: {
    open: "Request escrow return",
    title: "Request escrow return",
    context:
      "The bank payout failed, so the locked tokens can be returned. A new set of approvals is required.",
    confirm: "Request return",
    done: "Return requested. It needs approvals before tokens are released.",
  },
  reject: {
    open: "Reject",
    title: "Reject this request",
    context: "Rejecting closes the request and records your reason.",
    confirm: "Reject request",
    done: "Request rejected.",
  },
};
const ROTATION: Record<
  string,
  { title: string; context: string; confirm: string }
> = {
  prepare: {
    title: "Prepare a handover to new operators",
    context:
      "The bank sets up the incoming operators and checks they hold the keys for past payments. New requests pause until the handover finishes. The current institutions then approve it.",
    confirm: "Prepare handover",
  },
  "guardian-approve": {
    title: "Approve the handover",
    context:
      "Review the incoming operators and the funds that move to them in your institution’s own approval window.",
    confirm: "Open approval window",
  },
  advance: {
    title: "Continue the handover",
    context:
      "Runs only the next recorded step. Each step is saved before the next one starts.",
    confirm: "Run next step",
  },
  retry: {
    title: "Retry this handover step",
    context: "Runs the recorded step again with exactly the same transactions.",
    confirm: "Retry step",
  },
};
function sourceName(op: Operation, app: ReturnType<typeof useApp>): string {
  if (op.kind === "receipt") return "External wallet";
  if (op.kind === "deposit") return "Bank account (simulated)";
  return op.source_name || app.accountName(op.account_id);
}
function destinationName(
  op: Operation,
  app: ReturnType<typeof useApp>,
): string {
  if (op.kind === "transfer")
    return op.destination_name || app.accountName(op.to_account_id);
  if (["deposit", "refund", "receipt"].includes(op.kind))
    return app.accountName(op.account_id);
  return (
    op.beneficiary_name ||
    app.data.beneficiaries.find((b) => b.id === op.beneficiary_id)?.name ||
    "Configured bank account"
  );
}
function Footer({ children }: { children: ReactNode }) {
  return <div className="dialog-footer">{children}</div>;
}
function Cancel() {
  const app = useApp();
  return <Button onClick={() => app.setDialog(null)}>Cancel</Button>;
}
function Amount({
  value,
  onChange,
}: {
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <Field
      label="Amount"
      detail="Enter an exact amount with up to two decimal places."
    >
      <input
        name="amount"
        aria-label="Amount"
        data-testid="amount"
        type="text"
        inputMode="decimal"
        autoComplete="off"
        placeholder="0.00"
        pattern="[0-9]+([.][0-9]{1,2})?"
        maxLength={16}
        required
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </Field>
  );
}
export function Dialogs() {
  const app = useApp();
  const d = app.dialog;
  if (!d) return null;
  const close = () => app.setDialog(null);
  if (d.type === "receive")
    return (
      <Modal
        title="Receive on-chain"
        description="Share a beneficiary reference or confidential receiving address."
        close={close}
      >
        <div className="dialog-body">
          <Receive />
        </div>
        <Footer>
          <Button className="primary" onClick={close}>
            Done
          </Button>
        </Footer>
      </Modal>
    );
  if (d.type === "create") {
    const title = d.kind === "transfer" ? "Send on-chain" : human(d.kind);
    if (!app.can(`create_${d.kind}`))
      return (
        <Modal
          title={title}
          description="Who can start this request?"
          close={close}
        >
          <div className="dialog-body">
            <div className="form-context">
              {d.kind === "deposit"
                ? "A bank payment maker or bank administrator creates bank funding requests for your account."
                : "A bank or corporate payment maker creates this request. Your current role can review permitted requests but cannot create one."}
            </div>
            <p className="wallet-help-copy">
              Ask an authorized maker to create the request, then follow its
              progress in Requests.
            </p>
          </div>
          <Footer>
            <Button onClick={close}>Understood</Button>
          </Footer>
        </Modal>
      );
    const hold = settlementHold(app.data);
    if (hold)
      return (
        <Modal title="Requests are temporarily paused" close={close}>
          <div className="dialog-body">
            <p>{hold}</p>
            <p>
              Ask your bank operator to check the transition before creating a
              request.
            </p>
          </div>
          <Footer>
            <Button onClick={close}>Understood</Button>
          </Footer>
        </Modal>
      );
    return <CreateForm key={d.kind} kind={d.kind} />;
  }
  if (d.type === "operation") return <OperationDetail key={d.id} id={d.id} />;
  if (d.type === "review")
    return (
      <ReviewForm
        key={`${d.operation.id}-${d.action}`}
        operation={d.operation}
        action={d.action}
      />
    );
  if (d.type === "bank")
    return d.operation?.state === "awaiting_bank" ? (
      <BankCreditForm operation={d.operation} />
    ) : (
      <BankForm operation={d.operation} />
    );
  return <RotationForm action={d.action} />;
}
function CreateForm({ kind }: { kind: Exclude<Kind, "refund" | "receipt"> }) {
  const app = useApp();
  const [account, setAccount] = useState(app.account);
  const [currency, setCurrency] = useState<Currency>(
    app.data.accounts.find((a) => a.id === account)?.currencies[0] || "EUR",
  );
  const [amount, setAmount] = useState("");
  const [destination, setDestination] = useState("");
  const [transferDestination, setTransferDestination] =
    useState<TransferTarget | null>(null);
  const transferTarget =
    transferDestination?.scope === account + ":" + currency
      ? transferDestination
      : null;
  const accountInfo = app.data.accounts.find((a) => a.id === account);
  const balance = app.data.balances.find(
    (b) => b.account_id === account && b.currency === currency,
  );
  const exceedsAvailable =
    kind !== "deposit" &&
    balance &&
    /^[0-9]+([.][0-9]{1,2})?$/.test(amount) &&
    Math.round(Number(amount) * 100) > balance.available_minor;
  const destinations = eligibleDestinations(
    kind,
    app.data.accounts,
    app.data.beneficiaries,
    account,
    currency,
  );
  const selectedDestination = destinations.some((d) => d.id === destination)
    ? destination
    : "";
  const mutation = useMutation({
    mutationFn: async () => {
      const body = {
        account_id: account,
        currency,
        amount,
        ...(kind === "transfer"
          ? transferTarget?.route_id
            ? { route_id: transferTarget.route_id }
            : transferTarget?.address
              ? { address: transferTarget.address }
              : { to_account_id: transferTarget?.to_account_id }
          : kind === "redemption"
            ? { beneficiary_id: selectedDestination }
            : {}),
      };
      return api<Operation>(
        `/api/${kind === "transfer" ? "transfers" : kind === "redemption" ? "redemptions" : "deposits"}`,
        body,
      );
    },
    onSuccess: async (result) => {
      app.setAccount(account);
      app.notify("Request created. Here is what happens next.");
      await refreshData();
      app.setDialog({ type: "operation", id: result.id });
    },
  });
  return (
    <Modal
      title={kind === "transfer" ? "Send on-chain" : human(kind)}
      description={
        kind === "deposit"
          ? "Turn a bank deposit into tokens in this wallet."
          : kind === "redemption"
            ? "Turn tokens back into money in a bank account."
            : "Pay another account. A second person approves before it is sent."
      }
      close={() => app.setDialog(null)}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          mutation.mutate();
        }}
      >
        <div className="dialog-body">
          <div className="form-context">
            {kind === "deposit"
              ? app.data.deposit_issuance === "automatic"
                ? "Once the bank confirms the deposit arrived, three independent institutions approve and the tokens are issued automatically."
                : "After the bank confirms the deposit, a second person and three independent institutions approve before tokens are issued."
              : kind === "redemption"
                ? "Tokens are locked while the bank pays out, then destroyed once the payment is confirmed. A second person and three institutions approve first."
                : transferNeedsInstitutions(
                      app.data.transfer_institution_approval,
                      Math.round(Number(amount || 0) * 100),
                    )
                  ? "A second person and three independent institutions approve before the payment is sent."
                  : "A second person at your company approves before the payment is sent."}
          </div>
          <Field
            label={kind === "deposit" ? "Add tokens to" : "From wallet account"}
          >
            <select
              name="account_id"
              aria-label="Wallet account"
              data-testid="account"
              value={account}
              required
              onChange={(e) => {
                const id = e.target.value;
                setAccount(id);
                setDestination("");
                const supported =
                  app.data.accounts.find((a) => a.id === id)?.currencies || [];
                if (!supported.includes(currency))
                  setCurrency(supported[0] || "EUR");
              }}
            >
              {app.data.accounts.map((a) => (
                <option value={a.id} key={a.id}>
                  {a.name}
                </option>
              ))}
            </select>
          </Field>
          <div className="form-grid">
            <Field label="Test currency">
              <select
                name="currency"
                aria-label="Test currency"
                data-testid="currency"
                value={currency}
                required
                onChange={(e) => {
                  setCurrency(e.target.value as Currency);
                  setDestination("");
                }}
              >
                {accountInfo?.currencies.map((c) => (
                  <option key={c} value={c}>
                    Test{c}
                  </option>
                ))}
              </select>
            </Field>
            <Amount value={amount} onChange={setAmount} />
          </div>
          {kind === "transfer" && (
            <TransferDestination
              key={account + ":" + currency}
              account={account}
              currency={currency}
              onChange={setTransferDestination}
            />
          )}
          {kind !== "deposit" && (
            <div className="form-balance-summary" aria-live="polite">
              <span>Available from {accountInfo?.name || account}</span>
              <strong>
                {balance
                  ? money(balance.available_minor) + " Test" + currency
                  : "Balance check unavailable"}
              </strong>
              {balance && (
                <small>
                  Total {money(balance.balance_minor)} · Reserved{" "}
                  {money(balance.balance_minor - balance.available_minor)}
                </small>
              )}
            </div>
          )}
          {exceedsAvailable && (
            <p className="field-error" role="alert">
              This amount exceeds the currently available balance. The server
              checks the latest balance before accepting a request.
            </p>
          )}

          {kind === "redemption" && (
            <Field
              label="To bank account"
              detail="Bank account details are held on the server and bound by their reference hash."
            >
              <select
                name="beneficiary_id"
                aria-label="Destination"
                data-testid="beneficiary"
                required
                value={selectedDestination}
                onChange={(e) => setDestination(e.target.value)}
              >
                <option value="">Choose a configured destination</option>
                {destinations.map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.name}
                  </option>
                ))}
              </select>
            </Field>
          )}
          {kind === "redemption" && !destinations.length && (
            <div className="inline-warning">
              No eligible destination is configured for this account and
              currency.
            </div>
          )}
          <ErrorNote error={mutation.error} />
        </div>
        <Footer>
          <Cancel />
          <Button
            type="submit"
            className="primary"
            data-testid="submit-request"
            disabled={
              mutation.isPending ||
              !accountInfo ||
              !accountInfo.currencies.includes(currency) ||
              (kind === "transfer" && !transferTarget) ||
              (kind === "redemption" && !destinations.length)
            }
          >
            {mutation.isPending
              ? "Submitting…"
              : kind === "deposit"
                ? "Create funding request"
                : kind === "redemption"
                  ? "Request withdrawal"
                  : "Request on-chain transfer"}
          </Button>
        </Footer>
      </form>
    </Modal>
  );
}
function OperationDetail({ id }: { id: string }) {
  const app = useApp();
  const query = useQuery({
    queryKey: ["operation", app.user.id, id],
    queryFn: ({ signal }) =>
      api<Operation>(
        `/api/operations/${encodeURIComponent(id)}`,
        undefined,
        signal,
      ),
    refetchInterval: (q) =>
      SETTLING.includes(q.state.data?.state ?? "") ? 2000 : 30000,
  });
  const op = query.data;
  const actions = op?.allowed_actions || [];
  // Keep balances and lists in step when this request changes state.
  const state = op?.state;
  useEffect(() => {
    if (state) void refreshData();
  }, [state]);
  const bankEvent =
    app.can("simulate_bank") &&
    op &&
    ["awaiting_bank", "bank_pending", "bank_unknown"].includes(op.state);
  const technical: [string, string | undefined][] = op
    ? [
        ["Elements transaction ID", op.txid],
        ["Confidential destination address", op.destination_address],
        ["Approved request hash", op.request_hash],
        ["Destination hash", op.destination_hash],
        ["Bank account reference hash", op.bank_account_ref_hash],
        ["Bank receipt", op.cash_receipt_id],
        ["Asset ID", op.asset_id],
        ["Transaction template hash", op.transaction_template_hash],
      ]
    : [];
  // Evidence entries are newest first; show the timeline oldest first.
  const history = app.data.activity
    .filter((e) => e.operation_id === id)
    .reverse();
  return (
    <Modal title="Request details" close={() => app.setDialog(null)} drawer>
      <div className="dialog-body">
        {query.error && (
          <>
            <ErrorNote error={query.error} />
            <Button onClick={() => query.refetch()}>Try again</Button>
          </>
        )}
        {!op && !query.error && <p role="status">Loading request…</p>}
        {op && (
          <>
            <div className="detail-type">
              {op.kind === "receipt"
                ? "Confirmed on-chain receipt"
                : human(op.kind) + " request"}
            </div>
            <div className="detail-amount number">
              {money(op.amount_minor)} <span>Test{op.currency}</span>
            </div>
            <Badge status={op.state}>
              {op.declined_by === "institutions" ? "Declined" : undefined}
            </Badge>
            {["awaiting_approval", "ready"].includes(op.state) ? (
              op.incoming ? (
                <div className="wallet-request-next">
                  <strong>Incoming payment</strong>
                  <p>
                    The sender is completing their payment approvals. Your
                    wallet will be credited after chain confirmation; you do not
                    need to approve their request.
                  </p>
                </div>
              ) : (
                <ApprovalProgress operation={op} />
              )
            ) : (
              <div className="wallet-request-next">
                <strong>
                  {viewerNextAction(op)
                    ? "Your next action"
                    : "What happens next"}
                </strong>
                <p>{viewerNextAction(op) || nextStep(op)}</p>
                {op.state === "awaiting_bank" && !viewerNextAction(op) && (
                  <DemoNext
                    roles={["bankadmin"]}
                    operation={op.id}
                    guardian={app.guardian}
                    current={app.user.id}
                  />
                )}
              </div>
            )}

            <div className="status-pair">
              <div className="status-box">
                <span>Chain</span>
                <strong>{chainStatus(op)}</strong>
              </div>
              <div className="status-box">
                <span>Bank</span>
                <strong>{bankStatus(op)}</strong>
              </div>
            </div>
            {op.error && !waitingForInstitutions(op) && (
              <div className="inline-warning" role="alert">
                {op.error}
              </div>
            )}
            <div className="detail-section">
              <h3>Request details</h3>
              <CopyField label="Request reference" value={op.id} />
              <KV label="From">{sourceName(op, app)}</KV>
              <KV label="To">{destinationName(op, app)}</KV>
              {op.reference && <KV label="Reference">{op.reference}</KV>}
              <KV label="Created">{date(op.created_at, true)}</KV>
              <details className="wallet-technical">
                <summary>Technical details</summary>
                {technical.map(([label, value]) => (
                  <CopyField key={label} label={label} value={value} />
                ))}
              </details>
            </div>
            {op.kind === "receipt" ? (
              <div className="detail-section">
                <h3>Observed receipt</h3>
                <p>
                  This payment was received directly on-chain and credited after
                  confirmation. No application payment approval was requested
                  for this receipt.
                </p>
              </div>
            ) : ["awaiting_approval", "ready"].includes(op.state) ? null : (
              // While approvals are open, the progress panel above covers this.
              <div className="detail-section">
                <h3>Approvals</h3>
                <KV label="Second-person approval">
                  {op.user_approved ? "Recorded" : "Waiting"}
                </KV>
                <KV label="Institution approvals">
                  <Quorum operation={op} />
                </KV>
                <KV label="Approvals valid until">
                  {date(op.expires_at, true)}
                </KV>
              </div>
            )}
            {history.length > 0 && (
              <div className="detail-section">
                <h3>Request timeline</h3>
                <ol className="detail-timeline">
                  {history.map((e) => (
                    <li key={e.id}>
                      <strong>{human(e.event)}</strong>
                      <span>
                        {e.actor_name || e.actor} · {date(e.created_at, true)}
                      </span>
                    </li>
                  ))}
                </ol>
              </div>
            )}
            {!actions.length && !bankEvent && (
              <p className="small-note">
                No action is currently available to your account for this
                request.
              </p>
            )}
          </>
        )}
      </div>
      {op && (
        <Footer>
          {bankEvent && (
            <Button
              data-testid="bank-credit"
              onClick={() => app.setDialog({ type: "bank", operation: op })}
            >
              {op.state === "awaiting_bank"
                ? "Confirm bank deposit"
                : "Record bank event"}
            </Button>
          )}
          <Button
            onClick={() =>
              download(
                JSON.stringify(
                  {
                    document: "Concord local sandbox settlement record",
                    warning:
                      "Simulated bank reserves. This is not proof of a real bank payment or legal redemption promise.",
                    exported_at: new Date().toISOString(),
                    viewer: app.user.id,
                    operation: op,
                  },
                  null,
                  2,
                ),
                `concord-${safeFilename(op.id)}.json`,
              )
            }
          >
            Receipt
          </Button>
          {actions
            .filter((action) => action in REVIEW)
            // Settling requests finish on their own; "execute" is only a retry.
            .filter(
              (action) =>
                action !== "execute" ||
                !SETTLING.includes(op.state) ||
                retryable(op),
            )
            // While approvals are open, ApprovalProgress shows these actions.
            .filter(
              (action) =>
                !["awaiting_approval", "ready"].includes(op.state) ||
                !["approve", "guardian-approve", "execute"].includes(action),
            )
            .map((action) => (
              <Button
                key={action}
                className={action === "reject" ? "danger" : "primary"}
                data-testid={
                  action === "guardian-approve"
                    ? "guardian-approve"
                    : `${action}-request`
                }
                onClick={() =>
                  app.setDialog({ type: "review", operation: op, action })
                }
              >
                {action === "execute" && !app.guardian
                  ? op.state === "ready"
                    ? "Review and send"
                    : "Continue"
                  : REVIEW[action].open}
              </Button>
            ))}
        </Footer>
      )}
    </Modal>
  );
}
function ReviewForm({
  operation: op,
  action,
}: {
  operation: Operation;
  action: string;
}) {
  const app = useApp();
  const [reason, setReason] = useState("");
  const [checked, setChecked] = useState(false);
  const guardian = action === "guardian-approve";
  const reject = action === "reject";
  const copy = REVIEW[action];
  const mutation = useMutation({
    mutationFn: async () => {
      if (guardian)
        return app.openApproval(op.id, false, op, {
          from: sourceName(op, app),
          to: destinationName(op, app),
        });
      if (action === "approve-send") {
        // Two separate server checks: the approval, then execution.
        const base = `/api/operations/${encodeURIComponent(op.id)}`;
        await api(base + "/approve", {});
        return api(base + "/execute", {});
      }
      return api(
        `/api/operations/${encodeURIComponent(op.id)}/${action}`,
        reject ? { reason } : {},
      );
    },
    onSuccess: async () => {
      if (!guardian) {
        app.notify(copy.done);
        // Return to the request so its progress stays in view.
        app.setDialog({ type: "operation", id: op.id });
        await refreshData();
      }
    },
  });
  return (
    <Modal
      title={copy.title}
      description="Check the amount and destination before you confirm."
      close={() => app.setDialog(null)}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          mutation.mutate();
        }}
      >
        <div className="dialog-body">
          <div className="form-context">
            {guardian
              ? `You sign in ${app.user.institution_id || "your institution"}’s own approval window. This console never sees the institution’s signing key.`
              : copy.context}
          </div>
          <div className="confirmation-summary">
            <span>{human(op.kind)}</span>
            <strong className="number">
              {money(op.amount_minor)} Test{op.currency}
            </strong>
          </div>
          <KV label="From">{sourceName(op, app)}</KV>
          <KV label="To">{destinationName(op, app)}</KV>
          <details className="wallet-technical">
            <summary>Technical details</summary>
            <CopyField
              label="Exact destination"
              value={op.approval_request?.destination || op.destination_address}
            />
            <CopyField label="Destination hash" value={op.destination_hash} />
            <CopyField
              label="Bank account reference hash"
              value={op.bank_account_ref_hash}
            />
            <CopyField label="Bank receipt" value={op.cash_receipt_id} />
            <CopyField label="Asset ID" value={op.asset_id} />
            <CopyField
              label="Transaction template hash"
              value={op.transaction_template_hash}
            />
          </details>
          {reject && (
            <Field label="Reason for rejection">
              <textarea
                name="reason"
                aria-label="Reason for rejection"
                required
                maxLength={500}
                rows={3}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
            </Field>
          )}
          <label className="rotation-review-confirm">
            <input
              type="checkbox"
              required
              checked={checked}
              onChange={(e) => setChecked(e.target.checked)}
              data-testid="confirm-review"
            />
            <span>I have checked the amount and destination.</span>
          </label>
          <ErrorNote error={mutation.error} />
        </div>
        <Footer>
          <Cancel />
          <Button
            type="submit"
            className={reject ? "danger" : "primary"}
            data-testid="confirm-operation"
            disabled={mutation.isPending || !checked}
          >
            {mutation.isPending ? "Submitting…" : copy.confirm}
          </Button>
        </Footer>
      </form>
    </Modal>
  );
}
/** The common case: the bank confirms a funding request's deposit arrived. */
function BankCreditForm({ operation: op }: { operation: Operation }) {
  const app = useApp();
  const mutation = useMutation({
    mutationFn: () =>
      api("/api/bank/events", {
        event_id: `credit-${op.id}`,
        kind: "credit",
        currency: op.currency,
        operation_id: op.id,
        amount: (op.amount_minor / 100).toFixed(2),
      }),
    onSuccess: async () => {
      app.notify(
        op.issues_automatically
          ? "Deposit confirmed. Tokens are issued once three institutions approve."
          : "Bank deposit recorded. The request now needs approvals.",
      );
      app.setDialog({ type: "operation", id: op.id });
      await refreshData();
    },
  });
  return (
    <Modal
      title="Confirm bank deposit"
      description="Record that the money for this funding request arrived."
      close={() => app.setDialog({ type: "operation", id: op.id })}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          mutation.mutate();
        }}
      >
        <div className="dialog-body">
          <div className="confirmation-summary">
            <span>Deposit received</span>
            <strong className="number">
              {money(op.amount_minor)} {op.currency}
            </strong>
          </div>
          <KV label="For">{app.accountName(op.account_id)}</KV>
          <p className="small-note">
            {op.issues_automatically
              ? "Simulated bank: no real money moves. Confirming is the bank’s approval; tokens are issued once three institutions approve."
              : "Simulated bank: no real money moves. Tokens are issued only after a second person and three institutions approve."}
          </p>
          <ErrorNote error={mutation.error} />
        </div>
        <Footer>
          <Cancel />
          <Button
            type="submit"
            className="primary"
            data-testid="confirm-bank-credit"
            disabled={mutation.isPending}
          >
            {mutation.isPending ? "Recording…" : "Confirm deposit"}
          </Button>
        </Footer>
      </form>
    </Modal>
  );
}
function BankForm({ operation }: { operation?: Operation }) {
  const app = useApp();
  const [kind, setKind] = useState(
    operation?.kind === "redemption" ? "payout_result" : "credit",
  );
  const [currency, setCurrency] = useState<Currency>(
    operation?.currency || "EUR",
  );
  const [id, setId] = useState(operation?.id || "");
  const [amount, setAmount] = useState(
    operation ? String(operation.amount_minor / 100) : "",
  );
  const [outcome, setOutcome] = useState("settled");
  const [eventId, setEventId] = useState(`sim-${Date.now()}`);
  const related = ["credit", "payout_result"].includes(kind);
  const options = app.data.operations.filter(
    (op) =>
      ["deposit", "redemption"].includes(op.kind) &&
      (app.guardian ||
        op.account_id === app.account ||
        op.id === operation?.id),
  );
  const mutation = useMutation({
    mutationFn: () =>
      api("/api/bank/events", {
        event_id: eventId,
        kind,
        currency,
        ...(related ? { operation_id: id } : {}),
        ...(kind === "credit" ? { amount } : {}),
        ...(["payout_result", "payout_mode"].includes(kind) ? { outcome } : {}),
      }),
    onSuccess: async () => {
      app.notify("Simulated bank event recorded.");
      app.setDialog(null);
      await refreshData();
    },
  });
  if (!app.can("simulate_bank"))
    return (
      <Modal title="Bank simulator" close={() => app.setDialog(null)}>
        <div className="dialog-body">
          <Empty title="Bank operator access required" />
        </div>
      </Modal>
    );
  return (
    <Modal
      title="Record simulated bank event"
      description="Restricted to the bank simulator operator."
      close={() => app.setDialog(null)}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          mutation.mutate();
        }}
      >
        <div className="dialog-body">
          <div className="form-context">
            This creates auditable local evidence. It does not contact a bank or
            move real funds.
          </div>
          <Field
            label="Unique bank event reference"
            detail="Repeated references are rejected to prevent duplicate credits."
          >
            <input
              name="event_id"
              value={eventId}
              onChange={(e) => setEventId(e.target.value)}
              required
              maxLength={100}
            />
          </Field>
          <Field label="Event type">
            <select
              name="kind"
              value={kind}
              onChange={(e) => {
                setKind(e.target.value);
                setOutcome("settled");
              }}
            >
              {[
                ["credit", "Incoming reserve credit"],
                ["payout_result", "Resolve existing bank payout"],
                ["payout_mode", "Set future simulated payout behavior"],
                ["freeze", "Freeze new issuance and payouts"],
                ["unfreeze", "Unfreeze new issuance and payouts"],
              ].map(([v, l]) => (
                <option key={v} value={v}>
                  {l}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Currency">
            <select
              name="currency"
              value={currency}
              onChange={(e) => setCurrency(e.target.value as Currency)}
            >
              <option value="EUR">TestEUR</option>
              <option value="USD">TestUSD</option>
            </select>
          </Field>
          {related && (
            <Field label="Related settlement request">
              <select
                name="operation_id"
                value={id}
                onChange={(e) => setId(e.target.value)}
                required
              >
                <option value="">Choose request</option>
                {options.map((op) => (
                  <option value={op.id} key={op.id}>
                    {op.id.slice(0, 15)} · {human(op.kind)} ·{" "}
                    {money(op.amount_minor)} Test{op.currency}
                  </option>
                ))}
              </select>
            </Field>
          )}
          {kind === "credit" && <Amount value={amount} onChange={setAmount} />}
          {["payout_result", "payout_mode"].includes(kind) && (
            <Field label="Payout outcome">
              <select
                name="outcome"
                value={outcome}
                onChange={(e) => setOutcome(e.target.value)}
              >
                <option value="settled">Confirmed paid</option>
                <option value="failed">Confirmed not paid</option>
                {kind === "payout_mode" && (
                  <>
                    <option value="pending">Pending</option>
                    <option value="unknown">
                      Unknown — needs reconciliation
                    </option>
                  </>
                )}
              </select>
            </Field>
          )}
          {kind === "payout_mode" && (
            <p className="small-note">
              Future behavior changes affect new payout initiations only.
              Existing unknown payments require a definitive result.
            </p>
          )}
          <ErrorNote error={mutation.error} />
        </div>
        <Footer>
          <Cancel />
          <Button
            type="submit"
            className="primary"
            data-testid="submit-bank-event"
            disabled={mutation.isPending}
          >
            {mutation.isPending ? "Recording…" : "Record event"}
          </Button>
        </Footer>
      </form>
    </Modal>
  );
}
function RotationForm({ action }: { action: string }) {
  const app = useApp();
  const f = app.data.federation;
  const r = f?.rotation;
  const prepare = action === "prepare";
  const approve = action === "guardian-approve";
  const copy = ROTATION[action];
  const permitted = [
    ...(f?.allowed_actions || []),
    ...(r?.allowed_actions || []),
  ].includes(action);
  const mutation = useMutation({
    mutationFn: async () => {
      if (!permitted || (!prepare && !r))
        throw new Error("This handover action is not currently available.");
      // The institution window shows the full manifest it is asked to sign.
      if (approve) return app.openApproval(r!.id, true);
      return api(
        prepare
          ? "/api/federation/prepare"
          : `/api/federation/rotations/${encodeURIComponent(r!.id)}/${action}`,
        {},
      );
    },
    onSuccess: async () => {
      if (!approve) {
        app.notify(
          "Handover action recorded. Inspect its durable stage and readiness evidence.",
        );
        app.setDialog(null);
        await refreshData();
      }
    },
  });
  return (
    <Modal
      title={copy.title}
      description="Membership changes continue on the existing Elements chain."
      close={() => app.setDialog(null)}
    >
      <form
        onSubmit={(e: FormEvent) => {
          e.preventDefault();
          mutation.mutate();
        }}
      >
        <div className="dialog-body">
          <div className="form-context">{copy.context}</div>
          <KV label="Current operators">
            {f?.current.label || "Current membership"}
          </KV>
          <KV label="Incoming operators">
            {f?.incoming?.label || "Set up when the handover is prepared"}
          </KV>
          <CopyField label="Handover request" value={r?.id} />
          <CopyField
            label="Ledger (genesis block)"
            value={app.data.network.genesis_hash}
          />
          {r?.error && <div className="inline-warning">{r.error}</div>}
          <label className="rotation-review-confirm">
            <input
              type="checkbox"
              required
              data-testid="confirm-rotation-review"
            />
            <span>
              I have reviewed the current and incoming operators and understand
              that new requests pause during the handover.
            </span>
          </label>
          <ErrorNote error={mutation.error} />
        </div>
        <Footer>
          <Cancel />
          <Button
            className="primary"
            type="submit"
            data-testid="confirm-rotation-action"
            disabled={!permitted || mutation.isPending}
          >
            {mutation.isPending ? "Submitting…" : copy.confirm}
          </Button>
        </Footer>
      </form>
    </Modal>
  );
}
