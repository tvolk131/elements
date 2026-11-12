import { useState, type FormEvent, type ReactNode } from "react";
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
  date,
  download,
  eligibleDestinations,
  human,
  money,
  nextStep,
  viewerNextAction,
  safeFilename,
} from "./domain";
import { Quorum, Receive } from "./wallet";
import type { Currency, Kind, Operation } from "./types";

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
        description="Receive a managed transfer from another approved account."
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
    const hold =
      app.data.federation?.hold_reason ||
      app.data.federation?.rotation?.hold_reason ||
      app.data.network.settlement_hold;
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
  if (d.type === "bank") return <BankForm operation={d.operation} />;
  return <RotationForm action={d.action} />;
}
function CreateForm({ kind }: { kind: Exclude<Kind, "refund"> }) {
  const app = useApp();
  const [account, setAccount] = useState(app.account);
  const [currency, setCurrency] = useState<Currency>(
    app.data.accounts.find((a) => a.id === account)?.currencies[0] || "EUR",
  );
  const [amount, setAmount] = useState("");
  const [destination, setDestination] = useState("");
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
          ? { to_account_id: selectedDestination }
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
          ? "Bank → chain · Peg in. Request test tokens after a matching simulated bank credit."
          : kind === "redemption"
            ? "Chain → bank · Peg out. Request a simulated bank payout from your token balance."
            : "Wallet → wallet. This transfer stays on the chain and requires approvals."
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
            <strong>Sandbox issuer (legal entity undecided)</strong>
            <br />
            {kind === "deposit"
              ? "A bank administrator records a matching simulated credit using this request reference and amount. A separate user and the institution quorum must approve before test tokens are issued on-chain. Do not send real money."
              : kind === "redemption"
                ? "Tokens are held for redemption before a simulated bank payout. An unknown bank result remains pending reconciliation."
                : "This pilot requires a separate authorized user and an institution quorum before the application executes a transfer. This is application policy, separate from threshold unblinding."}
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
                  {a.name} · {a.tenant}
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

          {kind !== "deposit" && (
            <Field
              label={
                kind === "transfer" ? "To on-chain account" : "To bank account"
              }
              detail={
                kind === "transfer"
                  ? "Sending to arbitrary wallet addresses is not supported in this pilot."
                  : "Bank account details are held on the server and bound by their reference hash."
              }
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
          {kind !== "deposit" && !destinations.length && (
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
              (kind !== "deposit" && !destinations.length)
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
    refetchInterval: 30000,
  });
  const op = query.data;
  const actions = op?.allowed_actions || [];
  const bankEvent =
    app.can("simulate_bank") &&
    op &&
    ["awaiting_bank", "bank_pending", "bank_unknown"].includes(op.state);
  const technical: [string, string | undefined][] = op
    ? [
        ["Bound destination hash", op.destination_hash],
        ["Bank destination reference hash", op.bank_account_ref_hash],
        ["Simulated cash receipt / original redemption", op.cash_receipt_id],
        ["Native asset ID", op.asset_id],
        ["Bound transaction template hash", op.transaction_template_hash],
        ["Elements transaction ID", op.txid],
      ]
    : [];
  const chain =
    op?.chain_status ||
    (op?.txid
      ? [
          "settled",
          "escrow_confirmed",
          "bank_pending",
          "bank_unknown",
          "payment_failed",
          "refund_requested",
          "cancelled",
        ].includes(op.state)
        ? "Confirmed transaction"
        : "Awaiting chain confirmation"
      : "Not submitted");
  const bank =
    op?.bank_status ||
    (op?.kind === "transfer"
      ? "Not applicable"
      : op?.state === "awaiting_bank"
        ? "Awaiting bank credit"
        : op?.state === "bank_unknown"
          ? "Unknown · reconcile"
          : op?.state === "bank_pending"
            ? "Payout pending"
            : op?.state === "payment_failed"
              ? "Confirmed not paid"
              : op?.state === "cancelled"
                ? "Cancelled · escrow returned"
                : op?.state === "settled"
                  ? "Bank evidence recorded"
                  : "Not confirmed");
  const history = op?.history || op?.events || [];
  return (
    <Modal
      title="Settlement request"
      description="Review exact amounts, assets and destination before approving."
      close={() => app.setDialog(null)}
      drawer
    >
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
            <div className="wallet-request-next">
              <strong>
                {viewerNextAction(op)
                  ? "Your next action"
                  : "What happens next"}
              </strong>
              <p>{viewerNextAction(op) || nextStep(op)}</p>
              {viewerNextAction(op) && op.state === "awaiting_approval" && (
                <div className="approval-requirements">
                  <span>
                    User review: {op.user_approved ? "recorded" : "pending"}
                  </span>
                  <span>
                    Institution certificates: {op.guardian_approvals} /{" "}
                    {op.guardian_threshold}
                  </span>
                  <small>
                    Both requirements must be complete before the request can be
                    submitted.
                  </small>
                </div>
              )}
            </div>
            <div className="detail-type">{human(op.kind)} request</div>
            <div className="detail-amount number">
              {money(op.amount_minor)} <span>Test{op.currency}</span>
            </div>
            <Badge status={op.state} />
            <div className="status-pair">
              <div className="status-box">
                <span>ELEMENTS CHAIN</span>
                <strong>{human(chain)}</strong>
              </div>
              <div className="status-box">
                <span>SIMULATED BANK</span>
                <strong>{human(bank)}</strong>
              </div>
            </div>
            {op.error && (
              <div className="inline-warning" role="alert">
                {op.error}
              </div>
            )}
            <div className="detail-section">
              <h3>Request details</h3>
              <CopyField label="Request reference" value={op.id} />
              <KV label="Source account">{app.accountName(op.account_id)}</KV>
              <KV label="Tenant / customer">{op.tenant}</KV>
              <KV label="Destination">
                {op.kind === "transfer"
                  ? app.accountName(op.to_account_id)
                  : ["deposit", "refund"].includes(op.kind)
                    ? app.accountName(op.account_id)
                    : op.beneficiary_name ||
                      app.data.beneficiaries.find(
                        (b) => b.id === op.beneficiary_id,
                      )?.name ||
                      "Configured bank account"}
              </KV>
              {app.guardian && (
                <CopyField
                  label="Exact destination bound for approval"
                  value={op.approval_request?.destination}
                />
              )}
              <KV label="Issuer">
                {op.issuer || "Sandbox issuer (legal entity undecided)"}
              </KV>
              <KV label="Reference">{op.reference || "—"}</KV>
              <KV label="Created">{date(op.created_at, true)}</KV>
              <details className="wallet-technical">
                <summary>Technical transaction details</summary>
                {technical.map(([label, value]) => (
                  <CopyField key={label} label={label} value={value} />
                ))}
              </details>
            </div>
            <div className="detail-section">
              <h3>Authorization</h3>
              <KV label="Separate user approval">
                {op.user_approved ? "Recorded" : "Awaiting authorized approver"}
              </KV>
              <KV label="Institution certificate quorum">
                <Quorum operation={op} />
              </KV>
              <CopyField label="Bound request hash" value={op.request_hash} />
              <KV label="Approval expiry">{date(op.expires_at, true)}</KV>
              <p className="small-note">
                Institution payment approval is separate from block signing and
                threshold unblinding. Private approval credentials stay in the
                institution’s own window.
              </p>
            </div>
            {history.length > 0 && (
              <div className="detail-section">
                <h3>Request timeline</h3>
                <ol className="detail-timeline">
                  {history.map((e, i) => (
                    <li key={i}>
                      <strong>
                        {e.description || human(e.action || e.event || e.state)}
                      </strong>
                      <span>
                        {e.actor} · {date(e.created_at || e.timestamp, true)}
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
              Record bank event
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
            .filter((a) =>
              [
                "approve",
                "guardian-approve",
                "execute",
                "reject",
                "cancel",
              ].includes(a),
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
                {action === "approve"
                  ? "Approve request"
                  : action === "guardian-approve"
                    ? "Review institution approval"
                    : action === "execute"
                      ? app.guardian
                        ? "Execute next stage"
                        : op.state === "ready"
                          ? "Submit to chain"
                          : "Continue request"
                      : action === "cancel"
                        ? "Request escrow return"
                        : "Reject"}
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
  const guardian = action === "guardian-approve";
  const reject = action === "reject";
  const title = reject
    ? "Reject settlement request"
    : guardian
      ? "Institution approval"
      : action === "execute"
        ? "Execute next settlement stage"
        : action === "cancel"
          ? "Request escrow return"
          : "Approve settlement request";
  const mutation = useMutation({
    mutationFn: async () => {
      if (guardian) return app.openApproval(op.id, false, op);
      return api(`/api/operations/${encodeURIComponent(op.id)}/${action}`, {
        reason,
        note: reason,
      });
    },
    onSuccess: async () => {
      if (!guardian) {
        app.notify(
          reject
            ? "Request rejected with an attributable reason."
            : "Request action recorded. Check its bank and chain status.",
        );
        app.setDialog(null);
        await refreshData();
      }
    },
  });
  return (
    <Modal
      title={title}
      description="Review the request exactly as it is bound for authorization."
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
              ? `Continue in ${app.user.institution_id || "your institution"}’s independent approval window. This console never receives the institution passphrase or signing key.`
              : reject
                ? "Rejection records your identity and reason. The server checks the current state."
                : action === "cancel"
                  ? "Only a definitive failed bank payout can create a new return request. Separate approval and institution quorum are required."
                  : "The server checks the current state, exact authorization and permitted next stage. A user approval does not establish an institution quorum or bank payout."}
          </div>
          <div className="confirmation-summary">
            <span>{human(op.kind)}</span>
            <strong className="number">
              {money(op.amount_minor)} Test{op.currency}
            </strong>
          </div>
          <KV label="Source">{app.accountName(op.account_id)}</KV>
          <KV label="Destination">
            {op.approval_request?.destination ||
              op.destination ||
              op.to_account_id}
          </KV>
          <CopyField
            label="Bound destination hash"
            value={op.destination_hash}
          />
          <CopyField
            label="Bank reference hash"
            value={op.bank_account_ref_hash}
          />
          <CopyField
            label="Cash receipt / original redemption"
            value={op.cash_receipt_id}
          />
          <CopyField label="Native asset ID" value={op.asset_id} />
          <CopyField
            label="Transaction template hash"
            value={op.transaction_template_hash}
          />
          <Field
            label={reject ? "Reason for rejection" : "Review note (optional)"}
          >
            <textarea
              name="reason"
              aria-label={reject ? "Reason for rejection" : "Review note"}
              required={reject}
              maxLength={500}
              rows={3}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
          </Field>
          <label className="rotation-review-confirm">
            <input type="checkbox" required data-testid="confirm-review" />
            <span>
              I have reviewed the exact amount, test currency, asset and
              destination for this request.
            </span>
          </label>
          <ErrorNote error={mutation.error} />
        </div>
        <Footer>
          <Cancel />
          <Button
            type="submit"
            className={reject ? "danger" : "primary"}
            data-testid="confirm-operation"
            disabled={mutation.isPending}
          >
            {mutation.isPending
              ? "Submitting…"
              : reject
                ? "Confirm rejection"
                : guardian
                  ? "Open institution approval"
                  : action === "execute"
                    ? "Execute next stage"
                    : action === "cancel"
                      ? "Create escrow-return request"
                      : "Confirm approval"}
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
  const f = app.data.federation || {};
  const r = f.rotation;
  const prepare = action === "prepare";
  const approve = action === "approve";
  const allowed = [...(f.allowed_actions || []), ...(r?.allowed_actions || [])];
  const permitted = approve
    ? allowed.some((a) =>
        ["approve", "guardian-approve", "guardian_approve"].includes(a),
      )
    : allowed.includes(action);
  const mutation = useMutation({
    mutationFn: async () => {
      if (!permitted || (!prepare && !r))
        throw new Error("This handover action is not currently available.");
      if (approve)
        return app.openApproval(r!.id, true, {
          amount_minor: 0,
          currency: "",
          manifest_hash: r!.manifest_hash || r!.plan_hash || r!.payload_hash,
        });
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
      title={
        prepare
          ? "Prepare the next federation membership"
          : approve
            ? "Review federation authorization"
            : action === "retry"
              ? "Retry the recorded handover stage"
              : "Advance the federation handover"
      }
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
          <div className="form-context">
            {prepare
              ? "The coordinator prepares the incoming membership, readiness evidence and authority inventory. New requests may be held. Institutions authorize the exact manifest separately."
              : approve
                ? "Review the complete source and target policies, audit readiness binding and migration templates in your institution’s separate window."
                : "The coordinator performs only the next permitted durable stage. Retries use the recorded handover and transaction bytes."}
          </div>
          <KV label="Source membership">
            {f.current?.label || f.current?.id || "Current membership"}
          </KV>
          <KV label="Incoming membership">
            {f.incoming?.label ||
              f.incoming?.id ||
              "Prepared incoming membership"}
          </KV>
          <CopyField label="Handover request" value={r?.id} />
          <CopyField
            label="Existing chain genesis"
            value={f.genesis_hash || app.data.network.genesis_hash}
          />
          <CopyField
            label="Prepared manifest binding"
            value={r?.manifest_hash || r?.plan_hash || r?.payload_hash}
          />
          {r?.error && <div className="inline-warning">{r.error}</div>}
          <label className="rotation-review-confirm">
            <input
              type="checkbox"
              required
              data-testid="confirm-rotation-review"
            />
            <span>
              I have reviewed the source, incoming membership, migration scope
              and current stage. Preparing records a staged change to signing,
              recovery and treasury membership.
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
            {mutation.isPending
              ? "Submitting…"
              : prepare
                ? "Prepare handover"
                : approve
                  ? "Open institution approval"
                  : action === "retry"
                    ? "Retry recorded stage"
                    : "Advance handover"}
          </Button>
        </Footer>
      </form>
    </Modal>
  );
}
