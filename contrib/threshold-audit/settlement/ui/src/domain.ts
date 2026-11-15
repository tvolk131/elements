import type {
  Account,
  Beneficiary,
  Currency,
  Dashboard,
  Kind,
  Membership,
  Operation,
} from "./types";
export const human = (value?: string): string =>
  ({
    deposit: "Add funds from bank",
    redemption: "Withdraw to bank",
    transfer: "On-chain transfer",
    receipt: "Received on-chain",
    bankcompliance: "Bank compliance",
    federationcompliance: "Federation compliance",
    auditguardian: "Disclosure guardian",
    refund: "Return to wallet",
    bankadmin: "Bank administrator",
    bankmaker: "Bank payment maker",
    bankapprover: "Bank payment approver",
    corporatemaker: "Corporate payment maker",
    corporateapprover: "Corporate payment approver",
    institutionguardian: "Institution guardian",
    awaiting_approval: "Payment approvals needed",
    payment_failed: "Bank payout failed",
    refund_requested: "Escrow return requested",
    // Activity log events.
    operation_created: "Request created",
    user_approved: "Second-person approval",
    institution_approved: "Institution approval",
    operation_rejected: "Request rejected",
    operation_declined: "Declined by the institutions",
    unauthorized_transaction_refused:
      "Ledger refused a transaction without authorization",
    demo_institution_offline: "Demo: institution switched off",
    demo_institution_online: "Demo: institution switched on",
    execution_authorized: "Submitted for settlement",
    issuance_template_bound: "Token issuance prepared",
    credit_receipt_sealed: "Bank deposit confirmed",
    simulated_bank_credit: "Bank deposit received",
    transaction_prepared: "Transaction prepared",
    transaction_confirmed: "Confirmed on chain",
    execution_waiting: "Waiting to continue",
    payment_initiated: "Bank payout started",
    external_receipt_confirmed: "Payment received",
    login: "Signed in",
    disclosure_requested: "Disclosure requested",
    disclosure_approved: "Disclosure approved",
    disclosure_declined: "Disclosure declined",
    disclosure_cancelled: "Disclosure cancelled",
    disclosure_encrypted_release: "Disclosure released to recipient",
    disclosure_recipient_registered: "Recipient key registered",
    refund_requested_after_definite_failure:
      "Return requested after failed payout",
  })[value || ""] ||
  (value || "Not available")
    .replace(/_/g, " ")
    .replace(/^./, (c) => c.toUpperCase());
export const money = (minor?: number) =>
  minor === undefined
    ? "—"
    : new Intl.NumberFormat("en-GB", {
        minimumFractionDigits: 2,
        maximumFractionDigits: 2,
      }).format(minor / 100);
/** Format an on-chain amount (8 decimal places) for a known test currency. */
export function baseUnits(amount: string | number, currency?: Currency) {
  if (!currency) return `${amount} base units`;
  const n = BigInt(amount);
  const fraction = (n % 100000000n).toString().padStart(8, "0");
  // Whole cents read like money; anything finer keeps all eight places.
  const decimals = fraction.endsWith("000000")
    ? fraction.slice(0, 2)
    : fraction;
  return `${(n / 100000000n).toLocaleString("en-GB")}.${decimals} Test${currency}`;
}
export const short = (value?: string, size = 14) =>
  value ? value.slice(0, size) + (value.length > size ? "…" : "") : "—";
export const date = (value?: number | string, full = false) => {
  if (!value) return "—";
  const d = new Date(
    typeof value === "number" && value < 100000000000 ? value * 1000 : value,
  );
  return Number.isNaN(d.getTime())
    ? String(value)
    : new Intl.DateTimeFormat("en-GB", {
        day: "2-digit",
        month: "short",
        timeZone: "UTC",
        ...(full
          ? { year: "numeric", hour: "2-digit", minute: "2-digit" }
          : {}),
      }).format(d) + (full ? " UTC" : "");
};
/** Time of day in UTC, e.g. "18:55 UTC". */
export const clock = (value: number) =>
  new Intl.DateTimeFormat("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    timeZone: "UTC",
  }).format(new Date(value * 1000)) + " UTC";
/** Bank tenant IDs as names: "bank" → "Bank", "bank-b" → "Bank B". */
export const bankName = (id?: string) =>
  (id || "bank")
    .split("-")
    .map((w) =>
      w.length === 1 ? w.toUpperCase() : w[0].toUpperCase() + w.slice(1),
    )
    .join(" ");
/** Whether a new payment of this amount (minor units) needs institutions. */
export function transferNeedsInstitutions(
  policy: Dashboard["transfer_institution_approval"],
  amountMinor: number,
) {
  if (policy === "never") return false;
  if (typeof policy === "object") return amountMinor > policy.above_minor;
  return true;
}
export const isPending = (op: Operation) =>
  !["settled", "rejected", "failed", "cancelled"].includes(op.state);
export const isException = (op: Operation) =>
  ["bank_unknown", "failed", "payment_failed"].includes(op.state) || !!op.error;
export const isActiveException = (op: Operation) =>
  !["settled", "rejected", "cancelled"].includes(op.state) && isException(op);
export const needsInstitutionApproval = (op: Operation) =>
  isPending(op) && op.allowed_actions.includes("guardian-approve");
/** Why new settlement requests are paused, if a federation handover holds them. */
export const settlementHold = (data: Dashboard) =>
  data.federation?.rotation?.hold_reason || undefined;
const SETTLED_ON_CHAIN = [
  "settled",
  "escrow_confirmed",
  "bank_pending",
  "bank_unknown",
  "payment_failed",
  "refund_requested",
  "cancelled",
];
export function chainStatus(op: Operation) {
  if (!op.txid) return "Not submitted";
  return SETTLED_ON_CHAIN.includes(op.state)
    ? "Confirmed transaction"
    : "Awaiting chain confirmation";
}
const BANK_STATUS: Record<string, string> = {
  awaiting_bank: "Awaiting bank credit",
  bank_unknown: "Unknown · reconcile",
  bank_pending: "Payout pending",
  payment_failed: "Confirmed not paid",
  cancelled: "Cancelled · escrow returned",
  settled: "Bank evidence recorded",
};
export function bankStatus(op: Operation) {
  if (op.kind === "transfer") return "Not applicable";
  if (op.kind === "deposit" && op.cash_receipt_id && op.state !== "settled")
    return "Deposit received";
  return BANK_STATUS[op.state] || "Not confirmed";
}
/** Requests waiting on something the signed-in person can do. */
export const needsAction = (op: Operation) =>
  isPending(op) &&
  op.allowed_actions.some((a) =>
    [
      "approve",
      "guardian-approve",
      "execute",
      "bank-credit",
      "cancel",
    ].includes(a),
  ) &&
  !(SETTLING.includes(op.state) && !retryable(op));
export const waitingForInstitutions = (op: Operation) =>
  !!op.error?.startsWith("Waiting for the institutions");
/** A settling request whose recorded error a person can retry. Waiting for
 * the institutions is not one: it continues on its own when they are back. */
export const retryable = (op: Operation) =>
  !!op.error && !waitingForInstitutions(op);
export function requestSummary(op: Operation): string {
  if (op.declined_by === "institutions") return "Declined by the institutions";
  if (waitingForInstitutions(op)) return "Waiting for the institutions";
  if (op.state === "awaiting_approval")
    return !op.user_approved
      ? "Waiting for separate user approval"
      : "Waiting for institution approvals";
  return (
    {
      awaiting_bank: "Waiting for bank credit",
      ready: "Ready to submit",
      preparing: "Preparing transaction",
      chain_pending: "Waiting for chain confirmation",
      bank_pending: "Waiting for bank payout",
      escrow_confirmed: "Tokens locked for payout",
      bank_unknown: "Bank result needs reconciliation",
      burn_pending: "Finishing token burn",
      payment_failed: "Bank payout failed",
      refund_requested: "Return request in progress",
      settled: "Confirmed",
      rejected: "Closed · rejected",
      cancelled: "Closed · cancelled",
      failed: "Review recorded failure",
    }[op.state] || human(op.state)
  );
}
/** States where the server finishes the request on its own. */
export const SETTLING = [
  "preparing",
  "chain_pending",
  "escrow_confirmed",
  "bank_pending",
  "burn_pending",
];
export function viewerNextAction(op: Operation): string | undefined {
  const actions = op.allowed_actions;
  // "Execute" is offered while settling only as a retry after an error.
  if (SETTLING.includes(op.state) && !retryable(op)) return undefined;
  if (actions.includes("bank-credit"))
    return op.issues_automatically
      ? "Confirm the bank deposit arrived. That is the bank’s approval; tokens are issued once three institutions approve."
      : "Record the bank deposit so the tokens can be issued.";
  if (actions.includes("approve"))
    return op.guardian_approvals >= op.guardian_threshold
      ? op.issues_automatically
        ? "The institutions have approved. Your approval is the last one needed; the tokens are then issued."
        : op.guardian_threshold
          ? "The institutions have approved. Your approval is the last one needed: approve and send."
          : "Your approval is the only one needed: approve and send."
      : "Your approval is needed. Check the amount and destination, then approve.";
  if (needsInstitutionApproval(op))
    return "Your institution’s approval is needed. You sign in your institution’s own approval window.";
  if (actions.includes("execute"))
    return op.state === "ready"
      ? "All approvals are in place. Send it to settle."
      : "Continue this request to its next step.";
  if (actions.includes("cancel"))
    return "Review the failed payout and request an approved return of the locked tokens.";
  return undefined;
}
export const forAccount = (ops: Operation[], account: string) =>
  ops.filter((op) => op.account_id === account || op.to_account_id === account);
export function eligibleDestinations(
  kind: Kind,
  accounts: Account[],
  beneficiaries: Beneficiary[],
  account: string,
  currency: Currency,
) {
  return kind === "transfer"
    ? accounts
        .filter((a) => a.id !== account && a.currencies.includes(currency))
        .map((a) => ({ id: a.id, name: a.name }))
    : beneficiaries.filter(
        (b) =>
          b.kind === "bank" &&
          b.account_id === account &&
          (!b.currency || b.currency === currency),
      );
}
export function nextStep(op: Operation): string {
  if (waitingForInstitutions(op)) {
    const counts = op.error?.split(": ")[1];
    return `Waiting for the institutions to authorize it${counts ? ` (${counts})` : ""}. It goes through on its own as soon as enough of them are back; nobody needs to do anything.`;
  }
  if (op.declined_by === "institutions")
    return "The institutions declined this payment, so nothing was sent and the reserved funds were released.";
  if (op.state === "bank_unknown")
    return "The bank payout outcome is unknown. Tokens remain locked; a bank operator must reconcile the result before a payout or refund can be completed.";
  if (op.error && isPending(op))
    return "Review required. An operator must resolve the recorded issue before proceeding.";
  if (op.state === "awaiting_bank")
    return op.issues_automatically
      ? "Next: the bank confirms the deposit arrived. Tokens are then issued as soon as three institutions approve."
      : "Next: a bank administrator records the matching simulated bank credit. Tokens have not been issued yet.";
  if (op.state === "awaiting_approval") {
    if (!op.user_approved) {
      const reviewers = op.approval_workflow?.user_reviewers
        .map((actor) => actor.name)
        .join(" or ");
      return `Waiting for ${reviewers || "a bank or corporate payment approver"} to perform the second-person check.${op.guardian_threshold ? " Institution approvals are also required before it is sent." : ""}`;
    }
    const remaining = Math.max(
      0,
      op.guardian_threshold - op.guardian_approvals,
    );
    return `Waiting for ${remaining || "the remaining"} institution ${remaining === 1 ? "approval" : "approvals"}.${op.issues_automatically ? " Tokens are issued as soon as they are in." : ""}`;
  }
  if (op.state === "ready")
    return op.issues_automatically
      ? "All approvals are in place, but issuing did not start automatically. An approver can issue it."
      : "All approvals are in place. An approver sends it to settle.";
  if (op.state === "preparing")
    return "The transaction is being prepared. It has not been confirmed; an authorized operator can retry the recorded request if needed.";
  if (op.state === "chain_pending")
    return "The transaction has been submitted. Waiting for on-chain confirmation.";
  if (["bank_pending", "escrow_confirmed"].includes(op.state))
    return "Waiting for the bank payout result. Tokens remain locked.";
  if (op.state === "burn_pending")
    return "The bank payout is confirmed. Waiting for the on-chain token burn to finish.";
  if (op.state === "payment_failed")
    return "The bank payout failed. A new approved return request is required to unlock the tokens.";
  if (op.state === "refund_requested")
    return "Waiting for approval and execution of the return-to-wallet request.";
  if (op.state === "settled")
    return op.kind === "redemption"
      ? "Complete: the simulated bank payout and on-chain token burn are confirmed."
      : "Complete: the on-chain transaction is confirmed.";
  if (!isPending(op))
    return "This request is closed. Review its recorded outcome before creating another.";
  return "Review this request for its current stage and available actions.";
}
export const thresholdLabel = (policy?: Membership) =>
  policy ? `${policy.threshold} of ${policy.count}` : "Not reported";
export function csv(rows: unknown[][]) {
  return rows
    .map((row) =>
      row
        .map((v) => {
          let s = String(v ?? "");
          if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
          return '"' + s.replace(/"/g, '""') + '"';
        })
        .join(","),
    )
    .join("\r\n");
}
export function download(
  content: string,
  name: string,
  type = "application/json",
) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export const safeFilename = (s: string) => s.replace(/[^a-zA-Z0-9_-]/g, "");
