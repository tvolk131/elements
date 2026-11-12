import type {
  Account,
  Beneficiary,
  Currency,
  Kind,
  Membership,
  Operation,
} from "./types";
export const human = (value?: string): string =>
  ({
    deposit: "Add funds from bank",
    redemption: "Withdraw to bank",
    transfer: "On-chain transfer",
    refund: "Return to wallet",
    bankadmin: "Bank administrator",
    bankmaker: "Bank payment maker",
    bankapprover: "Bank payment approver",
    corporatemaker: "Corporate payment maker",
    corporateapprover: "Corporate payment approver",
    institutionguardian: "Institution guardian",
    payment_failed: "Bank payout failed",
    refund_requested: "Escrow return requested",
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
export const isPending = (op: Operation) =>
  !["settled", "rejected", "failed", "cancelled"].includes(op.state);
export const isException = (op: Operation) =>
  ["bank_unknown", "failed", "payment_failed"].includes(op.state) || !!op.error;
export const isActiveException = (op: Operation) =>
  !["settled", "rejected", "cancelled"].includes(op.state) && isException(op);
export const needsInstitutionApproval = (op: Operation) =>
  isPending(op) &&
  op.allowed_actions.some((action) =>
    ["guardian-approve", "guardian_approve"].includes(action),
  );
export function requestSummary(op: Operation): string {
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
export function viewerNextAction(op: Operation): string | undefined {
  const actions = op.allowed_actions;
  if (actions.includes("bank-credit"))
    return "Record the matching simulated bank credit before tokens can be issued.";
  if (actions.includes("approve"))
    return "Review the amount and destination, then record your separate user approval.";
  if (needsInstitutionApproval(op))
    return "Review this payment request in your institution’s independent approval window. Your certificate can be provided while other required reviews are pending.";
  if (actions.includes("execute"))
    return op.state === "ready"
      ? "Submit the approved request to the chain. The server checks all current authorizations before execution."
      : "Review the recorded state and continue the next permitted settlement stage.";
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
  if (op.state === "bank_unknown")
    return "The bank payout outcome is unknown. Tokens remain locked; a bank operator must reconcile the result before a payout or refund can be completed.";
  if (op.error && isPending(op))
    return "Review required. An operator must resolve the recorded issue before proceeding.";
  if (op.state === "awaiting_bank")
    return "Next: a bank administrator records the matching simulated bank credit. Tokens have not been issued yet.";
  if (op.state === "awaiting_approval") {
    if (!op.user_approved)
      return "Next: a separate authorized user reviews and approves this request.";
    const remaining = Math.max(
      0,
      op.guardian_threshold - op.guardian_approvals,
    );
    return `Waiting for ${remaining || "the remaining"} institution ${remaining === 1 ? "approval" : "approvals"}.`;
  }
  if (op.state === "ready")
    return "Next: an authorized approver submits the approved request to the chain.";
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
export function thresholdLabel(policy?: Membership) {
  const count =
    policy?.count ?? policy?.guardian_count ?? policy?.members?.length;
  return policy?.threshold !== undefined && count !== undefined
    ? `${policy.threshold} of ${count}`
    : "Not reported";
}
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
