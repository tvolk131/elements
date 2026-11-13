import { beforeEach, expect, it, vi } from "vitest";
import { render as baseRender, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactElement } from "react";
import userEvent from "@testing-library/user-event";
import { ApprovalProgress } from "./approval-progress";
import type { Operation } from "./types";
// Demo-only helpers query the (absent) persona list; give them a client.
const render = (ui: ReactElement) =>
  baseRender(
    <QueryClientProvider client={new QueryClient()}>{ui}</QueryClientProvider>,
  );
const app = vi.hoisted(() => ({
  user: { id: "bank-maker", name: "Bank Maker" },
  accountName: () => "Acme · Operating",
  setDialog: vi.fn(),
  can: (permission: string) => permission === "execute",
  data: {
    guardians: [
      { id: "c1", name: "Institution C1" },
      { id: "c2", name: "Institution C2" },
      { id: "c3", name: "Institution C3" },
      { id: "c4", name: "Institution C4" },
      { id: "c5", name: "Institution C5" },
    ],
  },
}));
vi.mock("./context", () => ({ useApp: () => app }));
function operation(values: Partial<Operation> = {}): Operation {
  return {
    id: "request",
    kind: "transfer",
    state: "awaiting_approval",
    account_id: "acme-main",
    currency: "EUR",
    amount_minor: 12000,
    created_at: 1,
    user_approved: false,
    guardian_approvals: 0,
    guardian_threshold: 3,
    allowed_actions: [],
    approval_workflow: {
      maker: { id: "bank-maker", name: "Bank Maker", role: "bankmaker" },
      user_reviewers: [
        { id: "bank-approver", name: "Bank Approver", role: "bankapprover" },
        {
          id: "acme-approver",
          name: "Acme Approver",
          role: "corporateapprover",
        },
      ],
      submitters: [
        { id: "bank-approver", name: "Bank Approver", role: "bankapprover" },
      ],
      institution_ids: ["c1", "c2", "c3", "c4", "c5"],
      required_institutions: 3,
      approved_institution_ids: [],
    },
    ...values,
  };
}
beforeEach(() => {
  app.user = { id: "bank-maker", name: "Bank Maker" };
  app.setDialog.mockClear();
});
it("explains every missing requirement to the maker and does not offer self approval", () => {
  render(<ApprovalProgress operation={operation()} />);
  expect(screen.getByText(/It has not been transferred yet/)).toBeVisible();
  expect(screen.getByText(/You cannot approve your own request/)).toBeVisible();
  expect(screen.getAllByText("Acme Approver")[0]).toBeVisible();
  expect(screen.getByText("0 of 3 recorded")).toBeVisible();
  expect(screen.getByText(/of the 5/)).toBeVisible();
  expect(screen.getByText(/does not happen automatically/)).toBeVisible();
  expect(
    screen.queryByRole("button", { name: "Review and approve" }),
  ).not.toBeInTheDocument();
  expect(app.setDialog).not.toHaveBeenCalled();
});
it("opens a separate review for an eligible approver without approving anything", async () => {
  app.user = { id: "bank-approver", name: "Bank Approver" };
  const op = operation({ allowed_actions: ["approve", "reject"] });
  render(<ApprovalProgress operation={op} />);
  await userEvent.click(
    screen.getByRole("button", { name: "Review and approve" }),
  );
  expect(app.setDialog).toHaveBeenCalledWith({
    type: "review",
    operation: op,
    action: "approve",
  });
});
it("keeps chain submission unavailable while institutions still need to approve", () => {
  app.user = { id: "bank-approver", name: "Bank Approver" };
  render(
    <ApprovalProgress
      operation={operation({
        user_approved: true,
        guardian_approvals: 2,
        allowed_actions: [],
      })}
    />,
  );
  expect(screen.getByText("2 of 3 recorded")).toBeVisible();
  expect(
    screen.queryByRole("button", { name: "Review and send" }),
  ).not.toBeInTheDocument();
});
it("offers a submission review only after the server says it is ready", async () => {
  app.user = { id: "bank-approver", name: "Bank Approver" };
  const op = operation({
    state: "ready",
    user_approved: true,
    guardian_approvals: 3,
    allowed_actions: ["execute"],
  });
  render(<ApprovalProgress operation={op} />);
  await userEvent.click(
    screen.getByRole("button", { name: "Review and send" }),
  );
  expect(app.setDialog).toHaveBeenCalledWith({
    type: "review",
    operation: op,
    action: "execute",
  });
});
it("lets the last approver approve and send in one step", async () => {
  app.user = { id: "acme-approver", name: "Acme Approver" };
  const op = operation({
    user_approved: false,
    guardian_approvals: 3,
    allowed_actions: ["approve"],
  });
  render(<ApprovalProgress operation={op} />);
  await userEvent.click(
    screen.getByRole("button", { name: "Review, approve and send" }),
  );
  expect(app.setDialog).toHaveBeenCalledWith({
    type: "review",
    operation: op,
    action: "approve-send",
  });
});
it("leaves out institutions when the payment policy does not need them", async () => {
  app.user = { id: "acme-approver", name: "Acme Approver" };
  const base = operation();
  const op = operation({
    guardian_threshold: 0,
    allowed_actions: ["approve"],
    approval_workflow: { ...base.approval_workflow!, required_institutions: 0 },
  });
  render(<ApprovalProgress operation={op} />);
  expect(screen.queryByText("Institution approvals")).not.toBeInTheDocument();
  expect(screen.getByText(/step 1 approval also sends/)).toBeVisible();
  await userEvent.click(
    screen.getByRole("button", { name: "Review, approve and send" }),
  );
  expect(app.setDialog).toHaveBeenCalledWith({
    type: "review",
    operation: op,
    action: "approve-send",
  });
});
it("shows automatic issuing for a confirmed deposit instead of a Send step", () => {
  app.user = { id: "bank-approver", name: "Bank Approver" };
  render(
    <ApprovalProgress
      operation={operation({
        kind: "deposit",
        user_approved: true,
        guardian_approvals: 1,
        issues_automatically: true,
        allowed_actions: ["execute"],
      })}
    />,
  );
  expect(screen.getByText("Issue tokens")).toBeVisible();
  expect(screen.getByText(/Nobody needs to press Send/)).toBeVisible();
  expect(
    screen.getByText("The bank confirmed the deposit, which is its approval."),
  ).toBeVisible();
  expect(screen.queryByRole("button", { name: /send|issue/i })).toBeNull();
});
