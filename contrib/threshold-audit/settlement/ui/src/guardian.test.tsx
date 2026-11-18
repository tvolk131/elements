import { beforeEach, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { GuardianOverview } from "./guardian";
import type { Operation } from "./types";
const app = vi.hoisted(() => ({
  guardian: true,
  account: "a",
  user: { institution_id: "institution-c-1" },
  refreshing: false,
  can: () => true,
  refresh: vi.fn(),
  setDialog: vi.fn(),
  accountName: (id: string) => id,
  data: {
    network: { height: 100, connected: true },
    guardians: [],
    operations: [] as Operation[],
  },
}));
vi.mock("./context", () => ({ useApp: () => app }));
vi.mock("./navigation", () => ({
  WorkspaceLink: ({ children }: { children: React.ReactNode }) => (
    <a>{children}</a>
  ),
}));
const op = (id: string, values: Partial<Operation>) =>
  ({
    id,
    kind: "transfer",
    account_id: "a",
    currency: "EUR",
    amount_minor: 100,
    state: "awaiting_approval",
    allowed_actions: [],
    user_approved: false,
    guardian_approvals: 0,
    guardian_threshold: 3,
    created_at: 1,
    ...values,
  }) as Operation;
beforeEach(() => {
  app.data.operations = [
    op("needs-this-institution", { allowed_actions: ["guardian-approve"] }),
    op("other-institution", { allowed_actions: [] }),
    op("closed-rejection", { state: "rejected", error: "user rejected" }),
    op("closed-cancellation", { state: "cancelled", error: "escrow returned" }),
  ];
});
it("shows only this operator’s actionable requests in the approval queue", () => {
  render(<GuardianOverview approvals />);
  expect(screen.getAllByTestId("operation-row")).toHaveLength(1);
  expect(screen.getByTestId("operation-row")).toHaveAttribute(
    "data-operation-id",
    "needs-this-institution",
  );
  expect(
    screen.queryByRole("button", { name: "Settled" }),
  ).not.toBeInTheDocument();
});
it("shows a completed queue state while keeping closed outcomes in history", () => {
  app.data.operations = app.data.operations.filter(
    (o) => !o.allowed_actions.length,
  );
  const { unmount } = render(<GuardianOverview approvals />);
  expect(screen.getByText("Your organization is up to date")).toBeVisible();
  unmount();
  render(<GuardianOverview />);
  expect(screen.getAllByTestId("operation-row")).toHaveLength(3);
  expect(
    screen
      .getByText("Unresolved exceptions")
      .closest("article")
      ?.querySelector(".metric-value"),
  ).toHaveTextContent("0");
});
