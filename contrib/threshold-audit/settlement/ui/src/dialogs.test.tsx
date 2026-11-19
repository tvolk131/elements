import { beforeEach, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Dialogs } from "./dialogs";
import { api } from "./api";
import type { DialogState } from "./types";
const app = vi.hoisted(() => ({
  account: "a",
  guardian: false,
  user: { id: "maker", institution_id: "i" },
  data: {
    accounts: [
      {
        id: "a",
        name: "Operating",
        tenant: "acme",
        currencies: ["EUR", "USD"],
      },
      { id: "b", name: "Treasury", tenant: "acme", currencies: ["EUR", "USD"] },
    ],
    beneficiaries: [
      {
        id: "eur",
        name: "EUR bank",
        kind: "bank",
        account_id: "a",
        currency: "EUR",
      },
      {
        id: "usd",
        name: "USD bank",
        kind: "bank",
        account_id: "a",
        currency: "USD",
      },
    ],
    balances: [
      {
        account_id: "a",
        currency: "EUR",
        balance_minor: 37977,
        available_minor: 15977,
      },
      {
        account_id: "a",
        currency: "USD",
        balance_minor: 25200,
        available_minor: 25200,
      },
      {
        account_id: "b",
        currency: "EUR",
        balance_minor: 123,
        available_minor: 123,
      },
    ],
    operations: [],
    network: {},
    federation: undefined,
  },
  dialog: null as DialogState,
  can: vi.fn(() => true),
  setAccount: vi.fn(),
  setDialog: vi.fn(),
  notify: vi.fn(),
}));
vi.mock("./context", () => ({ useApp: () => app }));
vi.mock("./api", async (original) => ({
  ...(await original<typeof import("./api")>()),
  api: vi.fn(),
  refreshData: vi.fn().mockResolvedValue(undefined),
}));
beforeEach(() => {
  vi.clearAllMocks();
  app.account = "a";
  app.can.mockReturnValue(true);
  app.dialog = null;
});
function show() {
  render(
    <QueryClientProvider
      client={
        new QueryClient({
          defaultOptions: {
            queries: { retry: false },
            mutations: { retry: false },
          },
        })
      }
    >
      <Dialogs />
    </QueryClientProvider>,
  );
}
it("explains the corporate funding role without sending a request", () => {
  app.can.mockReturnValue(false);
  app.dialog = { type: "create", kind: "deposit" };
  show();
  expect(
    screen.getByText(/bank payment maker or bank administrator/),
  ).toBeVisible();
  expect(api).not.toHaveBeenCalled();
});
it("offers a beneficiary reference and confidential receiving address", () => {
  app.dialog = { type: "receive" };
  show();
  expect(
    screen.getByRole("button", { name: "Generate receiving address" }),
  ).toBeVisible();
  expect(screen.getByText("a", { selector: "code" })).toBeVisible();
});
it("uses the selected source account and opens the created request", async () => {
  app.account = "b";
  app.dialog = { type: "create", kind: "transfer" };
  vi.mocked(api).mockResolvedValue({ id: "created-case" });
  show();
  expect(screen.getByLabelText("From wallet account")).toHaveValue("b");
  await userEvent.type(screen.getByLabelText("Amount"), "1.23");
  await userEvent.selectOptions(screen.getByLabelText("To account"), "a");
  await userEvent.click(screen.getByTestId("submit-request"));
  await waitFor(() =>
    expect(api).toHaveBeenCalledWith("/api/transfers", {
      account_id: "b",
      currency: "EUR",
      amount: "1.23",
      to_account_id: "a",
    }),
  );
  await waitFor(() =>
    expect(app.setDialog).toHaveBeenCalledWith({
      type: "operation",
      id: "created-case",
    }),
  );
});
it("changes bank destinations when the asset changes", async () => {
  app.dialog = { type: "create", kind: "redemption" };
  show();
  expect(screen.getByRole("option", { name: "EUR bank" })).toBeInTheDocument();
  await userEvent.selectOptions(screen.getByLabelText("Token"), "USD");
  expect(
    screen.queryByRole("option", { name: "EUR bank" }),
  ).not.toBeInTheDocument();
  expect(screen.getByRole("option", { name: "USD bank" })).toBeInTheDocument();
});

it("keeps the available amount tied to the source and currency", async () => {
  app.dialog = { type: "create", kind: "transfer" };
  show();
  expect(screen.getByText("159.77 UNITED EUR")).toBeVisible();
  await userEvent.selectOptions(screen.getByLabelText("Token"), "USD");
  expect(screen.getByText("252.00 UNITED USD")).toBeVisible();
  await userEvent.selectOptions(
    screen.getByLabelText("From wallet account"),
    "b",
  );
  await userEvent.selectOptions(screen.getByLabelText("Token"), "EUR");
  expect(screen.getByText("1.23 UNITED EUR")).toBeVisible();
});

it("displays an observed outside receipt as a credit without missing application approvals", async () => {
  const { OperationPanel } = await import("./wallet");
  const operation = {
    id: "receipt",
    kind: "receipt" as const,
    state: "settled",
    account_id: "a",
    currency: "EUR" as const,
    amount_minor: 1,
    created_at: 1,
    user_approved: false,
    guardian_approvals: 0,
    guardian_threshold: 3,
    allowed_actions: [],
  };
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <OperationPanel title="Transactions" operations={[operation]} />
    </QueryClientProvider>,
  );
  expect(screen.getByText("+0.01")).toBeVisible();
  expect(
    screen.getByText("Confirmed", { selector: ".wallet-next-summary" }),
  ).toBeVisible();
  expect(screen.queryByText("0 / 3")).not.toBeInTheDocument();
  client.clear();
});
it("says a customer payment needs no sign-off but is still checked", async () => {
  const { Quorum } = await import("./wallet");
  const payment = {
    id: "p",
    kind: "transfer" as const,
    state: "preparing",
    account_id: "a",
    currency: "EUR" as const,
    amount_minor: 1,
    created_at: 1,
    user_approved: true,
    guardian_approvals: 0,
    guardian_threshold: 0,
    allowed_actions: [],
  };
  const { rerender } = render(<Quorum operation={payment} />);
  expect(screen.getByText("No sign-off; checked automatically")).toBeVisible();
  rerender(
    <Quorum
      operation={{ ...payment, state: "rejected", declined_by: "institutions" }}
    />,
  );
  expect(screen.getByText("Declined automatically")).toBeVisible();
});
it("shows a regulator's quarantine and return in the holder's own history", async () => {
  const { OperationPanel } = await import("./wallet");
  const base = {
    state: "settled",
    account_id: "a",
    currency: "EUR" as const,
    amount_minor: 1275000,
    user_approved: false,
    guardian_approvals: 0,
    guardian_threshold: 5,
    allowed_actions: [],
    authority: "Financial Regulator",
    case_reference: "case-7",
  };
  const moved = {
    ...base,
    id: "moved",
    kind: "quarantine" as const,
    created_at: 2,
    recovery_order: "q1",
    source_name: "Operating",
    reference: "Moved to quarantine by regulator order (case-7)",
  };
  const returned = {
    ...base,
    id: "returned",
    kind: "receipt" as const,
    created_at: 3,
    recovery_order: "r1",
    reference: "Returned from quarantine by regulator order (case-7)",
  };
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <OperationPanel title="Transactions" operations={[moved, returned]} />
    </QueryClientProvider>,
  );
  expect(
    screen.getByText("Moved to quarantine · Financial Regulator order"),
  ).toBeVisible();
  expect(
    screen.getByText("Returned from quarantine · Financial Regulator order"),
  ).toBeVisible();
  expect(screen.getByText("−12,750.00")).toBeVisible();
  expect(screen.getByText("+12,750.00")).toBeVisible();
  client.clear();

  Object.assign(app.data, {
    activity: [
      {
        id: 1,
        created_at: 2,
        operation_id: "moved",
        actor: "federation",
        actor_name: "The operators, automatically",
        event: "funds_quarantined",
        entry_hash: "x",
      },
    ],
  });
  vi.mocked(api).mockResolvedValue(moved);
  app.dialog = { type: "operation", id: "moved" };
  show();
  expect(
    await screen.findByText("Moved to quarantine", {
      selector: ".detail-type",
    }),
  ).toBeVisible();
  const record = screen.getByTestId("recovery-record");
  expect(record).toHaveTextContent("moved out of this account without its key");
  expect(record).toHaveTextContent("AuthorityFinancial Regulator");
  expect(record).toHaveTextContent("Casecase-7");
  expect(
    screen.getByText("Moved to quarantine by the operators"),
  ).toBeVisible();
  expect(screen.getByText(/^Held in quarantine\./)).toBeVisible();
  expect(screen.getByText("Not applicable")).toBeVisible();
});
