import { beforeEach, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { IndependentNode, TheftDrill, type Drill } from "./theft-drill";

const server = vi.hoisted(() => ({
  calls: [] as [string, unknown][],
  node: {} as Record<string, unknown>,
  view: {} as Record<string, unknown>,
}));
vi.mock("./api", () => ({
  api: async (path: string, body?: unknown) => {
    server.calls.push([path, body]);
    if (path === "/api/independent-node") return server.node;
    if (path.startsWith("/api/demo/theft")) return server.view;
    throw new Error("unexpected " + path);
  },
}));

const target = {
  txid: "ab".repeat(32),
  vout: 1,
  account_id: "initech-main",
  account: "Initech · Operating",
  currency: "EUR",
  amount_minor: 1275000,
  case_id: "c".repeat(32),
};
const drill = (values: Partial<Drill> = {}): Drill => ({
  target,
  mule: { address: "el1mule", bank: "another member bank" },
  txid: "cd".repeat(32),
  authorized_until: 320,
  height: 305,
  raw_size: 9000,
  stolen: {
    at: 1,
    height: 300,
    independent_node: { accepted: true, in_mempool: false, reason: null },
  },
  broadcasts: [],
  replays: [],
  thief_transaction: "not_in_mempool",
  output_spent: false,
  frozen: null,
  quarantine: null,
  restore: null,
  ...values,
});

function renderWith(ui: React.ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>{ui}</QueryClientProvider>,
  );
}

beforeEach(() => {
  server.calls = [];
  server.node = {
    available: true,
    height: 410,
    demo_node_height: 410,
    behind: 0,
    same_chain: true,
    peers: 1,
    mempool: 0,
    authorization_rule: true,
  };
  server.view = { drill: null, targets: [target], independent_node: true };
});

it("shows the independent node keeping its own copy of the same ledger", async () => {
  renderWith(<IndependentNode />);
  expect(await screen.findByText("Same ledger")).toBeVisible();
  expect(screen.getByTestId("independent-node")).toHaveTextContent(
    "Its latest block410",
  );
  expect(screen.getByText("Enforced")).toBeVisible();
});

it("says plainly when the runtime runs no independent node", async () => {
  server.node = { available: false };
  renderWith(<IndependentNode />);
  expect(await screen.findByText("Not running")).toBeVisible();
  expect(
    screen.getByText(/every verdict here comes from the demo node/),
  ).toBeVisible();
});

it("steals the chosen output with the customer's key", async () => {
  renderWith(<TheftDrill />);
  const select = await screen.findByTestId("drill-target");
  expect(select).toHaveTextContent(
    "Initech · Operating · 12,750.00 UNITED EUR · regulator has a case",
  );
  server.view = { drill: drill(), targets: [], independent_node: true };
  await userEvent.click(screen.getByTestId("drill-steal"));
  expect(server.calls).toContainEqual([
    "/api/demo/theft/steal",
    { txid: target.txid, vout: 1 },
  ]);
  expect(await screen.findByTestId("drill-stolen")).toHaveTextContent(
    /the independent node would have accepted these bytes\./,
  );
  // Broadcasting before the freeze would simply complete the theft.
  expect(screen.getByTestId("drill-broadcast-button")).toBeDisabled();
  // Before the quarantine the independent node would only say "accepted".
  expect(screen.getByTestId("drill-replay-button")).toBeDisabled();
  expect(screen.getByTestId("drill-freeze")).toHaveTextContent(
    "open the disclosure case for this payment",
  );
});

it("tells the story once the regulator has frozen, quarantined and returned the funds", async () => {
  server.view = {
    drill: drill({
      frozen: { order_id: "f1", applied_by: 7, operators: 7, released: false },
      broadcasts: [
        {
          at: 2,
          height: 330,
          accepted: false,
          reason: "bad-tx-authorization-expired",
          reauthorization: {
            refused: true,
            reason:
              "7 of 7 operators refused to authorize this transaction: funds frozen by order f1",
          },
        },
      ],
      quarantine: { order_id: "q1", state: "confirmed", txid: "ef".repeat(32) },
      replays: [
        {
          at: 3,
          height: 340,
          accepted: false,
          in_mempool: false,
          reason: "missing-inputs",
          output_spent: true,
          submission: "bad-txns-inputs-missingorspent",
          spent_by: { txid: "ef".repeat(32), confirmations: 4 },
        },
      ],
      restore: {
        order_id: "r1",
        state: "confirmed",
        txid: "12".repeat(32),
        destination: "initech-main@bank-b",
      },
      output_spent: true,
    }),
    targets: [],
    independent_node: true,
  };
  renderWith(<TheftDrill />);
  expect(await screen.findByTestId("drill-freeze")).toHaveTextContent(
    "Applied by 7 of 7 operators",
  );
  expect(screen.getByTestId("drill-broadcast")).toHaveTextContent(
    "their authorization from the operators has lapsed",
  );
  expect(screen.getByTestId("drill-broadcast")).toHaveTextContent(
    "a fresh authorization: 7 of 7 refused, because the funds are frozen by the regulator’s order.",
  );
  expect(screen.queryByTestId("drill-broadcast-button")).toBeNull();
  expect(screen.getByTestId("drill-replay")).toHaveTextContent(
    "Rejected by a node that checks every block itself, because the output they spend no longer exists on its copy of the ledger.",
  );
  expect(screen.getByTestId("drill-replay")).toHaveTextContent(
    "4 confirmations on that node",
  );
  expect(screen.getByTestId("drill-restore")).toHaveTextContent(
    "Returned to Initech · Operating",
  );
  await userEvent.click(screen.getByTestId("drill-replay-button"));
  await waitFor(() =>
    expect(server.calls.map(([path]) => path)).toContain(
      "/api/demo/theft/replay",
    ),
  );
});
