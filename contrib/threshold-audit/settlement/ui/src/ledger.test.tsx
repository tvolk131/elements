import { beforeEach, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { LedgerPage } from "./ledger";
import {
  needsAction,
  nextStep,
  requestSummary,
  viewerNextAction,
} from "./domain";
import type { Operation } from "./types";

const app = vi.hoisted(() => ({ setDialog: vi.fn(), can: () => false }));
const calls = vi.hoisted(() => ({ list: [] as [string, unknown][] }));
const state = vi.hoisted(() => ({
  demo: true,
  online: [true, true, true, true, true],
}));
vi.mock("./context", () => ({ useApp: () => app }));
vi.mock("./demo", () => ({
  usePersonas: () => ({ data: state.demo ? [{ username: "x" }] : [] }),
}));
vi.mock("./api", () => ({
  api: async (path: string, body?: unknown) => {
    calls.list.push([path, body]);
    const institutions = () => ({
      institutions: state.online.map((online, i) => ({
        id: `institution-${i + 1}`,
        online,
      })),
    });
    if (path === "/api/ledger") return LEDGER;
    if (path === "/api/demo/institutions") return institutions();
    if (path.startsWith("/api/demo/institutions/")) {
      const index = Number(path.slice(-1)) - 1;
      state.online[index] = (body as { online: boolean }).online;
      return institutions();
    }
    if (path === "/api/ledger/unauthorized-attempt") return ATTEMPT;
    if (path === "/api/independent-node") return { available: false };
    if (path === "/api/demo/theft")
      return { drill: null, targets: [], independent_node: false };
    throw new Error("unexpected " + path);
  },
}));

const authorization = (signers: string[]) => ({
  expiry_height: 181,
  verified: true,
  threshold: 3,
  authorizers: 5,
  signers,
});
const LEDGER = {
  height: 200,
  latest_block: {
    height: 200,
    time: 1794697515,
    signers: ["institution-3", "institution-4", "institution-5"],
  },
  policy: {
    threshold: 3,
    authorizers: [1, 2, 3, 4, 5].map((n) => `institution-${n}`),
  },
  blocks_scanned: 40,
  transactions: [
    {
      txid: "aa".repeat(32),
      height: 162,
      time: 1794697000,
      inputs: 2,
      outputs: 3,
      hidden_amounts: 3,
      recovery_packets: 3,
      issues_tokens: false,
      burns_tokens: false,
      authorization: authorization([
        "institution-1",
        "institution-2",
        "institution-3",
      ]),
      block_signers: ["institution-1", "institution-2", "institution-3"],
      known: {
        operation_id: "op-1",
        kind: "transfer",
        stage: "transfer",
        amount_minor: 1275000,
        currency: "EUR",
        from: "Acme · Operating",
        to: "Initech · Operating",
      },
    },
    {
      txid: "bb".repeat(32),
      height: 123,
      time: 1794696000,
      inputs: 1,
      outputs: 2,
      hidden_amounts: 1,
      recovery_packets: 0,
      issues_tokens: false,
      burns_tokens: false,
      authorization: null,
      block_signers: null,
      known: null,
    },
  ],
};
const ATTEMPT = {
  txid: "cc".repeat(32),
  without: {
    accepted: false,
    reason: "bad-tx-authorization-missing",
    broadcast_refused: true,
  },
  with: {
    accepted: true,
    authorization: authorization([
      "institution-1",
      "institution-2",
      "institution-3",
    ]),
  },
};

function renderPage() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <LedgerPage />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  calls.list = [];
  state.demo = true;
  state.online = [true, true, true, true, true];
  app.setDialog.mockReset();
});

it("shows what the ledger recorded beside what only the bank knows", async () => {
  renderPage();
  const rows = await screen.findAllByTestId("ledger-row");
  expect(rows).toHaveLength(2);
  expect(
    screen.getByText("Every transaction needs 3 of 5 operators"),
  ).toBeVisible();
  expect(screen.getByText("Confirmed by Operators 3, 4, 5")).toBeVisible();
  const first = within(rows[0]);
  expect(first.getByText(/all amounts hidden/)).toBeVisible();
  expect(first.getByText(/3 sealed recovery records/)).toBeVisible();
  expect(first.getByText("Operators 1, 2, 3")).toBeVisible();
  expect(first.getByText(/Valid until block 181/)).toBeVisible();
  await userEvent.click(
    first.getByRole("button", {
      name: /Payment · 12,750.00 UNITED EUR · Acme · Operating → Initech/,
    }),
  );
  expect(app.setDialog).toHaveBeenCalledWith({ type: "operation", id: "op-1" });
  const second = within(rows[1]);
  expect(second.getByText(/1 of 2 amounts hidden/)).toBeVisible();
  expect(second.getByText("No authorization")).toBeVisible();
  expect(second.getByText("Before the rule was turned on")).toBeVisible();
  expect(
    second.getByText(/Not this bank’s: another bank’s customers/),
  ).toBeVisible();
});

it("shows the ledger refusing a transaction sent without the operators", async () => {
  renderPage();
  await userEvent.click(
    screen.getByRole("button", { name: "Send without the operators" }),
  );
  const results = await screen.findByTestId("attempt-results");
  expect(results).toHaveTextContent(
    "Without the operators: refused by the ledger",
  );
  expect(results).toHaveTextContent(
    "it carries no authorization from the operators",
  );
  expect(results).toHaveTextContent(
    "The same payment, authorized by the operators: accepted",
  );
  expect(results).toHaveTextContent("checked, not sent");
});

it("lets a demo presenter take operators offline and says when nothing can move", async () => {
  renderPage();
  expect(await screen.findByText("5 of 5 online")).toBeVisible();
  for (const n of [1, 2, 3]) {
    await userEvent.click(
      screen.getByRole("switch", { name: `Operator ${n} online` }),
    );
    await waitFor(() =>
      expect(
        screen.getByRole("switch", { name: `Operator ${n} online` }),
      ).not.toBeChecked(),
    );
    if (n === 2)
      expect(
        screen.getByText(/The remaining 3 still authorize transactions/),
      ).toBeVisible();
  }
  expect(screen.getByText("2 of 5 online")).toBeVisible();
  expect(
    screen.getByText(/nothing moves and nobody can force it through/),
  ).toBeVisible();
  expect(calls.list).toContainEqual([
    "/api/demo/institutions/institution-3",
    { online: false },
  ]);
});

it("hides the operator switches outside demo runtimes", async () => {
  state.demo = false;
  renderPage();
  await screen.findAllByTestId("ledger-row");
  expect(screen.queryByRole("switch")).not.toBeInTheDocument();
  expect(calls.list.map(([path]) => path)).not.toContain(
    "/api/demo/institutions",
  );
});

it("summarizes declined and waiting requests in plain words", () => {
  const op = (values: Partial<Operation>) =>
    ({ state: "preparing", user_approved: true, ...values }) as Operation;
  expect(
    requestSummary(
      op({ state: "rejected", declined_by: "institutions", error: "refused" }),
    ),
  ).toBe("Declined by the operators");
  expect(
    requestSummary(
      op({
        error:
          "Waiting for the operators to authorize this transaction: 2 of 5 reachable, 3 needed",
      }),
    ),
  ).toBe("Waiting for the operators");
  // Runtimes started before the rename still report "institutions".
  expect(
    requestSummary(
      op({
        error:
          "Waiting for the institutions to authorize this transaction: 2 of 5 reachable, 3 needed",
      }),
    ),
  ).toBe("Waiting for the operators");
  expect(requestSummary(op({ state: "rejected" }))).toBe("Closed · rejected");
});

it("tells people a waiting payment needs nothing from them", () => {
  const waiting = {
    state: "preparing",
    error:
      "Waiting for the operators to authorize this transaction: 2 of 5 reachable, 3 needed",
    allowed_actions: ["execute"],
  } as unknown as Operation;
  expect(needsAction(waiting)).toBe(false);
  expect(viewerNextAction(waiting)).toBeUndefined();
  expect(nextStep(waiting)).toBe(
    "Waiting for the operators to authorize it (2 of 5 reachable, 3 needed). It goes through on its own as soon as enough of them are back; nobody needs to do anything.",
  );
  // Any other recorded error is still a retry for a person.
  const stuck = { ...waiting, error: "node unreachable" } as Operation;
  expect(needsAction(stuck)).toBe(true);
  const declined = {
    state: "rejected",
    declined_by: "institutions",
    allowed_actions: [],
  } as unknown as Operation;
  expect(nextStep(declined)).toMatch(/^The operators declined this payment/);
});
