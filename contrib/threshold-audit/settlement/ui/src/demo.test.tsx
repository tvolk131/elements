import { expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { DemoNext, DemoSignIn, type Persona } from "./demo";

const operator = (n: number): Persona => ({
  username: `institution-${n}`,
  label: `Operator ${n} · signs approvals`,
  workspace: "guardian",
  name: `Operator ${n}`,
  role: "institutionguardian",
});
vi.mock("./api", () => ({
  api: async () => [
    ...[1, 2, 3, 4, 5, 6, 7].map(operator),
    {
      username: "acme-approver",
      label: "Acme · approves payments",
      workspace: "wallet",
      name: "Acme Approver",
      role: "corporateapprover",
    },
  ],
  startSession: vi.fn(),
}));

it("offers one operator to sign live, not all seven", async () => {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <DemoNext
        usernames={[2, 3, 4, 5, 6, 7].map((n) => `institution-${n}`)}
        roles={["corporateapprover"]}
        operation="op"
        guardian={false}
        current="bank-admin"
      />
    </QueryClientProvider>,
  );
  expect(await screen.findByText("Switch to Operator 2")).toBeVisible();
  expect(screen.getByText("Switch to Acme Approver")).toBeVisible();
  expect(screen.getAllByRole("button")).toHaveLength(2);
});

it("groups the operators on one card with a button each", async () => {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <DemoSignIn guardian={false} />
    </QueryClientProvider>,
  );
  const group = await screen.findByRole("group", {
    name: "Operators · signs approvals",
  });
  const buttons = within(group).getAllByRole("button");
  expect(buttons.map((b) => b.textContent)).toEqual([
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
  ]);
  expect(buttons[2]).toHaveAccessibleName("Operator 3 · signs approvals");
  expect(
    screen.getByRole("button", { name: /Acme · approves payments/ }),
  ).toBeVisible();
});
