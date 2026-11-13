import { expect, it, vi, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClientProvider } from "@tanstack/react-query";
import { queryClient } from "./api";
import { SessionGate, useApp } from "./context";
afterEach(() => {
  queryClient.clear();
  vi.unstubAllGlobals();
});
it("updates the mounted session observer through login and logout", async () => {
  const session = {
    user: { id: "maker", name: "Maker", role: "bankmaker", tenant: "bank" },
    csrf: "csrf",
    permissions: [],
  };
  const dashboard = {
    accounts: [],
    operations: [],
    guardians: [],
    balances: [],
    beneficiaries: [],
    activity: [],
    assets: [],
    reserves: [],
    network: {},
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async (path: string) =>
        new Response(
          JSON.stringify(
            path === "/api/login"
              ? session
              : path === "/api/dashboard"
                ? dashboard
                : path === "/api/session"
                  ? { user: null, csrf: null, permissions: [] }
                  : { ok: true },
          ),
          { status: 200 },
        ),
    ),
  );
  function Probe() {
    const app = useApp();
    return <button onClick={app.logout}>Authorized {app.user.name}</button>;
  }
  render(
    <QueryClientProvider client={queryClient}>
      <SessionGate guardian={false}>
        <Probe />
      </SessionGate>
    </QueryClientProvider>,
  );
  await screen.findByLabelText("Username");
  await userEvent.type(screen.getByLabelText("Username"), "maker");
  await userEvent.type(screen.getByLabelText("Password"), "password");
  await userEvent.click(screen.getByTestId("login-submit"));
  await userEvent.click(
    await screen.findByRole("button", { name: "Authorized Maker" }),
  );
  await waitFor(() => expect(screen.getByTestId("login-submit")).toBeVisible());
  expect(
    screen.queryByRole("button", { name: "Authorized Maker" }),
  ).not.toBeInTheDocument();
});
