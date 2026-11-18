import { expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { FederationPage, memberName } from "./guardian";
import type { Federation, FederationPolicy, Rotation } from "./types";

const policy = (label: string): FederationPolicy => ({
  label,
  epoch: 1,
  policy_version: "v1",
  audit: { threshold: 7, count: 10, members: ["1", "2"] },
  block_signing: { threshold: 3, count: 5, members: ["institution-1"] },
  treasury: { threshold: 3, count: 5, members: ["institution-1"] },
  authorization: { threshold: 3, count: 5, members: ["institution-1"] },
});
const federation: Federation = {
  id: "v1",
  genesis_hash: "ab".repeat(32),
  current: policy("Federation A"),
  incoming: null,
  rotation: null,
  allowed_actions: ["prepare"],
};
const app = vi.hoisted(() => ({
  guardian: true,
  user: { id: "bank-admin" },
  can: () => true,
  refresh: vi.fn(),
  setDialog: vi.fn(),
  data: {
    network: { chain: "auditregtest" },
    federation: null as unknown,
  },
}));
vi.mock("./context", () => ({ useApp: () => app }));
vi.mock("./navigation", () => ({
  WorkspaceLink: ({ children }: { children: React.ReactNode }) => (
    <a>{children}</a>
  ),
}));

it("explains the current operators in plain terms when no handover runs", () => {
  app.data.federation = federation;
  render(<FederationPage />);
  expect(screen.getByText("Approve settlements")).toBeVisible();
  expect(screen.getByText("Approve disclosures")).toBeVisible();
  expect(screen.getByText("Authorize every transaction")).toBeVisible();
  expect(screen.getByText("7 of 10")).toBeVisible();
  expect(screen.getByText("No handover is in progress.")).toBeVisible();
  expect(screen.getByTestId("rotation-prepare")).toBeVisible();
  expect(screen.queryByText("Handover steps")).not.toBeInTheDocument();
});

it("shows handover steps, approvals and checks while a handover runs", () => {
  const rotation: Rotation = {
    id: "r1",
    state: "awaiting_approval",
    stage: "awaiting_approval",
    created_at: 1,
    error: null,
    hold_reason: "Paused for the handover.",
    allowed_actions: ["guardian-approve"],
    steps: [
      {
        id: "preparing",
        label: "Prepare incoming guardians",
        state: "complete",
      },
      { id: "awaiting_approval", label: "Collect approvals", state: "active" },
    ],
    readiness: [
      {
        id: "audit",
        label: "Historical audit shares",
        state: "ready",
        detail: "x",
      },
    ],
    migrations: [],
    outstanding_cases: [],
    approval_count: 1,
    approval_threshold: 3,
    approvals: ["institution-1"],
  };
  app.data.federation = {
    ...federation,
    incoming: policy("Federation B"),
    rotation,
    allowed_actions: [],
  };
  render(<FederationPage />);
  expect(screen.getByText("Incoming operators")).toBeVisible();
  // Named both as the current step (metric) and in the step list.
  expect(
    screen.getAllByText("Current operators approve the handover"),
  ).toHaveLength(2);
  expect(screen.getByText("1 of 3 approved")).toBeVisible();
  expect(screen.getByText("Past payments stay disclosable")).toBeVisible();
  expect(screen.getByTestId("rotation-approve")).toBeVisible();
  expect(screen.queryByTestId("rotation-prepare")).not.toBeInTheDocument();
});

it("names operators for people", () => {
  expect(memberName("institution-c-1")).toBe("Operator C-1");
  expect(memberName("7")).toBe("Guardian 7");
});
