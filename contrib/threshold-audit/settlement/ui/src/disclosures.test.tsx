import { beforeEach, afterEach, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { DisclosuresPage } from "./disclosures";
import { api } from "./api";
import {
  newRecipientKey,
  unlockRecipientKey,
  recoverBundle,
} from "./recipient-crypto";
const state = vi.hoisted(() => ({
  user: { id: "g1", name: "Guardian 1" },
  permissions: ["review_disclosure"],
  data: { operations: [], assets: [] },
  notify: vi.fn(),
}));
vi.mock("./context", () => ({
  useApp: () => ({
    ...state,
    can: (p: string) => state.permissions.includes(p),
  }),
}));
vi.mock("./api", () => ({ api: vi.fn() }));
vi.mock("./domain", async () => ({
  ...(await vi.importActual("./domain")),
  download: vi.fn(),
}));
vi.mock("./recipient-crypto", () => ({
  newRecipientKey: vi.fn(),
  unlockRecipientKey: vi.fn(),
  recoverBundle: vi.fn(),
}));
const key = {
  format: "concord-recipient-key-v1",
  user_id: "recipient",
  public_key: "02" + "11".repeat(32),
  salt: "00".repeat(16),
  nonce: "00".repeat(12),
  ciphertext: "00".repeat(48),
};
let actions: string[];
let client: QueryClient;
function setup() {
  client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <DisclosuresPage />
    </QueryClientProvider>,
  );
}
beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
  actions = ["approve", "decline"];
  state.user = { id: "g1", name: "Guardian 1" };
  state.permissions = ["review_disclosure"];
  vi.mocked(api).mockImplementation(async (path) => {
    if (path === "/api/disclosures")
      return {
        cases: [
          {
            id: "a".repeat(32),
            state: "awaiting_approval",
            authority: "Bank A Compliance",
            reason: "Investigate this payment",
            requester_id: "compliance",
            recipient: {
              id: "recipient",
              name: "Auditor",
              public_key: key.public_key,
            },
            created_at: 1,
            expires_at: 1800000000,
            threshold: 11,
            guardian_count: 15,
            approved_members: [],
            declined_members: [],
            manifest_hash: "b".repeat(64),
            allowed_actions: actions,
            outputs: [
              {
                txid: "c".repeat(64),
                output_index: 0,
                creation_height: 12,
                key_version: 1,
                released_partials: 0,
              },
            ],
          },
        ],
        recipients: [],
        my_keys: [],
        members: [1, 2, 3],
      };
    return {};
  });
});
afterEach(() => client?.clear());
it("requires explicit guardian consent before signing and never releases automatically", async () => {
  setup();
  await screen.findByRole("heading", { name: "Bank A Compliance" });
  expect(
    screen.getByRole("button", { name: "Approve recipient access" }),
  ).toBeDisabled();
  expect(api).toHaveBeenCalledTimes(1);
  await userEvent.click(screen.getByTestId("disclosure-consent"));
  await userEvent.click(
    screen.getByRole("button", { name: "Approve recipient access" }),
  );
  await waitFor(() =>
    expect(api).toHaveBeenCalledWith(
      "/api/disclosures/" + "a".repeat(32) + "/approve",
      {},
    ),
  );
  expect(vi.mocked(api).mock.calls.some(([p]) => p.endsWith("/release"))).toBe(
    false,
  );
});
it("does not offer approval actions to a recipient", async () => {
  state.user = { id: "recipient", name: "Auditor" };
  state.permissions = ["receive_disclosure"];
  actions = [];
  setup();
  await screen.findByRole("heading", { name: "Bank A Compliance" });
  expect(
    screen.queryByRole("button", { name: "Approve recipient access" }),
  ).not.toBeInTheDocument();
});
it("registers only the public key, keeping the key password out of API requests", async () => {
  state.user = { id: "recipient", name: "Auditor" };
  state.permissions = ["receive_disclosure"];
  actions = [];
  vi.mocked(newRecipientKey).mockResolvedValue(key);
  setup();
  await userEvent.click(screen.getByText("Create or import a recipient key"));
  await userEvent.type(
    screen.getByTestId("recipient-new-password"),
    "only-local-password",
  );
  await userEvent.click(screen.getByTestId("recipient-create-key"));
  await waitFor(() =>
    expect(api).toHaveBeenCalledWith("/api/disclosures/recipient-key", {
      public_key: key.public_key,
    }),
  );
  expect(JSON.stringify(vi.mocked(api).mock.calls)).not.toContain(
    "only-local-password",
  );
  expect(
    JSON.parse(localStorage.getItem("concord-recipient-key-v1:recipient")!),
  ).toEqual(key);
});
it("opens recipient details locally and clears the private scalar after use", async () => {
  state.user = { id: "recipient", name: "Auditor" };
  state.permissions = ["receive_disclosure"];
  actions = ["download"];
  localStorage.setItem(
    "concord-recipient-key-v1:recipient",
    JSON.stringify(key),
  );
  const secret = new Uint8Array(32).fill(7);
  vi.mocked(unlockRecipientKey).mockResolvedValue(secret);
  vi.mocked(recoverBundle).mockResolvedValue([
    {
      txid: "c".repeat(64),
      output_index: 0,
      asset_id: "d".repeat(64),
      amount_base_units: "123000000",
      asset_blinder: "1",
      value_blinder: "2",
      verified_guardians: 11,
    },
  ]);
  setup();
  await screen.findByTestId("recipient-unlock-password");
  await userEvent.type(
    screen.getByTestId("recipient-unlock-password"),
    "only-local-password",
  );
  await userEvent.click(screen.getByTestId("open-disclosure"));
  await screen.findByTestId("disclosure-result");
  expect(
    vi
      .mocked(api)
      .mock.calls.some(
        ([p, body]) => p.endsWith("/bundle") && body === undefined,
      ),
  ).toBe(true);
  expect(JSON.stringify(vi.mocked(api).mock.calls)).not.toContain(
    "only-local-password",
  );
  expect(secret.every((v) => v === 0)).toBe(true);
});
