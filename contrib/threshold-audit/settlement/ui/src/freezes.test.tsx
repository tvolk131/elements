import { beforeEach, afterEach, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { schnorr } from "@noble/curves/secp256k1.js";
import { DisclosuresPage } from "./disclosures";
import { api } from "./api";
import {
  bytes,
  freezeOrderDigest,
  unlockRecipientKey,
} from "./recipient-crypto";

// The order-signing key derived from recipient secret 1 (see recipient-crypto.test.ts).
const AUTHORITY =
  "5d027bd59943981e1c762a33f03db253e6b403a1722a5905758348259852c4cb";
const state = vi.hoisted(() => ({
  user: { id: "demo-recipient", name: "Financial Regulator" },
  permissions: ["receive_disclosure", "order_freeze"],
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
vi.mock("./recipient-crypto", async () => ({
  ...(await vi.importActual("./recipient-crypto")),
  unlockRecipientKey: vi.fn(),
}));
const caseId = "a".repeat(32);
const txid = "c".repeat(64);
let authorities: Record<string, string>;
let orders: unknown[];
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
  localStorage.setItem(
    "concord-recipient-key-v1:demo-recipient",
    JSON.stringify({
      format: "concord-recipient-key-v1",
      user_id: "demo-recipient",
    }),
  );
  const secret = new Uint8Array(32);
  secret[31] = 1;
  vi.mocked(unlockRecipientKey).mockImplementation(async () => secret.slice());
  authorities = { "Financial Regulator": AUTHORITY };
  orders = [];
  vi.mocked(api).mockImplementation(async (path, body) => {
    if (path === "/api/freezes" && body) return { id: "f".repeat(32) };
    if (path === "/api/freezes")
      return {
        orders,
        authorities,
        genesis_hash: "d".repeat(64),
        can_order: true,
      };
    if (path === "/api/disclosures")
      return {
        cases: [
          {
            id: caseId,
            state: "delivered",
            authority: "Financial regulator · theft report",
            reason: "Trace the proceeds of a stolen payment",
            requester_id: "bank-compliance",
            recipient: {
              id: "demo-recipient",
              name: "Financial Regulator",
              public_key: "02" + "11".repeat(32),
            },
            created_at: 1,
            expires_at: 1800000000,
            threshold: 7,
            guardian_count: 10,
            approved_members: [],
            declined_members: [],
            manifest_hash: "b".repeat(64),
            allowed_actions: [],
            outputs: [
              {
                txid,
                output_index: 0,
                creation_height: 12,
                key_version: 1,
                released_partials: 7,
              },
            ],
          },
        ],
        recipients: [],
        my_keys: [],
        members: [],
      };
    return {};
  });
});
afterEach(() => client?.clear());

it("signs a freeze order for the case's outputs in the browser", async () => {
  setup();
  await userEvent.type(
    await screen.findByTestId("freeze-reason"),
    "Proceeds of a reported theft",
  );
  await userEvent.type(screen.getByTestId("freeze-password"), "concord-demo");
  await userEvent.click(screen.getByTestId("freeze-submit"));
  await waitFor(() =>
    expect(
      vi.mocked(api).mock.calls.some(([p, b]) => p === "/api/freezes" && b),
    ).toBe(true),
  );
  const [, sent] = vi
    .mocked(api)
    .mock.calls.find(([p, b]) => p === "/api/freezes" && b)!;
  const { order, signature } = sent as {
    order: Record<string, unknown>;
    signature: string;
  };
  expect(order).toMatchObject({
    format: "concord-freeze-order-v1",
    kind: "freeze",
    authority: "Financial Regulator",
    authority_key: AUTHORITY,
    case_reference: caseId,
    genesis_hash: "d".repeat(64),
    outputs: [{ txid, vout: 0 }],
  });
  // The operators verify this exact signature; the password never leaves.
  expect(
    schnorr.verify(
      bytes(signature),
      freezeOrderDigest(order),
      bytes(AUTHORITY),
    ),
  ).toBe(true);
  expect(JSON.stringify(sent)).not.toContain("concord-demo");
});

it("refuses to sign with a key the operators don't trust", async () => {
  authorities = { "Financial Regulator": "ee".repeat(32) };
  setup();
  await userEvent.type(
    await screen.findByTestId("freeze-reason"),
    "Proceeds of a reported theft",
  );
  await userEvent.type(screen.getByTestId("freeze-password"), "concord-demo");
  await userEvent.click(screen.getByTestId("freeze-submit"));
  expect(await screen.findByText(/don't recognize this key/)).toBeVisible();
  expect(
    vi.mocked(api).mock.calls.some(([p, b]) => p === "/api/freezes" && b),
  ).toBe(false);
});

it("shows which operators applied a freeze and signs its release", async () => {
  orders = [
    {
      id: "f".repeat(32),
      kind: "freeze",
      authority: "Financial Regulator",
      case_reference: caseId,
      reason: "Proceeds of a reported theft",
      issued_at: 1795000000,
      applied_by: ["institution-1", "institution-2"],
      errors: { "institution-3": "unreachable; will retry" },
      operators: ["institution-1", "institution-2", "institution-3"],
      threshold: 2,
      released_by: null,
      outputs: [{ txid, vout: 0, status: "unspent" }],
    },
  ];
  setup();
  expect(await screen.findByTestId("case-frozen")).toBeVisible();
  expect(
    screen.getByTestId("freeze-applied-" + "f".repeat(32)),
  ).toHaveTextContent("Applied by 2 of 3 operators (Operator 1, Operator 2)");
  expect(screen.getByText(/Operator 3: unreachable/)).toBeVisible();
  await userEvent.click(screen.getByTestId("release-" + "f".repeat(32)));
  await userEvent.type(
    screen.getByTestId("release-reason"),
    "Owner verified, funds returned",
  );
  await userEvent.type(screen.getByTestId("release-password"), "concord-demo");
  await userEvent.click(
    screen.getByRole("button", { name: "Sign and send release" }),
  );
  await waitFor(() =>
    expect(
      vi.mocked(api).mock.calls.some(([p, b]) => p === "/api/freezes" && b),
    ).toBe(true),
  );
  const [, sent] = vi
    .mocked(api)
    .mock.calls.find(([p, b]) => p === "/api/freezes" && b)!;
  expect((sent as { order: unknown }).order).toMatchObject({
    kind: "release",
    releases: "f".repeat(32),
  });
});
