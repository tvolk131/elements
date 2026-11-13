import { beforeEach, afterEach, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { TransferDestination } from "./beneficiary-routing";
import { api } from "./api";
import { bytes, hex, canonical } from "./recipient-crypto";
const app = vi.hoisted(() => ({
  data: {
    accounts: [{ id: "a", name: "Sender", currencies: ["EUR"] }],
    assets: [{ currency: "EUR", asset_id: "a".repeat(64) }],
    network: { genesis_hash: "b".repeat(64) },
    directory_banks: [] as { id: string; public_key: string }[],
  },
}));
vi.mock("./context", () => ({ useApp: () => app }));
vi.mock("./api", () => ({ api: vi.fn() }));
let client: QueryClient;
const changed = vi.fn();
const secret = bytes("00".repeat(31) + "07");
function route() {
  const payload = {
    id: "c".repeat(32),
    reference: "customer@bank-b",
    beneficiary_name: "Customer · Operating",
    bank_id: "bank-b",
    currency: "EUR",
    asset_id: "a".repeat(64),
    address: "el1fixture" + "a".repeat(80),
    source_account_hash: hex(sha256(utf8ToBytes("a"))),
    genesis_hash: "b".repeat(64),
    expires_at: Math.floor(Date.now() / 1000) + 600,
  };
  return {
    payload,
    public_key: hex(schnorr.getPublicKey(secret)),
    signature: hex(
      schnorr.sign(
        sha256(
          concatBytes(
            utf8ToBytes("Concord/beneficiary-routing/v1\x00"),
            canonical(payload),
          ),
        ),
        secret,
      ),
    ),
    verified: true,
  };
}
function show() {
  client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <TransferDestination account="a" currency="EUR" onChange={changed} />
    </QueryClientProvider>,
  );
}
beforeEach(() => {
  vi.clearAllMocks();
  app.data.directory_banks = [
    { id: "bank-b", public_key: hex(schnorr.getPublicKey(secret)) },
  ];
});
afterEach(() => client.clear());
it("accepts a signed destination only under the pinned bank key and current payment context", async () => {
  const value = route();
  vi.mocked(api).mockResolvedValue(value);
  show();
  await userEvent.selectOptions(
    screen.getByTestId("destination-type"),
    "reference",
  );
  await userEvent.type(
    screen.getByTestId("beneficiary-reference"),
    "customer@bank-b",
  );
  await userEvent.click(screen.getByTestId("resolve-beneficiary"));
  await screen.findByText(/Verified routing signature/);
  expect(changed).toHaveBeenLastCalledWith({
    scope: "a:EUR",
    route_id: value.payload.id,
  });
});
it("rejects a changed beneficiary name even when the server labels the route verified", async () => {
  const value = route();
  value.payload.beneficiary_name = "Someone else";
  vi.mocked(api).mockResolvedValue(value);
  show();
  await userEvent.selectOptions(
    screen.getByTestId("destination-type"),
    "reference",
  );
  await userEvent.type(
    screen.getByTestId("beneficiary-reference"),
    "customer@bank-b",
  );
  await userEvent.click(screen.getByTestId("resolve-beneficiary"));
  await screen.findByRole("alert");
  expect(
    screen.queryByText(/Verified routing signature/),
  ).not.toBeInTheDocument();
  expect(changed.mock.calls.some(([v]) => v?.route_id)).toBe(false);
});
it("keeps raw-address identity unverified after chain address validation", async () => {
  const address = "el1fixture" + "a".repeat(80);
  vi.mocked(api).mockResolvedValue({ address });
  show();
  await userEvent.selectOptions(
    screen.getByTestId("destination-type"),
    "address",
  );
  await userEvent.type(screen.getByTestId("destination-address"), address);
  expect(changed).toHaveBeenLastCalledWith(null);
  await userEvent.click(screen.getByTestId("validate-destination"));
  await waitFor(() =>
    expect(changed).toHaveBeenLastCalledWith({ scope: "a:EUR", address }),
  );
  expect(screen.getByText("Recipient identity not verified.")).toBeVisible();
});
it("ignores an address check that finishes after the address was edited", async () => {
  const first = "el1fixture" + "a".repeat(80);
  let finish: (value: { address: string }) => void = () => {};
  vi.mocked(api).mockImplementation(
    () => new Promise((resolve) => (finish = resolve as typeof finish)),
  );
  show();
  await userEvent.selectOptions(
    screen.getByTestId("destination-type"),
    "address",
  );
  await userEvent.type(screen.getByTestId("destination-address"), first);
  await userEvent.click(screen.getByTestId("validate-destination"));
  await userEvent.type(screen.getByTestId("destination-address"), "b");
  finish({ address: first });
  await new Promise((resolve) => setTimeout(resolve, 20));
  expect(changed.mock.calls.some(([v]) => v?.address)).toBe(false);
  expect(
    screen.queryByText("Recipient identity not verified."),
  ).not.toBeInTheDocument();
});
