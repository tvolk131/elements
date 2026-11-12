import { describe, expect, it } from "vitest";
import {
  csv,
  eligibleDestinations,
  forAccount,
  nextStep,
  needsInstitutionApproval,
  isActiveException,
  viewerNextAction,
} from "./domain";
import type { Account, Beneficiary, Operation } from "./types";
const op = (values: Partial<Operation>) =>
  ({
    id: "case",
    kind: "transfer",
    state: "awaiting_approval",
    account_id: "a",
    to_account_id: "b",
    currency: "EUR",
    amount_minor: 123,
    created_at: 1,
    user_approved: false,
    guardian_approvals: 0,
    guardian_threshold: 3,
    allowed_actions: [],
    ...values,
  }) as Operation;
const accounts: Account[] = [
  { id: "a", name: "Operating", tenant: "acme", currencies: ["EUR", "USD"] },
  { id: "b", name: "Treasury", tenant: "acme", currencies: ["EUR"] },
];
const bank: Beneficiary[] = [
  {
    id: "eur",
    name: "EUR bank",
    account_id: "a",
    kind: "bank",
    currency: "EUR",
  },
  {
    id: "usd",
    name: "USD bank",
    account_id: "a",
    kind: "bank",
    currency: "USD",
  },
  {
    id: "other",
    name: "Other bank",
    account_id: "b",
    kind: "bank",
    currency: "EUR",
  },
];
describe("wallet movement boundaries", () => {
  it("includes incoming transactions when viewing the recipient", () =>
    expect(forAccount([op({})], "b")).toHaveLength(1));
  it("offers a different permitted on-chain account supporting the selected asset", () => {
    expect(
      eligibleDestinations("transfer", accounts, bank, "a", "EUR").map(
        (d) => d.id,
      ),
    ).toEqual(["b"]);
    expect(
      eligibleDestinations("transfer", accounts, bank, "a", "USD"),
    ).toEqual([]);
  });
  it("keeps bank recipients scoped by account and currency", () =>
    expect(
      eligibleDestinations("redemption", accounts, bank, "a", "USD").map(
        (d) => d.id,
      ),
    ).toEqual(["usd"]));
  it("explains the bank credit before token issuance", () =>
    expect(nextStep(op({ kind: "deposit", state: "awaiting_bank" }))).toContain(
      "Tokens have not been issued",
    ));
  it("does not describe preparation as submission", () =>
    expect(nextStep(op({ state: "preparing" }))).not.toContain(
      "has been submitted",
    ));
  it("does not offer a refund while the bank result is unknown", () =>
    expect(nextStep(op({ state: "bank_unknown", error: "timeout" }))).toContain(
      "Tokens remain locked",
    ));
  it("treats a rejection reason as a closed outcome", () =>
    expect(nextStep(op({ state: "rejected", error: "review test" }))).toContain(
      "request is closed",
    ));
  it("escapes spreadsheet formulas and quoted CSV values", () =>
    expect(csv([["=cmd", 'a"b']])).toBe('"\'=cmd","a""b"'));
});

describe("operator work", () => {
  it("counts only requests with this institution's remaining approval action", () => {
    expect(
      needsInstitutionApproval(op({ allowed_actions: ["guardian-approve"] })),
    ).toBe(true);
    expect(needsInstitutionApproval(op({ allowed_actions: [] }))).toBe(false);
    expect(
      needsInstitutionApproval(
        op({ state: "settled", allowed_actions: ["guardian-approve"] }),
      ),
    ).toBe(false);
  });
  it("keeps historical rejection and cancellation reasons out of active exceptions", () => {
    expect(
      isActiveException(op({ state: "rejected", error: "request closed" })),
    ).toBe(false);
    expect(
      isActiveException(op({ state: "cancelled", error: "escrow returned" })),
    ).toBe(false);
    expect(
      isActiveException(op({ state: "bank_unknown", error: "timeout" })),
    ).toBe(true);
  });
  it("shows the institution's available action while a separate user review is pending", () => {
    expect(
      viewerNextAction(
        op({ allowed_actions: ["guardian-approve"], user_approved: false }),
      ),
    ).toContain("independent approval window");
  });
});
