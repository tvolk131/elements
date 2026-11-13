import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { utf8ToBytes, concatBytes } from "@noble/hashes/utils.js";
import { useApp } from "./context";
import { api } from "./api";
import { Badge, Button, CopyField, ErrorNote, Field } from "./components";
import { canonical, bytes, hex } from "./recipient-crypto";
import type { Currency } from "./types";
export interface TransferTarget {
  scope: string;
  to_account_id?: string;
  route_id?: string;
  address?: string;
}
interface Route {
  payload: {
    id: string;
    reference: string;
    beneficiary_name: string;
    bank_id: string;
    currency: string;
    asset_id: string;
    address: string;
    source_account_hash: string;
    genesis_hash: string;
    expires_at: number;
  };
  public_key: string;
  signature: string;
  verified: boolean;
}
export function TransferDestination({
  account,
  currency,
  onChange,
}: {
  account: string;
  currency: Currency;
  onChange: (value: TransferTarget | null) => void;
}) {
  const app = useApp();
  const [mode, setMode] = useState("managed");
  const [reference, setReference] = useState("");
  const [address, setAddress] = useState("");
  const [route, setRoute] = useState<Route | null>(null);
  const [managed, setManaged] = useState("");
  const scope = account + ":" + currency;
  const resolve = useMutation({
    mutationFn: () =>
      api<Route>("/api/beneficiaries/resolve", {
        account_id: account,
        currency,
        reference,
      }),
    onSuccess: (result) => {
      const p = result.payload,
        bank = app.data.directory_banks?.find((b) => b.id === p.bank_id),
        asset = app.data.assets.find((a) => a.currency === currency);
      const message = sha256(
        concatBytes(
          utf8ToBytes("Concord/beneficiary-routing/v1\x00"),
          canonical(p),
        ),
      );
      if (
        !bank ||
        result.public_key !== bank.public_key ||
        p.reference !== reference.trim().toLowerCase() ||
        p.currency !== currency ||
        p.asset_id !== asset?.asset_id ||
        p.genesis_hash !== app.data.network.genesis_hash ||
        p.source_account_hash !== hex(sha256(utf8ToBytes(account))) ||
        p.expires_at <= Date.now() / 1000 ||
        !schnorr.verify(
          bytes(result.signature),
          message,
          bytes(bank.public_key),
        )
      )
        throw new Error("Beneficiary routing signature or context is invalid");
      setRoute(result);
      onChange({ scope, route_id: p.id });
    },
  });
  const validate = useMutation({
    mutationFn: () =>
      api<{ address: string }>("/api/beneficiaries/validate-address", {
        address: address.trim(),
      }),
    onSuccess: (result) => onChange({ scope, address: result.address }),
  });
  const changeMode = (value: string) => {
    setMode(value);
    setRoute(null);
    onChange(null);
    resolve.reset();
    validate.reset();
  };
  return (
    <section className="beneficiary-routing">
      <Field label="Send to">
        <select
          aria-label="Destination type"
          value={mode}
          onChange={(e) => changeMode(e.target.value)}
          data-testid="destination-type"
        >
          <option value="managed">Another managed account</option>
          <option value="reference">Beneficiary at a bank</option>
          <option value="address">Confidential wallet address</option>
        </select>
      </Field>
      {mode === "managed" ? (
        <Field label="To on-chain account">
          <select
            aria-label="Destination"
            data-testid="beneficiary"
            required
            value={managed}
            onChange={(e) => {
              setManaged(e.target.value);
              onChange(
                e.target.value
                  ? { scope, to_account_id: e.target.value }
                  : null,
              );
            }}
          >
            <option value="">Choose a managed destination</option>
            {app.data.accounts
              .filter(
                (a) => a.id !== account && a.currencies.includes(currency),
              )
              .map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
          </select>
        </Field>
      ) : mode === "reference" ? (
        <>
          <Field
            label="Beneficiary reference"
            detail="Enter the exact reference provided by the recipient, including their bank."
          >
            <input
              value={reference}
              onChange={(e) => {
                setReference(e.target.value);
                setRoute(null);
                onChange(null);
                resolve.reset();
              }}
              placeholder="initech-main@bank-b"
              autoComplete="off"
              data-testid="beneficiary-reference"
            />
          </Field>
          <Button
            type="button"
            disabled={resolve.isPending || !reference.trim()}
            onClick={() => resolve.mutate()}
            data-testid="resolve-beneficiary"
          >
            {resolve.isPending
              ? "Checking receiving bank…"
              : "Look up beneficiary"}
          </Button>
          {route && (
            <div className="beneficiary-confirmation">
              <Badge status="complete">
                Verified routing signature · Demo bank
              </Badge>
              <h4>{route.payload.beneficiary_name}</h4>
              <p>
                {route.payload.bank_id} · Test{route.payload.currency}
              </p>
              <CopyField
                label="Receiving confidential address"
                value={route.payload.address}
              />
              <p className="small-note">
                The receiving bank signed this destination. Confirm the
                beneficiary before creating the payment request.
              </p>
            </div>
          )}
        </>
      ) : (
        <>
          <Field
            label="Confidential wallet address"
            detail="The address must belong to this chain. Address validation does not verify the recipient’s identity."
          >
            <textarea
              value={address}
              onChange={(e) => {
                setAddress(e.target.value);
                onChange(null);
                validate.reset();
              }}
              spellCheck={false}
              data-testid="destination-address"
            />
          </Field>
          <Button
            type="button"
            disabled={validate.isPending || address.trim().length < 30}
            onClick={() => validate.mutate()}
            data-testid="validate-destination"
          >
            {validate.isPending ? "Checking address…" : "Check address"}
          </Button>
          {validate.isSuccess && (
            <p>
              <Badge status="ready">Valid confidential address</Badge>{" "}
              <span>Recipient identity not verified.</span>
            </p>
          )}
        </>
      )}
      <ErrorNote error={resolve.error || validate.error} />
    </section>
  );
}
