import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import { useApp } from "./context";
import { Badge, Button, Empty, ErrorNote, Field, Panel } from "./components";
import { date, money } from "./domain";
import { memberName } from "./guardian";
import {
  caseAuthorityKey,
  caseAuthoritySecret,
  hex,
  signFreezeOrder,
  unlockRecipientKey,
  type RecipientKeyFile,
} from "./recipient-crypto";

export interface FrozenOutput {
  txid: string;
  vout: number;
  status: "unspent" | "spend_pending" | "spent";
  holding?: { account_id: string; currency: string; amount_minor: number };
}
export interface FreezeOrder {
  id: string;
  kind: "freeze" | "release";
  authority: string;
  case_reference: string;
  reason: string;
  issued_at: number;
  applied_by: string[];
  errors: Record<string, string>;
  operators: string[];
  threshold: number;
  released_by: string | null;
  outputs?: FrozenOutput[];
  releases?: string;
}
interface FreezeOverview {
  orders: FreezeOrder[];
  authorities: Record<string, string>;
  genesis_hash: string;
  can_order: boolean;
}
/** Where the disclosures page keeps the password-protected recipient key. */
export const recipientKeyStore = (user: string) =>
  `concord-recipient-key-v1:${user}`;
export function useFreezes() {
  const app = useApp();
  return useQuery({
    queryKey: ["freezes"],
    queryFn: () => api<FreezeOverview>("/api/freezes"),
    refetchInterval: 10000,
    enabled: app.can("order_freeze") || app.can("view_bank"),
  });
}

type OrderBody =
  | {
      kind: "freeze";
      case_reference: string;
      reason: string;
      outputs: { txid: string; vout: number }[];
    }
  | {
      kind: "release";
      case_reference: string;
      reason: string;
      releases: string;
    };

/**
 * Sign an order in this browser with the key derived from the recipient key.
 * The password and keys never leave the browser; the server only relays the
 * signed order, and each operator checks the signature itself.
 */
async function signOrder(
  user: string,
  password: string,
  overview: FreezeOverview,
  body: OrderBody,
) {
  const stored = localStorage.getItem(recipientKeyStore(user));
  if (!stored)
    throw new Error("Import your recipient key on the Disclosures page first");
  const recipient = await unlockRecipientKey(
    JSON.parse(stored) as RecipientKeyFile,
    user,
    password,
  );
  const secret = caseAuthoritySecret(recipient);
  recipient.fill(0);
  try {
    const key = caseAuthorityKey(secret);
    const authority = Object.entries(overview.authorities).find(
      ([, value]) => value === key,
    )?.[0];
    if (!authority)
      throw new Error(
        "The operators don't recognize this key as a case authority",
      );
    const order = {
      format: "concord-freeze-order-v1",
      id: hex(crypto.getRandomValues(new Uint8Array(16))),
      genesis_hash: overview.genesis_hash,
      authority,
      authority_key: key,
      issued_at: Math.floor(Date.now() / 1000),
      ...body,
    };
    return { order, signature: signFreezeOrder(order, secret) };
  } finally {
    secret.fill(0);
  }
}

function useSubmitOrder(onDone: () => unknown) {
  const app = useApp(),
    cache = useQueryClient();
  const freezes = useFreezes();
  return useMutation({
    mutationFn: async ({
      password,
      body,
    }: {
      password: string;
      body: OrderBody;
    }) => {
      const overview = freezes.data ?? (await freezes.refetch()).data;
      if (!overview) throw new Error("Freeze orders are unavailable");
      return api<FreezeOrder>(
        "/api/freezes",
        await signOrder(app.user.id, password, overview, body),
      );
    },
    onSuccess: () => {
      onDone();
      void cache.invalidateQueries({ queryKey: ["freezes"] });
      void cache.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });
}

/** A case recipient with freeze authority can freeze the case's outputs. */
export function FreezeCaseOutputs({
  caseId,
  outputs,
}: {
  caseId: string;
  outputs: { txid: string; output_index: number }[];
}) {
  const app = useApp();
  const freezes = useFreezes();
  const [reason, setReason] = useState("");
  const [password, setPassword] = useState("");
  const submit = useSubmitOrder(() => {
    setPassword("");
    setReason("");
  });
  if (!app.can("order_freeze")) return null;
  const active = new Set(
    (freezes.data?.orders ?? [])
      .filter((o) => o.kind === "freeze" && !o.released_by)
      .flatMap((o) => (o.outputs ?? []).map((x) => `${x.txid}:${x.vout}`)),
  );
  const open = outputs.filter(
    (o) => !active.has(`${o.txid}:${o.output_index}`),
  );
  if (!open.length)
    return (
      <p className="small-note" data-testid="case-frozen">
        These outputs are frozen. See Freeze orders below.
      </p>
    );
  return (
    <form
      className="disclosure-consent"
      onSubmit={(e) => {
        e.preventDefault();
        submit.mutate({
          password,
          body: {
            kind: "freeze",
            case_reference: caseId,
            reason,
            outputs: open.map((o) => ({ txid: o.txid, vout: o.output_index })),
          },
        });
      }}
    >
      <h3>Freeze these funds</h3>
      <p>
        Sign a freeze order for{" "}
        {open.length === 1 ? "this output" : `these ${open.length} outputs`}.
        Each operator checks your signature and from then on refuses to
        authorize or confirm any transaction that spends them.
      </p>
      <Field
        label="Reason"
        detail="Recorded in the order every operator keeps."
      >
        <input
          required
          minLength={8}
          maxLength={1000}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          data-testid="freeze-reason"
        />
      </Field>
      <Field
        label="Recipient key password"
        detail="Unlocks your key in this browser to sign the order."
      >
        <input
          type="password"
          autoComplete="off"
          required
          maxLength={256}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          data-testid="freeze-password"
        />
      </Field>
      <Button
        type="submit"
        className="primary"
        disabled={submit.isPending}
        data-testid="freeze-submit"
      >
        {submit.isPending
          ? "Signing and sending…"
          : "Sign and send freeze order"}
      </Button>
      <ErrorNote error={submit.error} />
    </form>
  );
}

const OUTPUT_STATUS = {
  unspent: "Held in place",
  spend_pending: "A spend is waiting; operators won't confirm it",
  spent: "Spent",
};

function ReleaseForm({ order }: { order: FreezeOrder }) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [password, setPassword] = useState("");
  const submit = useSubmitOrder(() => setOpen(false));
  if (!open)
    return (
      <Button onClick={() => setOpen(true)} data-testid={`release-${order.id}`}>
        Release…
      </Button>
    );
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        submit.mutate({
          password,
          body: {
            kind: "release",
            case_reference: order.case_reference,
            reason,
            releases: order.id,
          },
        });
      }}
    >
      <Field label="Reason for release">
        <input
          required
          minLength={8}
          maxLength={1000}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          data-testid="release-reason"
        />
      </Field>
      <Field label="Recipient key password">
        <input
          type="password"
          autoComplete="off"
          required
          maxLength={256}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          data-testid="release-password"
        />
      </Field>
      <Button type="submit" className="primary" disabled={submit.isPending}>
        Sign and send release
      </Button>
      <ErrorNote error={submit.error} />
    </form>
  );
}

/** Every freeze order this account may see, with each operator's receipt. */
export function FreezeOrders() {
  const query = useFreezes();
  const app = useApp();
  const orders = (query.data?.orders ?? []).filter((o) => o.kind === "freeze");
  return (
    <Panel
      title="Freeze orders"
      subtitle="Signed by the regulator. Each operator verifies the signature and returns a signed receipt."
    >
      <ErrorNote error={query.error} />
      {query.isPending ? (
        <p role="status">Loading freeze orders…</p>
      ) : orders.length ? (
        <ul className="freeze-orders">
          {orders.map((o) => (
            <li key={o.id} data-testid={`freeze-${o.id}`}>
              <div className="freeze-order-head">
                <Badge status={o.released_by ? "complete" : "blocked"}>
                  {o.released_by ? "Released" : "Frozen"}
                </Badge>
                <strong>{o.authority}</strong>
                <small>
                  {date(o.issued_at, true)} · case {o.case_reference}
                </small>
              </div>
              <p>{o.reason}</p>
              <ul className="freeze-outputs">
                {(o.outputs ?? []).map((x) => (
                  <li key={`${x.txid}:${x.vout}`}>
                    <code>
                      {x.txid.slice(0, 16)}…:{x.vout}
                    </code>{" "}
                    <span>{OUTPUT_STATUS[x.status]}</span>
                    {x.holding && (
                      <span>
                        {" "}
                        · {money(x.holding.amount_minor)} {x.holding.currency}{" "}
                        held by {x.holding.account_id}
                      </span>
                    )}
                  </li>
                ))}
              </ul>
              <p className="small-note" data-testid={`freeze-applied-${o.id}`}>
                Applied by {o.applied_by.length} of {o.operators.length}{" "}
                operators
                {o.applied_by.length
                  ? ` (${o.applied_by.map(memberName).join(", ")})`
                  : ""}
                . {o.operators.length - o.threshold + 1} refusing are enough to
                stop a spend.
              </p>
              {Object.entries(o.errors).map(([guardian, error]) => (
                <p className="inline-warning" key={guardian}>
                  {memberName(guardian)}: {error}
                </p>
              ))}
              {app.can("order_freeze") && !o.released_by && (
                <ReleaseForm order={o} />
              )}
            </li>
          ))}
        </ul>
      ) : (
        <Empty title="No freeze orders">
          Funds frozen by the regulator will appear here.
        </Empty>
      )}
    </Panel>
  );
}
