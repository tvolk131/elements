import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import { useApp } from "./context";
import { Badge, Button, Empty, ErrorNote, Field, Panel } from "./components";
import { date, money, tokenName } from "./domain";
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
  acts_on?: string;
  /** Recovery progress, on a freeze. */
  quarantine?: RecoveryStep;
  restore?: RecoveryStep & { destination: string };
}
export interface RecoveryStep {
  id: string;
  state: "ordered" | "built" | "broadcast" | "confirmed";
  txid: string | null;
  error: string | null;
  reason: string;
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
    }
  | {
      kind: "quarantine";
      case_reference: string;
      reason: string;
      freeze: string;
    }
  | {
      kind: "restore";
      case_reference: string;
      reason: string;
      quarantine: string;
      destination: string;
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

/** A signed regulator action on a freeze: release, quarantine or restore. */
function ActionForm({
  name,
  title,
  explain,
  submitLabel,
  withDestination = false,
  build,
  close,
}: {
  name: string;
  title: string;
  explain: string;
  submitLabel: string;
  withDestination?: boolean;
  build: (reason: string, destination: string) => OrderBody;
  close: () => void;
}) {
  const [reason, setReason] = useState("");
  const [destination, setDestination] = useState("");
  const [password, setPassword] = useState("");
  const submit = useSubmitOrder(close);
  const field = name.split("-")[0];
  return (
    <form
      className="freeze-action-form"
      onSubmit={(e) => {
        e.preventDefault();
        submit.mutate({ password, body: build(reason, destination) });
      }}
    >
      <h4>{title}</h4>
      <p>{explain}</p>
      {withDestination && (
        <Field
          label="Destination bank reference"
          detail="The member bank account to return the funds to, written account@bank."
        >
          <input
            required
            pattern="[a-z0-9._-]+@[a-z0-9._-]+"
            value={destination}
            onChange={(e) =>
              setDestination(e.target.value.trim().toLowerCase())
            }
            data-testid={`${field}-destination`}
          />
        </Field>
      )}
      <Field label="Reason">
        <input
          required
          minLength={8}
          maxLength={1000}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          data-testid={`${field}-reason`}
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
          data-testid={`${field}-password`}
        />
      </Field>
      <div className="freeze-actions">
        <Button
          type="submit"
          className="primary"
          disabled={submit.isPending}
          data-testid={`${field}-submit`}
        >
          {submit.isPending ? "Signing and sending…" : submitLabel}
        </Button>
        <Button type="button" onClick={close} disabled={submit.isPending}>
          Cancel
        </Button>
      </div>
      <ErrorNote error={submit.error} />
    </form>
  );
}

const STEP_STATE: Record<RecoveryStep["state"], string> = {
  ordered: "Ordered; the operators are opening the funds",
  built: "Waiting for the operators' recovery signatures",
  broadcast: "Sent; waiting for the next block",
  confirmed: "Confirmed on the ledger",
};

function RecoveryStatus({
  label,
  step,
}: {
  label: string;
  step: RecoveryStep;
}) {
  return (
    <p className="small-note" data-testid={`step-${step.id}`}>
      <strong>{label}:</strong> {STEP_STATE[step.state]}
      {step.txid && (
        <>
          {" "}
          · <code title={step.txid}>{step.txid.slice(0, 12)}…</code>
        </>
      )}
      {step.error && <span className="warning-text"> · {step.error}</span>}
    </p>
  );
}

function FreezeOrderCard({ order: o }: { order: FreezeOrder }) {
  const app = useApp();
  // One action form at a time, across the card's full width.
  const [acting, setActing] = useState<
    "quarantine" | "release" | "restore" | null
  >(null);
  const close = () => setActing(null);
  const released = Boolean(o.released_by);
  const moved =
    o.quarantine && ["broadcast", "confirmed"].includes(o.quarantine.state);
  const returned =
    o.restore && ["broadcast", "confirmed"].includes(o.restore.state);
  const all = o.applied_by.length === o.operators.length;
  const regulator = app.can("order_freeze");
  const account = (id: string) =>
    app.data.accounts?.find((a) => a.id === id)?.name ?? id;
  return (
    <li
      className={`freeze-order ${released ? "released" : ""}`}
      data-testid={`freeze-${o.id}`}
    >
      <div className="freeze-order-head">
        <Badge status={released || returned ? "complete" : "blocked"}>
          {released
            ? "Released"
            : returned
              ? "Restored"
              : moved
                ? "Quarantined"
                : "Frozen"}
        </Badge>
        <strong>{o.reason}</strong>
        <small>
          {o.authority} · {date(o.issued_at, true)}
        </small>
      </div>
      <ul className="freeze-outputs">
        {(o.outputs ?? []).map((x) => (
          <li key={`${x.txid}:${x.vout}`}>
            {x.holding ? (
              <strong>
                {money(x.holding.amount_minor)} {tokenName(x.holding.currency)}{" "}
                held by {account(x.holding.account_id)}
              </strong>
            ) : (
              <strong>Output {x.vout}</strong>
            )}
            <span>
              {released
                ? "No longer frozen"
                : returned
                  ? `Returned to ${o.restore!.destination}`
                  : moved
                    ? "Moved into quarantine"
                    : OUTPUT_STATUS[x.status]}
            </span>
            <code title={`${x.txid}:${x.vout}`}>
              {x.txid.slice(0, 12)}…:{x.vout}
            </code>
          </li>
        ))}
      </ul>
      {!released && (
        <p className="small-note" data-testid={`freeze-applied-${o.id}`}>
          {all
            ? `Applied by all ${o.operators.length} operators`
            : `Applied by ${o.applied_by.length} of ${o.operators.length} operators` +
              (o.applied_by.length
                ? ` (${o.applied_by.map(memberName).join(", ")})`
                : "")}
          , each with a signed receipt. Any{" "}
          {o.operators.length - o.threshold + 1} refusing stop a spend.
        </p>
      )}
      {!released &&
        Object.entries(o.errors).map(([guardian, error]) => (
          <p className="inline-warning" key={guardian}>
            {memberName(guardian)}: {error}
          </p>
        ))}
      {o.quarantine && (
        <RecoveryStatus label="Quarantine" step={o.quarantine} />
      )}
      {o.restore && (
        <RecoveryStatus
          label={`Restore to ${o.restore.destination}`}
          step={o.restore}
        />
      )}
      {regulator && !released && !o.quarantine && !acting && (
        <div className="freeze-actions">
          <Button
            onClick={() => setActing("quarantine")}
            data-testid={`quarantine-${o.id}`}
          >
            Quarantine…
          </Button>
          <Button
            onClick={() => setActing("release")}
            data-testid={`release-${o.id}`}
          >
            Release…
          </Button>
        </div>
      )}
      {acting === "quarantine" && (
        <ActionForm
          name={`quarantine-${o.id}`}
          title="Quarantine these funds"
          explain="The operators open the hidden amount with their disclosure key and move the funds into quarantine, without the holder's key. Only a later restore order can move them out."
          submitLabel="Sign and send quarantine order"
          close={close}
          build={(reason) => ({
            kind: "quarantine",
            case_reference: o.case_reference,
            reason,
            freeze: o.id,
          })}
        />
      )}
      {acting === "release" && (
        <ActionForm
          name={`release-${o.id}`}
          title="Release the freeze"
          explain="The operators stop holding these funds, and the holder can spend them again."
          submitLabel="Sign and send release"
          close={close}
          build={(reason) => ({
            kind: "release",
            case_reference: o.case_reference,
            reason,
            releases: o.id,
          })}
        />
      )}
      {regulator && moved && !o.restore && !acting && (
        <div className="freeze-actions">
          <Button
            onClick={() => setActing("restore")}
            data-testid={`restore-${o.id}`}
          >
            Restore…
          </Button>
        </div>
      )}
      {acting === "restore" && !o.restore && (
        <ActionForm
          name={`restore-${o.id}`}
          title="Restore the funds"
          explain={`The operators move the quarantined funds to a new address of the member bank account you name. ${o.threshold} of the ${o.operators.length} must sign.`}
          submitLabel="Sign and send restore order"
          withDestination
          close={close}
          build={(reason, destination) => ({
            kind: "restore",
            case_reference: o.case_reference,
            reason,
            quarantine: o.quarantine!.id,
            destination,
          })}
        />
      )}
    </li>
  );
}

/** Every freeze order this account may see, with each operator's receipt. */
export function FreezeOrders() {
  const query = useFreezes();
  const orders = (query.data?.orders ?? []).filter((o) => o.kind === "freeze");
  const closed = (o: FreezeOrder) =>
    Boolean(o.released_by) ||
    (o.restore !== undefined && o.restore.state === "confirmed");
  const active = orders.filter((o) => !closed(o));
  const released = orders.filter(closed);
  return (
    <Panel
      title="Freeze orders"
      subtitle="Signed by the regulator. Each operator checks the signature itself and returns a signed receipt."
    >
      <div className="capability-panel-body">
        <ErrorNote error={query.error} />
        {query.isPending ? (
          <p role="status">Loading freeze orders…</p>
        ) : active.length ? (
          <ul className="freeze-orders">
            {active.map((o) => (
              <FreezeOrderCard key={o.id} order={o} />
            ))}
          </ul>
        ) : (
          <Empty title="Nothing is frozen">
            {released.length
              ? "Closed orders, including restored funds, are listed below."
              : "Funds frozen by the regulator will appear here."}
          </Empty>
        )}
        {released.length > 0 && (
          // Open while nothing else is, so a restore's outcome stays in view.
          <details className="freeze-history" open={!active.length}>
            <summary>Closed ({released.length})</summary>
            <ul className="freeze-orders">
              {released.map((o) => (
                <FreezeOrderCard key={o.id} order={o} />
              ))}
            </ul>
          </details>
        )}
      </div>
    </Panel>
  );
}
