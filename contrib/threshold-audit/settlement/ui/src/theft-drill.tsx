// The independent node's view, and the demo-only theft drill. Only the thief
// is simulated; the regulator's orders and every verdict are real.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";
import { api } from "./api";
import { Badge, Button, CopyField, ErrorNote, Icon, Panel } from "./components";
import { money, short, tokenName } from "./domain";

interface NodeStatus {
  available: boolean;
  error?: string;
  height?: number;
  demo_node_height?: number;
  behind?: number;
  same_chain?: boolean;
  peers?: number;
  mempool?: number;
  authorization_rule?: boolean;
}

export function IndependentNode() {
  const query = useQuery({
    queryKey: ["independent-node"],
    queryFn: ({ signal }) =>
      api<NodeStatus>("/api/independent-node", undefined, signal),
    refetchInterval: 5000,
  });
  const s = query.data;
  if (!s) return null;
  const state = !s.available
    ? ["neutral", "Not running"]
    : !s.peers
      ? ["blocked", "Not connected"]
      : s.same_chain
        ? ["healthy", "Same ledger"]
        : (s.behind ?? 0) > 0
          ? ["pending", "Catching up"]
          : ["error", "Different ledger"];
  return (
    <Panel
      title="Independent node"
      subtitle="A second node with its own copy of the ledger. It checks every block itself and has no wallet and no keys."
      actions={<Badge status={state[0]}>{state[1]}</Badge>}
      className="independent-node"
    >
      {s.available ? (
        <dl className="node-facts" data-testid="independent-node">
          <div>
            <dt>Its latest block</dt>
            <dd>{s.height}</dd>
          </div>
          <div>
            <dt>Demo node’s latest block</dt>
            <dd>{s.demo_node_height}</dd>
          </div>
          <div>
            <dt>Connections</dt>
            <dd>{s.peers}</dd>
          </div>
          <div>
            <dt>Operator authorization</dt>
            <dd>{s.authorization_rule ? "Enforced" : "Not in force"}</dd>
          </div>
        </dl>
      ) : (
        <p className="small-note">
          This runtime does not run one, so every verdict here comes from the
          demo node alone.
        </p>
      )}
    </Panel>
  );
}

interface Target {
  txid: string;
  vout: number;
  account_id: string;
  account: string;
  currency: string;
  amount_minor: number;
  case_id: string | null;
}
interface Verdict {
  accepted: boolean;
  in_mempool: boolean;
  reason: string | null;
}
interface Broadcast {
  at: number;
  height: number;
  accepted: boolean;
  reason: string | null;
  reauthorization?: { refused: boolean; reason: string | null };
}
interface Replay extends Verdict {
  at: number;
  height: number;
  output_spent: boolean;
  submission?: string;
  spent_by?: { txid: string; confirmations: number };
}
interface Order {
  order_id: string;
  state?: string | null;
  txid?: string | null;
}
export interface Drill {
  target: Target;
  mule: { address: string; bank: string };
  txid: string;
  authorized_until: number;
  height: number;
  raw_size: number;
  stolen: { at: number; height: number; independent_node: Verdict | null };
  broadcasts: Broadcast[];
  replays: Replay[];
  thief_transaction: "confirmed" | "in_mempool" | "not_in_mempool";
  output_spent: boolean;
  frozen: null | {
    order_id: string;
    applied_by: number;
    operators: number;
    released: boolean;
  };
  quarantine: null | Order;
  restore: null | (Order & { destination: string });
}
interface DrillView {
  drill: Drill | null;
  targets: Target[];
  independent_node: boolean;
}

const SPENT = new Set(["bad-txns-inputs-missingorspent", "missing-inputs"]);

const amount = (t: Target) =>
  `${money(t.amount_minor)} ${tokenName(t.currency)}`;

function whyRefused(reason: string | null) {
  if (!reason) return "";
  if (SPENT.has(reason) || reason.includes("missingorspent"))
    return "the output they spend no longer exists on its copy of the ledger";
  if (reason.includes("authorization-expired"))
    return "their authorization from the operators has lapsed";
  return reason;
}

type StepState = "done" | "current" | "waiting" | "failed";

function Step({
  state,
  title,
  children,
  testid,
}: {
  state: StepState;
  title: string;
  children?: ReactNode;
  testid: string;
}) {
  return (
    <li className={`drill-step ${state}`} data-testid={testid}>
      <span className="drill-mark" aria-hidden="true">
        {state === "done" ? (
          <Icon name="check" />
        ) : state === "failed" ? (
          <Icon name="close" />
        ) : null}
      </span>
      <div>
        <strong>{title}</strong>
        {children}
      </div>
    </li>
  );
}

function orderState(order: Order | null | undefined) {
  if (!order) return null;
  if (order.state === "confirmed") return "confirmed";
  if (order.state === "error") return "retrying";
  return order.state || "ordered";
}

function BroadcastResult({ drill }: { drill: Drill }) {
  const last = drill.broadcasts[drill.broadcasts.length - 1];
  if (!last) return null;
  if (last.accepted)
    return (
      <p>
        The demo node took them into its waiting pool. They are validly signed
        and still authorized, but the operators refuse to sign any block that
        contains them.{" "}
        {drill.thief_transaction === "confirmed"
          ? "They confirmed."
          : drill.thief_transaction === "in_mempool"
            ? `They are waiting, unconfirmed; the node drops them when their authorization lapses after block ${drill.authorized_until}.`
            : "They are no longer waiting: the node dropped them."}
      </p>
    );
  return (
    <p>
      The demo node refused them because {whyRefused(last.reason)}.
      {last.reauthorization &&
        (last.reauthorization.refused
          ? ` The thief asked the operators to authorize them again and was refused: ${last.reauthorization.reason}`
          : " The operators would have authorized them again; the freeze has not reached them.")}
    </p>
  );
}

function ReplayResult({ replay }: { replay: Replay }) {
  if (replay.accepted)
    return (
      <p>
        {replay.in_mempool
          ? "Already in its waiting pool: it received the thief’s broadcast from the demo node."
          : "It would still accept them: the output is unspent on its copy of the ledger. They were checked, not sent."}
      </p>
    );
  return (
    <>
      <p>
        Rejected by a node that checks every block itself, because{" "}
        {whyRefused(replay.reason)}.
        {replay.spent_by &&
          ` The quarantine spent it (${short(replay.spent_by.txid)}, ${replay.spent_by.confirmations} confirmations on that node).`}
        {replay.submission && " Submitting them was refused too."}
      </p>
      {replay.reason && <code>{replay.reason}</code>}
    </>
  );
}

function DrillSteps({
  drill,
  broadcast,
  replay,
  independent,
}: {
  drill: Drill;
  broadcast: () => void;
  replay: () => void;
  independent: boolean;
}) {
  const t = drill.target;
  const frozen = drill.frozen && !drill.frozen.released;
  const quarantined = orderState(drill.quarantine);
  const restored = orderState(drill.restore);
  const lastReplay = drill.replays[drill.replays.length - 1];
  const before = drill.stolen.independent_node;
  return (
    <ol className="drill-steps">
      <Step
        state="done"
        title="A thief signs with the stolen key"
        testid="drill-stolen"
      >
        <p>
          {amount(t)} from {t.account} to an account the thief opened at{" "}
          {drill.mule.bank}. The operators authorized it, valid until block{" "}
          {drill.authorized_until}: the signature is good and the destination is
          registered, so nothing looked wrong.
        </p>
        {before && (
          <p>
            Independent node:{" "}
            {before.accepted
              ? "would accept these bytes."
              : `would refuse them (${before.reason}).`}
          </p>
        )}
        <details className="wallet-technical">
          <summary>
            Signed transaction {short(drill.txid)} · {drill.raw_size} bytes
          </summary>
          <CopyField label="Transaction ID" value={drill.txid} />
        </details>
      </Step>
      <Step
        state={frozen ? "done" : "current"}
        title="The regulator freezes the output"
        testid="drill-freeze"
      >
        <p>
          {frozen
            ? `Applied by ${drill.frozen!.applied_by} of ${drill.frozen!.operators} operators. They now refuse to authorize the spend or sign a block that contains it.`
            : t.case_id
              ? "Sign in as the regulator, open the disclosure case for this payment and freeze the output."
              : "No delivered disclosure case covers this output, so the regulator cannot see it yet. The bank requests one first."}
        </p>
      </Step>
      <Step
        state={
          drill.thief_transaction === "confirmed"
            ? "failed"
            : drill.broadcasts.length
              ? "done"
              : frozen && !quarantined
                ? "current"
                : "waiting"
        }
        title="The thief broadcasts the signed bytes"
        testid="drill-broadcast"
      >
        <BroadcastResult drill={drill} />
        {!quarantined && (
          <Button
            onClick={broadcast}
            disabled={!frozen}
            title={
              frozen
                ? undefined
                : "Freeze first: an unfrozen spend confirms in the next block"
            }
            data-testid="drill-broadcast-button"
          >
            {drill.broadcasts.length
              ? "Broadcast again"
              : "Broadcast as the thief"}
          </Button>
        )}
      </Step>
      <Step
        state={
          quarantined === "confirmed"
            ? "done"
            : quarantined
              ? "current"
              : "waiting"
        }
        title="The regulator quarantines the funds"
        testid="drill-quarantine"
      >
        <p>
          {quarantined === "confirmed"
            ? `Moved into quarantine (${short(drill.quarantine!.txid ?? "")}). Only the operators’ recovery authorization can move them from there.`
            : quarantined
              ? `Quarantine ${quarantined}…`
              : "On the freeze order, the regulator orders a quarantine. The operators move the output without its owner’s key."}
        </p>
      </Step>
      <Step
        state={
          lastReplay && !lastReplay.accepted
            ? "done"
            : quarantined === "confirmed"
              ? "current"
              : "waiting"
        }
        title="The same bytes go to the independent node"
        testid="drill-replay"
      >
        {lastReplay && <ReplayResult replay={lastReplay} />}
        <Button
          onClick={replay}
          disabled={!independent}
          data-testid="drill-replay-button"
        >
          Submit to the independent node
        </Button>
      </Step>
      <Step
        state={
          restored === "confirmed" ? "done" : restored ? "current" : "waiting"
        }
        title="The regulator returns the funds to their owner"
        testid="drill-restore"
      >
        <p>
          {restored === "confirmed"
            ? `Returned to ${t.account} (${short(drill.restore!.txid ?? "")}).`
            : restored
              ? `Return ${restored}…`
              : `On the quarantine, the regulator orders the funds returned to ${t.account}.`}
        </p>
      </Step>
    </ol>
  );
}

export function TheftDrill() {
  const client = useQueryClient();
  const [choice, setChoice] = useState("");
  const query = useQuery({
    queryKey: ["theft-drill"],
    queryFn: ({ signal }) =>
      api<DrillView>("/api/demo/theft", undefined, signal),
    refetchInterval: (q) => (q.state.data?.drill ? 4000 : false),
  });
  const act = useMutation({
    mutationFn: ({ action, body }: { action: string; body?: unknown }) =>
      api<DrillView>(`/api/demo/theft/${action}`, body ?? {}),
    onSuccess: (view) => {
      client.setQueryData(["theft-drill"], view);
      void client.invalidateQueries({ queryKey: ["ledger"] });
      void client.invalidateQueries({ queryKey: ["freezes"] });
    },
  });
  const v = query.data;
  if (!v) return null;
  const targets = v.targets;
  const picked =
    targets.find((t) => `${t.txid}:${t.vout}` === choice) ?? targets[0];
  return (
    <Panel
      title="Theft drill"
      subtitle="Demo only: play a thief who stole a customer’s key. The regulator’s freeze, quarantine and return are real, signed orders on the regulator’s own screen."
      actions={
        v.drill && (
          <Button
            onClick={() => act.mutate({ action: "reset" })}
            disabled={act.isPending}
            data-testid="drill-reset"
          >
            Start over
          </Button>
        )
      }
      className="theft-drill"
    >
      {v.drill ? (
        <DrillSteps
          drill={v.drill}
          independent={v.independent_node}
          broadcast={() => act.mutate({ action: "broadcast" })}
          replay={() => act.mutate({ action: "replay" })}
        />
      ) : targets.length ? (
        <div className="drill-start">
          <label>
            <span>Output to steal</span>
            <select
              value={picked ? `${picked.txid}:${picked.vout}` : ""}
              onChange={(e) => setChoice(e.target.value)}
              data-testid="drill-target"
            >
              {targets.map((t) => (
                <option
                  key={`${t.txid}:${t.vout}`}
                  value={`${t.txid}:${t.vout}`}
                >
                  {t.account} · {amount(t)}
                  {t.case_id ? " · regulator has a case" : ""}
                </option>
              ))}
            </select>
          </label>
          <Button
            className="primary"
            onClick={() =>
              picked &&
              act.mutate({
                action: "steal",
                body: { txid: picked.txid, vout: picked.vout },
              })
            }
            disabled={act.isPending || !picked}
            data-testid="drill-steal"
          >
            {act.isPending ? "Signing…" : "Steal it with the customer’s key"}
          </Button>
        </div>
      ) : (
        <p className="small-note">No customer output is available to steal.</p>
      )}
      {act.isPending && v.drill && <p role="status">Working…</p>}
      <ErrorNote error={act.error} />
    </Panel>
  );
}
