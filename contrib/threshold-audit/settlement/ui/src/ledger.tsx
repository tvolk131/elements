// What the shared ledger itself recorded, beside what only this bank knows.
// Demo runtimes add switches that stop and restart each institution.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import { useApp } from "./context";
import {
  Badge,
  Button,
  CopyField,
  Empty,
  ErrorNote,
  Heading,
  Icon,
  Panel,
} from "./components";
import { date, human, money, short, tokenName } from "./domain";
import { memberName } from "./guardian";
import { usePersonas } from "./demo";
import { FreezeOrders } from "./freezes";

interface Authorization {
  expiry_height: number;
  verified: boolean;
  threshold?: number;
  authorizers?: number;
  signers: string[];
}
interface LedgerTransaction {
  txid: string;
  height: number;
  time: number;
  inputs: number;
  outputs: number;
  hidden_amounts: number;
  recovery_packets: number;
  issues_tokens: boolean;
  burns_tokens: boolean;
  authorization: Authorization | null;
  block_signers: string[] | null;
  known: null | {
    operation_id: string;
    kind: string;
    stage: string;
    amount_minor: number;
    currency: string;
    from: string;
    to?: string;
  };
}
interface Ledger {
  height: number;
  latest_block: {
    height: number;
    time: number;
    signers: string[] | null;
  } | null;
  policy: { threshold: number; authorizers: string[] };
  blocks_scanned: number;
  transactions: LedgerTransaction[];
}
interface Attempt {
  txid: string;
  without: {
    accepted: boolean;
    reason?: string;
    broadcast_refused?: boolean;
  };
  with: {
    accepted: boolean;
    reason?: string;
    authorization?: Authorization | null;
  };
}
interface InstitutionStatus {
  id: string;
  online: boolean;
}

const REASONS: Record<string, string> = {
  "bad-tx-authorization-missing":
    "it carries no authorization from the operators",
  "bad-tx-authorization-expired": "its authorization has expired",
  "bad-tx-authorization-signature":
    "its authorization is not signed by the operators",
  "bad-tx-authorization-malformed": "its authorization is malformed",
  "bad-tx-authorization-unexpected": "this chain does not use authorizations",
};

const names = (list: string[]) =>
  list.length
    ? list.map((m) => memberName(m).replace(/^Operator /, "")).join(", ")
    : "";

function signedBy(list: string[]) {
  return list.length === 1 ? memberName(list[0]) : `Operators ${names(list)}`;
}

function whatItWas(item: LedgerTransaction) {
  const k = item.known;
  if (!k) return null;
  const amount = `${money(k.amount_minor)} ${tokenName(k.currency)}`;
  switch (k.stage) {
    case "transfer":
      return `Payment · ${amount} · ${k.from} → ${k.to || "a wallet address"}`;
    case "issue":
      return `Tokens issued · ${amount} · to ${k.from}`;
    case "escrow":
      return `Withdrawal · ${amount} locked · from ${k.from}`;
    case "burn":
      return `Withdrawal · ${amount} destroyed after payout · ${k.from}`;
    case "refund":
      return `Refund · ${amount} · to ${k.from}`;
    default:
      return `${human(k.kind)} · ${amount}`;
  }
}

function Institutions() {
  const client = useQueryClient();
  const demo = !!usePersonas().data?.length;
  const query = useQuery({
    queryKey: ["demo-institutions"],
    queryFn: ({ signal }) =>
      api<{ institutions: InstitutionStatus[] }>(
        "/api/demo/institutions",
        undefined,
        signal,
      ),
    enabled: demo,
    refetchInterval: 5000,
  });
  const toggle = useMutation({
    mutationFn: ({ id, online }: { id: string; online: boolean }) =>
      api<{ institutions: InstitutionStatus[] }>(
        `/api/demo/institutions/${id}`,
        { online },
      ),
    onSuccess: (result) => {
      client.setQueryData(["demo-institutions"], result);
      void client.invalidateQueries({ queryKey: ["ledger"] });
    },
  });
  if (!demo || !query.data) return null;
  const list = query.data.institutions;
  const online = list.filter((i) => i.online).length;
  const needed = 3;
  const halted = online < needed;
  return (
    <Panel
      title="The operators"
      subtitle="Demo only: switch an operator off to stop its whole service, as if it went offline."
      actions={
        <Badge status={halted ? "blocked" : "healthy"}>
          {online} of {list.length} online
        </Badge>
      }
      className="ledger-institutions"
    >
      <ul className="institution-switches">
        {list.map((i) => (
          <li key={i.id} className={i.online ? "online" : "offline"}>
            <div>
              <strong>{memberName(i.id)}</strong>
              <span>{i.online ? "Online" : "Offline"}</span>
            </div>
            <label className="switch">
              <input
                type="checkbox"
                role="switch"
                checked={i.online}
                disabled={toggle.isPending}
                onChange={(e) =>
                  toggle.mutate({ id: i.id, online: e.target.checked })
                }
                aria-label={`${memberName(i.id)} online`}
                data-testid={`institution-switch-${i.id}`}
              />
              <span aria-hidden="true" />
            </label>
          </li>
        ))}
      </ul>
      <p
        className={
          halted ? "institution-summary halted" : "institution-summary"
        }
        role="status"
      >
        {halted
          ? `Only ${online} online. No transaction can be authorized and no block can be confirmed, so nothing moves and nobody can force it through. It resumes when a third operator is back.`
          : online === list.length
            ? `Every transaction and every block needs ${needed} of them. Any ${list.length - needed} can be offline and payments still settle.`
            : `${list.length - online} offline. The remaining ${online} still authorize transactions and confirm blocks.`}
      </p>
      <ErrorNote error={toggle.error} />
    </Panel>
  );
}

function TryWithout() {
  const client = useQueryClient();
  const attempt = useMutation({
    mutationFn: () => api<Attempt>("/api/ledger/unauthorized-attempt", {}),
    onSettled: () => void client.invalidateQueries({ queryKey: ["ledger"] }),
  });
  const r = attempt.data;
  return (
    <Panel
      title="Try to go around the operators"
      subtitle="A bank wallet signs a valid payment to itself, then offers it to the ledger without asking any operator."
      actions={
        <Button
          className="primary"
          onClick={() => attempt.mutate()}
          disabled={attempt.isPending}
          data-testid="unauthorized-attempt"
        >
          {attempt.isPending ? "Trying…" : "Send without the operators"}
        </Button>
      }
    >
      {r ? (
        <ol className="attempt-results" data-testid="attempt-results">
          <li className={r.without.accepted ? "accepted" : "refused"}>
            <Icon name={r.without.accepted ? "check" : "close"} />
            <div>
              <strong>
                Without the operators:{" "}
                {r.without.accepted ? "accepted" : "refused by the ledger"}
              </strong>
              {!r.without.accepted && (
                <p>
                  The node turned it down because{" "}
                  {REASONS[r.without.reason || ""] || r.without.reason}.
                  {r.without.broadcast_refused &&
                    " Broadcasting it was refused too; it never entered the network."}
                </p>
              )}
              {r.without.reason && <code>{r.without.reason}</code>}
            </div>
          </li>
          <li className={r.with.accepted ? "accepted" : "refused"}>
            <Icon name={r.with.accepted ? "check" : "close"} />
            <div>
              <strong>
                The same payment, authorized by the operators:{" "}
                {r.with.accepted ? "accepted" : "not authorized"}
              </strong>
              <p>
                {r.with.accepted && r.with.authorization
                  ? `Signed by ${signedBy(r.with.authorization.signers)}, valid until block ${r.with.authorization.expiry_height}. The ledger would accept it; it was checked, not sent.`
                  : r.with.reason}
              </p>
            </div>
          </li>
        </ol>
      ) : (
        <p className="small-note">
          Nothing is sent unless the ledger would refuse it anyway. The rule is
          checked by every node, so no wallet, bank or operator can skip it.
        </p>
      )}
      <ErrorNote error={attempt.error} />
    </Panel>
  );
}

export function LedgerPage() {
  const app = useApp();
  const query = useQuery({
    queryKey: ["ledger"],
    queryFn: ({ signal }) => api<Ledger>("/api/ledger", undefined, signal),
    refetchInterval: 4000,
  });
  const l = query.data;
  return (
    <>
      <Heading
        title="What the ledger saw"
        actions={
          <Button
            symbol="refresh"
            onClick={() => void query.refetch()}
            disabled={query.isFetching}
          >
            Refresh
          </Button>
        }
      >
        Read from the shared ledger itself. Amounts and parties are hidden; the
        operators’ authorization of every transaction is not.
      </Heading>
      <ErrorNote error={query.error} />
      {l && (
        <div className="ledger-rule">
          <span className="ledger-rule-icon">
            <Icon name="shield" />
          </span>
          <div>
            <strong>
              {l.policy.threshold
                ? `Every transaction needs ${l.policy.threshold} of ${l.policy.authorizers.length} operators`
                : "No authorization rule is in force"}
            </strong>
            <p>
              {l.policy.threshold
                ? "Every node rejects a transaction without an unexpired authorization signed by enough of them. It is a rule of the ledger, not of this service."
                : "This chain accepts transactions without the operators’ authorization."}
            </p>
          </div>
          {l.latest_block && (
            <div className="ledger-latest">
              <span>Latest block</span>
              <strong>{l.latest_block.height}</strong>
              <span>
                {l.latest_block.signers
                  ? `Confirmed by ${signedBy(l.latest_block.signers)}`
                  : "Before federation signing"}
              </span>
            </div>
          )}
        </div>
      )}
      <div className="ledger-controls">
        <TryWithout />
        <Institutions />
      </div>
      <Panel
        title="Recent transactions"
        subtitle={
          l
            ? `The latest ${l.transactions.length} transactions in the last ${l.blocks_scanned} blocks. Signatures are checked against the operators’ keys.`
            : undefined
        }
      >
        {!l ? (
          <p role="status">Reading the ledger…</p>
        ) : l.transactions.length ? (
          <div className="table-scroll">
            <table className="ledger-table">
              <thead>
                <tr>
                  <th>Block</th>
                  <th>What the ledger shows</th>
                  <th>Authorized by</th>
                  <th>What it was · known only to the bank</th>
                </tr>
              </thead>
              <tbody>
                {l.transactions.map((t) => {
                  const known = whatItWas(t);
                  const a = t.authorization;
                  return (
                    <tr key={t.txid} data-testid="ledger-row">
                      <td>
                        <span className="cell-primary">{t.height}</span>
                        <span className="cell-secondary">
                          {date(t.time, true)}
                        </span>
                      </td>
                      <td>
                        <span className="cell-primary">
                          {t.outputs} {t.outputs === 1 ? "output" : "outputs"} ·{" "}
                          {t.hidden_amounts
                            ? t.hidden_amounts === t.outputs
                              ? "all amounts hidden"
                              : `${t.hidden_amounts} of ${t.outputs} amounts hidden`
                            : "amounts visible"}
                        </span>
                        <span className="cell-secondary">
                          {[
                            t.recovery_packets &&
                              `${t.recovery_packets} sealed recovery ${t.recovery_packets === 1 ? "record" : "records"}`,
                            t.issues_tokens && "issues tokens",
                            t.burns_tokens && "destroys tokens",
                          ]
                            .filter(Boolean)
                            .join(" · ") || "No sealed recovery records"}
                        </span>
                        <details className="wallet-technical">
                          <summary>Transaction {short(t.txid)}</summary>
                          <CopyField label="Transaction ID" value={t.txid} />
                        </details>
                      </td>
                      <td>
                        {a ? (
                          <>
                            <Badge status={a.verified ? "success" : "error"}>
                              {a.verified
                                ? signedBy(a.signers)
                                : "Signatures do not check out"}
                            </Badge>
                            <span className="cell-secondary">
                              Valid until block {a.expiry_height}
                              {t.block_signers &&
                                ` · block confirmed by ${names(t.block_signers)}`}
                            </span>
                          </>
                        ) : (
                          <>
                            <Badge status="neutral">No authorization</Badge>
                            <span className="cell-secondary">
                              Before the rule was turned on
                            </span>
                          </>
                        )}
                      </td>
                      <td>
                        {known ? (
                          <button
                            className="link-button ledger-known"
                            onClick={() =>
                              t.known &&
                              app.setDialog({
                                type: "operation",
                                id: t.known.operation_id,
                              })
                            }
                          >
                            {known}
                          </button>
                        ) : (
                          <span className="cell-secondary">
                            Not one of this bank’s requests (network set-up or
                            fees)
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="No transactions yet" />
        )}
      </Panel>
      {app.can("view_bank") && <FreezeOrders />}
    </>
  );
}
