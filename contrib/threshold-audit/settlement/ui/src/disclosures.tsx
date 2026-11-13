import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import { useApp } from "./context";
import {
  Badge,
  Button,
  CopyField,
  Empty,
  ErrorNote,
  Field,
  Heading,
  Panel as BasePanel,
} from "./components";
import { baseUnits, date, download, human, money } from "./domain";
import {
  newRecipientKey,
  unlockRecipientKey,
  recoverBundle,
  type RecipientKeyFile,
  type DisclosureBundle,
  type RecoveredOutput,
} from "./recipient-crypto";
import type { ComponentProps } from "react";
function Panel({ children, ...props }: ComponentProps<typeof BasePanel>) {
  return (
    <BasePanel {...props}>
      <div className="capability-panel-body">{children}</div>
    </BasePanel>
  );
}
interface Recipient {
  id: string;
  name: string;
  public_key: string;
  fingerprint: string;
}
interface DisclosureCase {
  id: string;
  state: string;
  authority: string;
  reason: string;
  requester_id: string;
  recipient: Recipient;
  created_at: number;
  expires_at: number;
  threshold: number;
  guardian_count: number;
  approved_members: number[];
  declined_members: number[];
  allowed_actions: string[];
  manifest_hash: string;
  error?: string;
  outputs: {
    txid: string;
    output_index: number;
    creation_height: number;
    key_version: number;
    released_partials: number;
  }[];
}
interface Overview {
  cases: DisclosureCase[];
  recipients: Recipient[];
  my_keys: Recipient[];
  members: number[];
}
const keyStore = (user: string) => `concord-recipient-key-v1:${user}`;
export function DisclosuresPage() {
  const app = useApp();
  const [selected, setSelected] = useState("");
  const query = useQuery({
    queryKey: ["disclosures", app.user.id],
    queryFn: () => api<Overview>("/api/disclosures"),
    refetchInterval: 15000,
  });
  const refresh = () => query.refetch();
  const current =
    query.data?.cases.find((c) => c.id === selected) || query.data?.cases[0];
  return (
    <>
      <Heading title="Confidential disclosures">
        {app.can("review_disclosure")
          ? "Approve recipient access to selected confidential outputs. These are disclosure approvals, separate from payments."
          : "Request access to selected output details, or open an encrypted package addressed to you."}
      </Heading>
      <ErrorNote error={query.error} />
      {app.can("receive_disclosure") && <RecipientKeys onChange={refresh} />}
      {app.can("request_disclosure") && query.data && (
        <NewCase
          recipients={query.data.recipients}
          onCreated={(c) => {
            setSelected(c.id);
            void refresh();
          }}
        />
      )}
      <div className="disclosure-layout">
        <Panel
          title="Disclosure cases"
          subtitle="Approvals authorize a named recipient and exact outputs."
        >
          {query.isPending ? (
            <p role="status">Loading cases…</p>
          ) : query.data?.cases.length ? (
            <div className="disclosure-case-list">
              {query.data.cases.map((c) => (
                <button
                  key={c.id}
                  className={current?.id === c.id ? "selected" : ""}
                  onClick={() => setSelected(c.id)}
                  data-testid={`case-${c.id}`}
                >
                  <strong>{c.authority}</strong>
                  <span>
                    {c.outputs.length} output{c.outputs.length === 1 ? "" : "s"}{" "}
                    · To {c.recipient.name}
                  </span>
                  <Badge status={c.state}>{human(c.state)}</Badge>
                  <small>
                    {c.approved_members.length} of {c.threshold} guardian
                    approvals
                  </small>
                </button>
              ))}
            </div>
          ) : (
            <Empty title="No disclosure cases">
              Cases visible to this account will appear here.
            </Empty>
          )}
        </Panel>
        {current ? (
          <CaseDetail key={current.id} value={current} refresh={refresh} />
        ) : (
          <Panel title="Case details">
            <p className="muted">
              Select a case to review its scope, recipient and guardian
              approvals.
            </p>
          </Panel>
        )}
      </div>
    </>
  );
}
function RecipientKeys({ onChange }: { onChange: () => unknown }) {
  const app = useApp();
  const [file, setFile] = useState<RecipientKeyFile | null>(() => {
    try {
      return JSON.parse(localStorage.getItem(keyStore(app.user.id)) || "null");
    } catch {
      return null;
    }
  });
  const [password, setPassword] = useState("");
  const [importError, setImportError] = useState<Error | null>(null);
  const make = useMutation({
    mutationFn: async () => {
      const created = await newRecipientKey(app.user.id, password);
      await api("/api/disclosures/recipient-key", {
        public_key: created.public_key,
      });
      return created;
    },
    onSuccess: (created) => {
      setFile(created);
      setPassword("");
      try {
        localStorage.setItem(keyStore(app.user.id), JSON.stringify(created));
      } catch {
        app.notify(
          "Browser storage is unavailable. Download your encrypted key backup.",
          "error",
        );
      }
      download(
        JSON.stringify(created, null, 2),
        `concord-recipient-${app.user.id}.json`,
        "application/json",
      );
      void onChange();
    },
  });
  return (
    <Panel
      title="Your recipient key"
      subtitle="The private key is password-encrypted in this browser. Only its public key is registered with the demo."
    >
      {file ? (
        <>
          <CopyField label="Recipient public key" value={file.public_key} />
          <Button
            onClick={() =>
              download(
                JSON.stringify(file, null, 2),
                `concord-recipient-${app.user.id}.json`,
                "application/json",
              )
            }
          >
            Download encrypted key backup
          </Button>
          <p className="small-note">
            Keep the backup and its password. You need the matching key to open
            a case addressed to it.
          </p>
        </>
      ) : (
        <p>
          Set up a recipient key before someone can address a disclosure to you.
        </p>
      )}
      <details className="recipient-key-setup">
        <summary>
          {file
            ? "Import a backup or create another key"
            : "Create or import a recipient key"}
        </summary>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            make.mutate();
          }}
        >
          <Field
            label="New recipient key password"
            detail="Use at least 10 characters. This password stays in your browser."
          >
            <input
              type="password"
              autoComplete="new-password"
              minLength={10}
              maxLength={256}
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              data-testid="recipient-new-password"
            />
          </Field>
          <Button
            type="submit"
            className="primary"
            disabled={make.isPending}
            data-testid="recipient-create-key"
          >
            {make.isPending
              ? "Creating encrypted key…"
              : "Create key and download backup"}
          </Button>
        </form>
        <Field label="Import an encrypted key backup">
          <input
            type="file"
            accept="application/json,.json"
            onChange={async (e) => {
              try {
                const upload = e.target.files?.[0];
                if (!upload) return;
                if (upload.size > 8192)
                  throw new Error("Key file is too large");
                const parsed = JSON.parse(
                  await upload.text(),
                ) as RecipientKeyFile;
                if (
                  parsed.format !== "concord-recipient-key-v1" ||
                  parsed.user_id !== app.user.id
                )
                  throw new Error(
                    "Choose a recipient key backup for your account",
                  );
                await api("/api/disclosures/recipient-key", {
                  public_key: parsed.public_key,
                });
                localStorage.setItem(
                  keyStore(app.user.id),
                  JSON.stringify(parsed),
                );
                setFile(parsed);
                setImportError(null);
                app.notify(
                  "Recipient key imported. You can now open cases addressed to it.",
                );
                void onChange();
              } catch (error) {
                setImportError(
                  error instanceof Error ? error : new Error("Import failed"),
                );
              }
            }}
          />
        </Field>
      </details>
      <ErrorNote error={make.error || importError} />
    </Panel>
  );
}
function NewCase({
  recipients,
  onCreated,
}: {
  recipients: Recipient[];
  onCreated: (value: DisclosureCase) => void;
}) {
  const app = useApp();
  const [operation, setOperation] = useState("");
  const [indices, setIndices] = useState<number[]>([]);
  const [recipient, setRecipient] = useState("");
  const [authority, setAuthority] = useState("");
  const [reason, setReason] = useState("");
  const [ttl, setTtl] = useState(3600);
  const [advanced, setAdvanced] = useState(false);
  const [txid, setTxid] = useState("");
  const [vout, setVout] = useState(0);
  const outputs = useQuery({
    queryKey: ["disclosure-targets", app.user.id, operation],
    enabled: !!operation && !advanced,
    queryFn: () =>
      api<{ outputs: { txid: string; output_index: number; label: string }[] }>(
        `/api/disclosure-targets/${operation}`,
      ),
  });
  const choices = app.data.operations.filter((o) => o.txid);
  const create = useMutation({
    mutationFn: () => {
      const named = recipients.find(
        (r) => r.id + ":" + r.public_key === recipient,
      );
      if (!named) throw new Error("Select a registered recipient");
      const targets = advanced
        ? [{ txid, output_index: vout }]
        : (outputs.data?.outputs || [])
            .filter((o) => indices.includes(o.output_index))
            .map(({ txid, output_index }) => ({ txid, output_index }));
      return api<DisclosureCase>("/api/disclosures", {
        ...(!advanced ? { operation_id: operation } : {}),
        targets,
        recipient_id: named.id,
        recipient_key: named.public_key,
        authority,
        reason,
        expires_in: ttl,
      });
    },
    onSuccess: (result) => {
      onCreated(result);
      setIndices([]);
      app.notify(
        "Case created. Guardians must explicitly approve recipient access.",
      );
    },
  });
  return (
    <Panel
      title="Request a disclosure"
      subtitle="Choose the payment, exact outputs and intended recipient."
    >
      <details className="disclosure-create">
        <summary>New disclosure case</summary>
        {!recipients.length ? (
          <p className="inline-warning">
            No recipient keys are registered. Ask the intended recipient to open
            Disclosures and set up their key first.
          </p>
        ) : null}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate();
          }}
        >
          {app.can("network_disclosures") && (
            <label className="check-row">
              <input
                type="checkbox"
                checked={advanced}
                onChange={(e) => setAdvanced(e.target.checked)}
              />
              Select a chain output outside the payment list
            </label>
          )}
          {advanced ? (
            <div className="capability-form-grid">
              <Field label="Transaction ID">
                <input
                  required
                  pattern="[a-f0-9]{64}"
                  value={txid}
                  onChange={(e) => setTxid(e.target.value)}
                />
              </Field>
              <Field label="Output index">
                <input
                  required
                  type="number"
                  min={0}
                  max={65535}
                  value={vout}
                  onChange={(e) => setVout(Number(e.target.value))}
                />
              </Field>
            </div>
          ) : (
            <>
              <Field label="Payment">
                <select
                  required
                  value={operation}
                  onChange={(e) => {
                    setOperation(e.target.value);
                    setIndices([]);
                  }}
                >
                  <option value="">
                    Choose a payment with a chain transaction
                  </option>
                  {choices.map((o) => (
                    <option key={o.id} value={o.id}>
                      {money(o.amount_minor)} Test{o.currency} · {human(o.kind)}{" "}
                      · {o.id.slice(0, 8)}
                    </option>
                  ))}
                </select>
              </Field>
              <ErrorNote error={outputs.error} />
              {outputs.isFetching ? (
                <p>Loading confirmed outputs…</p>
              ) : (
                outputs.data && (
                  <fieldset className="disclosure-outputs">
                    <legend>Outputs to disclose (up to four)</legend>
                    {outputs.data.outputs.map((o) => (
                      <label className="check-row" key={o.output_index}>
                        <input
                          type="checkbox"
                          checked={indices.includes(o.output_index)}
                          onChange={(e) =>
                            setIndices((previous) =>
                              e.target.checked
                                ? [...previous, o.output_index]
                                : previous.filter((i) => i !== o.output_index),
                            )
                          }
                        />
                        {o.label} · output {o.output_index}
                      </label>
                    ))}
                    {!outputs.data.outputs.length && (
                      <p>
                        No eligible confidential outputs in this transaction.
                      </p>
                    )}
                  </fieldset>
                )
              )}
            </>
          )}
          <Field label="Named recipient">
            <select
              required
              value={recipient}
              onChange={(e) => setRecipient(e.target.value)}
            >
              <option value="">Choose recipient and key</option>
              {recipients.map((r) => (
                <option
                  key={r.id + r.public_key}
                  value={r.id + ":" + r.public_key}
                >
                  {r.name} · key {r.fingerprint}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Requesting authority or case owner">
            <input
              required
              minLength={3}
              maxLength={160}
              value={authority}
              onChange={(e) => setAuthority(e.target.value)}
              placeholder="For example, Bank A Compliance"
            />
          </Field>
          <Field label="Reason and authorization basis">
            <textarea
              required
              minLength={8}
              maxLength={1000}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Explain why these outputs should be disclosed to this recipient."
            />
          </Field>
          <Field label="Time allowed for guardian approvals and release">
            <select
              value={ttl}
              onChange={(e) => setTtl(Number(e.target.value))}
            >
              <option value={900}>15 minutes</option>
              <option value={3600}>1 hour</option>
              <option value={86400}>24 hours</option>
            </select>
          </Field>
          <p className="small-note">
            Expiry stops new releases. It cannot revoke information or encrypted
            packages already delivered.
          </p>
          <ErrorNote error={create.error} />
          <Button
            type="submit"
            className="primary"
            disabled={
              create.isPending ||
              !recipients.length ||
              (!advanced && (!indices.length || indices.length > 4))
            }
            data-testid="create-disclosure"
          >
            {create.isPending ? "Preparing case…" : "Request guardian approval"}
          </Button>
        </form>
      </details>
    </Panel>
  );
}
function CaseDetail({
  value: c,
  refresh,
}: {
  value: DisclosureCase;
  refresh: () => unknown;
}) {
  const app = useApp(),
    cache = useQueryClient();
  const [ack, setAck] = useState(false);
  const [password, setPassword] = useState("");
  const [results, setResults] = useState<RecoveredOutput[] | null>(null);
  const action = useMutation({
    mutationFn: (name: string) =>
      api<DisclosureCase>(`/api/disclosures/${c.id}/${name}`, {}),
    onSuccess: () => {
      setAck(false);
      void refresh();
      void cache.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });
  const getBundle = () =>
    api<DisclosureBundle>(`/api/disclosures/${c.id}/bundle`);
  const open = useMutation({
    mutationFn: async () => {
      const stored = localStorage.getItem(keyStore(app.user.id));
      if (!stored)
        throw new Error("Import the matching recipient key backup above first");
      const file = JSON.parse(stored) as RecipientKeyFile;
      if (file.public_key !== c.recipient.public_key)
        throw new Error(
          "Import the recipient key whose public key matches this case",
        );
      const secret = await unlockRecipientKey(file, app.user.id, password);
      try {
        return await recoverBundle(await getBundle(), secret, app.user.id);
      } finally {
        secret.fill(0);
      }
    },
    onSuccess: (result) => {
      setPassword("");
      setResults(result);
    },
  });
  const exportPackage = useMutation({
    mutationFn: getBundle,
    onSuccess: (bundle) =>
      download(
        JSON.stringify(bundle, null, 2),
        `concord-disclosure-${c.id}.json`,
        "application/json",
      ),
  });
  return (
    <Panel title="Case details" subtitle={`Case ${c.id}`}>
      <div className="disclosure-detail">
        <Badge status={c.state}>{human(c.state)}</Badge>
        <h3>{c.authority}</h3>
        <p>{c.reason}</p>
        <dl className="disclosure-facts">
          <div>
            <dt>Requester</dt>
            <dd>{c.requester_id}</dd>
          </div>
          <div>
            <dt>Recipient</dt>
            <dd>{c.recipient.name}</dd>
          </div>
          <div>
            <dt>Release deadline</dt>
            <dd>{date(c.expires_at, true)}</dd>
          </div>
          <div>
            <dt>Guardian approvals</dt>
            <dd>
              {c.approved_members.length} of {c.threshold} required (
              {c.guardian_count} guardians)
            </dd>
          </div>
        </dl>
        <CopyField
          label="Approved recipient public key"
          value={c.recipient.public_key}
        />
        <ul className="disclosure-output-status">
          {c.outputs.map((o) => (
            <li key={o.txid + ":" + o.output_index}>
              <strong>Output {o.output_index}</strong>
              <code>{o.txid}</code>
              <span>
                Created at block {o.creation_height} · recovery key{" "}
                {o.key_version}
              </span>
              <span>
                {o.released_partials} encrypted guardian contributions retained
              </span>
            </li>
          ))}
        </ul>
        <details>
          <summary>Approval and case evidence</summary>
          <p>Approved guardians: {c.approved_members.join(", ") || "None"}</p>
          <p>Declined guardians: {c.declined_members.join(", ") || "None"}</p>
          <CopyField label="Approved case binding" value={c.manifest_hash} />
        </details>
        {c.state === "membership_changed" && (
          <p className="inline-warning">
            Federation recovery policy changed. Create a new case so the current
            guardians can approve this historical output.
          </p>
        )}
        {c.state === "recipient_unavailable" && (
          <p className="inline-warning">
            The named recipient account or key is unavailable. Further releases
            are blocked. Create a new case with an active recipient key.
          </p>
        )}
        {c.state === "expired" && (
          <p className="inline-warning">
            The release deadline passed. Existing encrypted contributions remain
            available to the recipient; further contributions require a new
            case.
          </p>
        )}
        {c.allowed_actions.includes("approve") && (
          <div className="disclosure-consent">
            <label className="check-row">
              <input
                type="checkbox"
                checked={ack}
                onChange={(e) => setAck(e.target.checked)}
                data-testid="disclosure-consent"
              />
              I reviewed the reason, exact outputs and recipient key. I
              authorize releasing my guardian contribution to this recipient.
            </label>
            <Button
              className="primary"
              disabled={!ack || action.isPending}
              onClick={() => action.mutate("approve")}
              data-testid="approve-disclosure"
            >
              Approve recipient access
            </Button>
            <Button
              disabled={action.isPending}
              onClick={() => action.mutate("decline")}
            >
              Decline my approval
            </Button>
            <p className="small-note">
              A decline does not give one guardian a veto. A different quorum
              may still approve.
            </p>
          </div>
        )}
        {c.allowed_actions.includes("release") && (
          <div className="disclosure-consent">
            <p>
              The guardian quorum approved this case. Send their encrypted
              contributions to {c.recipient.name}; the recipient combines them
              using their private key.
            </p>
            <Button
              className="primary"
              disabled={action.isPending}
              onClick={() => action.mutate("release")}
              data-testid="release-disclosure"
            >
              {action.isPending
                ? "Requesting encrypted contributions…"
                : "Send encrypted contributions"}
            </Button>
          </div>
        )}
        {c.allowed_actions.includes("cancel") && (
          <Button
            disabled={action.isPending}
            onClick={() => action.mutate("cancel")}
          >
            Cancel unreleased case
          </Button>
        )}
        {c.allowed_actions.includes("download") && (
          <div className="disclosure-consent">
            <h3>Recipient access</h3>
            <Button
              disabled={exportPackage.isPending}
              onClick={() => exportPackage.mutate()}
              data-testid="download-disclosure"
            >
              Download encrypted package and evidence
            </Button>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                open.mutate();
              }}
            >
              <Field
                label="Recipient key password"
                detail="Unlocks your key locally. Your password, private key and recovered details are not sent to the server."
              >
                <input
                  type="password"
                  autoComplete="off"
                  required
                  maxLength={256}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  data-testid="recipient-unlock-password"
                />
              </Field>
              <Button
                type="submit"
                className="primary"
                disabled={open.isPending}
                data-testid="open-disclosure"
              >
                {open.isPending
                  ? "Verifying and opening locally…"
                  : "Open in this browser"}
              </Button>
            </form>
          </div>
        )}
        <ErrorNote
          error={action.error || open.error || exportPackage.error || c.error}
        />
        {results && (
          <div className="disclosure-results" data-testid="disclosure-result">
            <h3>Revealed payment details</h3>
            {results.length < c.outputs.length && (
              <p className="inline-warning">
                Only {results.length} of {c.outputs.length} approved outputs
                could be opened. The others remain confidential.
              </p>
            )}
            <p>
              Decrypted in this browser from independent guardian contributions,
              and checked against the payment recorded on chain. Only the named
              recipient can do this.
            </p>
            {results.map((r) => (
              <div
                key={r.txid + ":" + r.output_index}
                className="revealed-output"
              >
                <span>Amount</span>
                <strong className="number">
                  {baseUnits(
                    r.amount_base_units,
                    app.data.assets.find((a) => a.asset_id === r.asset_id)
                      ?.currency,
                  )}
                </strong>
                <small>
                  Confirmed by {r.verified_guardians} guardians · Output{" "}
                  {r.output_index}
                </small>
                <details className="wallet-technical">
                  <summary>Technical details</summary>
                  <CopyField label="Asset ID" value={r.asset_id} />
                  <CopyField label="Transaction ID" value={r.txid} />
                </details>
              </div>
            ))}
            <Button
              onClick={() =>
                download(
                  JSON.stringify(
                    {
                      case_id: c.id,
                      manifest_hash: c.manifest_hash,
                      outputs: results,
                    },
                    null,
                    2,
                  ),
                  `concord-openings-${c.id}.json`,
                  "application/json",
                )
              }
            >
              Export revealed details
            </Button>
          </div>
        )}
      </div>
    </Panel>
  );
}
