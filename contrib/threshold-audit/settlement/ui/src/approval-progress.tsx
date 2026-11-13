import { useApp } from "./context";
import { Badge, Button, Icon } from "./components";
import { DemoNext } from "./demo";
import { money } from "./domain";
import type { Operation, WorkflowActor } from "./types";

function Actors({
  actors,
  fallback,
}: {
  actors?: WorkflowActor[];
  fallback: string;
}) {
  if (!actors) return <>{fallback}</>;
  if (!actors.length)
    return (
      <>
        No eligible account is currently configured. Ask the bank administrator
        to assign an approver.
      </>
    );
  return (
    <>
      {actors.map((actor, index) => (
        <span key={actor.id}>
          {index > 0 ? " or " : ""}
          <strong>{actor.name}</strong>
        </span>
      ))}
    </>
  );
}
export function ApprovalProgress({ operation: op }: { operation: Operation }) {
  const app = useApp();
  const workflow = op.approval_workflow;
  const makerId = workflow?.maker.id || op.maker;
  const isMaker = makerId === app.user.id;
  const required = workflow?.required_institutions ?? op.guardian_threshold;
  const approved = op.guardian_approvals;
  const policyIds =
    workflow?.institution_ids ||
    app.data.guardians
      .map((g) => g.institution_id || g.id || "")
      .filter(Boolean);
  const institutionCount = policyIds.length;
  const ready = op.state === "ready";
  const kind =
    op.kind === "transfer"
      ? "transfer"
      : op.kind === "redemption"
        ? "withdrawal"
        : "request";
  return (
    <section
      className="payment-approval-progress"
      aria-labelledby="payment-approval-heading"
    >
      <div className="payment-approval-heading">
        <Icon name="info" />
        <h3 id="payment-approval-heading">
          {ready ? "Ready to submit" : `Why this ${kind} is waiting`}
        </h3>
      </div>
      <p className="payment-not-sent">
        {op.kind === "transfer" && !op.txid ? (
          <>
            The app has reserved{" "}
            <strong>
              {money(op.amount_minor)} Test{op.currency}
            </strong>{" "}
            from {app.accountName(op.account_id)}. It has not been transferred
            yet.
          </>
        ) : op.kind === "redemption" && !op.txid ? (
          <>
            The tokens are reserved for this request. The bank payout has not
            started.
          </>
        ) : (
          <>
            The next chain transaction for this request has not been submitted.
          </>
        )}
      </p>
      <ol className="payment-approval-steps">
        <li>
          <span className="payment-step-number">
            {op.user_approved ? <Icon name="check" /> : "1"}
          </span>
          <div>
            <div className="payment-step-title">
              <h4>Second-person check</h4>
              <Badge status={op.user_approved ? "complete" : "pending"}>
                {op.user_approved ? "Approved" : "Not approved"}
              </Badge>
            </div>
            {!op.user_approved ? (
              <>
                {workflow?.user_reviewers.length === 0 ? (
                  <p>
                    No eligible second-person approver is configured. Ask the
                    bank administrator to assign one.
                  </p>
                ) : (
                  <p>
                    <Actors
                      actors={workflow?.user_reviewers}
                      fallback="A bank or corporate payment approver"
                    />{" "}
                    must review the amount and destination in{" "}
                    <b>Wallet → Requests</b>.
                  </p>
                )}
                {isMaker ? (
                  <p className="payment-viewer-note">
                    You created this request
                    {workflow?.maker.name ? ` as ${workflow.maker.name}` : ""}.
                    You cannot approve your own request.
                  </p>
                ) : (
                  !op.allowed_actions.includes("approve") && (
                    <p className="payment-viewer-note">
                      Your current account ({app.user.name}) cannot provide this
                      approval.
                    </p>
                  )
                )}
                {!op.allowed_actions.includes("approve") && (
                  <DemoNext
                    usernames={workflow?.user_reviewers.map((a) => a.id)}
                    operation={op.id}
                    guardian={app.guardian}
                    current={app.user.id}
                  />
                )}
                {op.allowed_actions.includes("approve") && (
                  <Button
                    className="primary small"
                    data-testid="workflow-approve"
                    onClick={() =>
                      app.setDialog({
                        type: "review",
                        operation: op,
                        action: "approve",
                      })
                    }
                  >
                    Review and approve
                  </Button>
                )}
              </>
            ) : (
              <p>The required approval from a different person is recorded.</p>
            )}
          </div>
        </li>
        <li>
          <span className="payment-step-number">
            {approved >= required ? <Icon name="check" /> : "2"}
          </span>
          <div>
            <div className="payment-step-title">
              <h4>Institution approvals</h4>
              <Badge status={approved >= required ? "complete" : "pending"}>
                {approved} of {required} recorded
              </Badge>
            </div>
            <p>
              {approved >= required ? (
                "The required institution approvals are recorded."
              ) : (
                <>
                  Any <strong>{required}</strong>
                  {institutionCount ? ` of the ${institutionCount}` : ""}{" "}
                  independent institutions must also approve this payment, each
                  in its own approval window.
                </>
              )}
            </p>
            {!!policyIds.length && (
              <details className="payment-institutions">
                <summary>Which institutions can approve?</summary>
                <ul>
                  {policyIds.map((id) => {
                    const institution = app.data.guardians.find(
                      (g) => (g.institution_id || g.id) === id,
                    );
                    return (
                      <li key={id}>
                        <span>{institution?.name || id}</span>
                        {workflow?.approved_institution_ids.includes(id) && (
                          <span>Approved</span>
                        )}
                      </li>
                    );
                  })}
                </ul>
              </details>
            )}
            {approved < required &&
              !op.allowed_actions.includes("guardian-approve") && (
                <DemoNext
                  usernames={policyIds.filter(
                    (id) => !workflow?.approved_institution_ids.includes(id),
                  )}
                  operation={op.id}
                  guardian={app.guardian}
                  current={app.user.id}
                />
              )}
            {op.allowed_actions.includes("guardian-approve") && (
              <Button
                className="primary small"
                data-testid="workflow-institution-approve"
                onClick={() =>
                  app.setDialog({
                    type: "review",
                    operation: op,
                    action: "guardian-approve",
                  })
                }
              >
                Review institution approval
              </Button>
            )}
          </div>
        </li>
        <li>
          <span className="payment-step-number">3</span>
          <div>
            <div className="payment-step-title">
              <h4>Send</h4>
              <Badge status={ready ? "ready" : "neutral"}>
                {ready ? "Ready" : "Waiting for steps 1 and 2"}
              </Badge>
            </div>
            {workflow?.submitters.length === 0 ? (
              <p>
                No chain submitter is configured. Ask the bank administrator to
                assign an authorized payment approver.
              </p>
            ) : (
              <p>
                Once steps 1 and 2 are complete,{" "}
                <Actors
                  actors={workflow?.submitters}
                  fallback="an authorized payment approver"
                />{" "}
                selects <b>Send</b>. This does not happen automatically.
              </p>
            )}
            {ready && !op.allowed_actions.includes("execute") && (
              <DemoNext
                usernames={workflow?.submitters.map((a) => a.id)}
                operation={op.id}
                guardian={app.guardian}
                current={app.user.id}
              />
            )}
            {ready && op.allowed_actions.includes("execute") && (
              <Button
                className="primary small"
                data-testid="workflow-execute"
                onClick={() =>
                  app.setDialog({
                    type: "review",
                    operation: op,
                    action: "execute",
                  })
                }
              >
                Review and send
              </Button>
            )}
          </div>
        </li>
      </ol>
    </section>
  );
}
