import { Outlet, useRouterState } from "@tanstack/react-router";
import { useEffect } from "react";
import { useApp } from "./context";
import { Brand, Button, Icon } from "./components";
import {
  isPending,
  forAccount,
  human,
  needsInstitutionApproval,
} from "./domain";
import { Dialogs } from "./dialogs";
import { WorkspaceLink } from "./navigation";
import type { Page } from "./types";
export function Shell() {
  const app = useApp();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const page = pathname.split("/")[2] || "overview";
  const items: [Page, string, string][] = app.guardian
    ? [
        ["overview", "Overview", "grid"],
        ["approvals", "Approval queue", "shield"],
        ["reserves", "Reserve accounts", "bank"],
        ["network", "Network & key readiness", "network"],
      ]
    : [
        ["overview", "Wallet", "wallet"],
        ["payments", "Requests", "activity"],
        ["banking", "Bank transfers", "bank"],
        ["beneficiaries", "Recipients", "users"],
      ];
  if (app.guardian && app.can("view_bank"))
    items.push(["federation", "Federation lifecycle", "refresh"]);
  items.push([
    "activity",
    app.guardian ? "Activity log" : "Audit log",
    "activity",
  ]);
  const pending = app.guardian
    ? app.data.operations.filter(needsInstitutionApproval).length
    : forAccount(app.data.operations, app.account).filter(isPending).length;
  const title = items.find((item) => item[0] === page)?.[1] || "Overview";
  useEffect(() => {
    document.title = `${title} · Concord ${app.guardian ? "guardian" : "wallet"}`;
  }, [title, app.guardian]);
  return (
    <div className="shell">
      <aside className="sidebar">
        <Brand />
        <div className="workspace-label">
          <Icon name={app.guardian ? "shield" : "wallet"} />
          {app.guardian ? "Guardian console" : "Institutional wallet"}
          <span className="dot" />
        </div>
        <div className="nav-label">Workspace</div>
        <nav className="nav" aria-label="Workspace navigation">
          {items.map(([id, label, symbol]) => (
            <WorkspaceLink
              key={id}
              page={id}
              className={
                page === id || (id === "overview" && page === "")
                  ? "active"
                  : ""
              }
              aria-current={page === id ? "page" : undefined}
              data-testid={`nav-${id}`}
            >
              <Icon name={symbol} />
              {label}
              {["approvals", "payments"].includes(id) && pending > 0 && (
                <span className="nav-badge">{pending}</span>
              )}
            </WorkspaceLink>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div className="security-card">
            <Icon name="lock" />
            <strong>
              {app.guardian
                ? "Independent institution authority"
                : "Institutional access controls"}
            </strong>
            <p>
              {app.guardian
                ? "Approvals use your institution’s configured signer. Private shares stay outside this browser."
                : "Your account determines your access. Payment approvals require a separate authorized person."}
            </p>
          </div>
          <p>
            LOCAL DEVELOPMENT ENVIRONMENT
            <br />
            Sandbox issuer · Legal entity undecided
          </p>
        </div>
      </aside>
      <div className="shell-main">
        <header className="topbar">
          <div className="breadcrumb">
            {app.guardian ? "Federation" : app.user.tenant}
            <Icon name="chevron" />
            <strong>{title}</strong>
          </div>
          <div className="top-actions">
            <span className="environment">
              <span className="dot gold" /> LOCAL SANDBOX
            </span>
            <span className="top-divider" />
            <div className="user-info">
              <span className="avatar">
                {app.user.name
                  .split(/\s+/)
                  .slice(0, 2)
                  .map((p) => p[0])
                  .join("")
                  .toUpperCase()}
              </span>
              <div className="user-copy">
                <div className="user-name">{app.user.name}</div>
                <div className="user-role">
                  {human(app.user.role)}
                  {app.user.institution_id && ` · ${app.user.institution_id}`}
                </div>
              </div>
            </div>
            <button
              className="icon-button"
              aria-label="Sign out"
              data-testid="logout"
              onClick={app.logout}
              disabled={app.loggingOut}
            >
              <Icon name="logout" />
            </button>
          </div>
        </header>
        <main className="content" id="main-content">
          <div className="sandbox-note">
            <Icon name="info" />
            <span>
              <strong>TEST NETWORK</strong> · On-chain tokens. Bank deposits and
              payouts are simulated.
            </span>
          </div>
          {app.error && (
            <div className="error-banner" role="alert">
              <span>{app.error.message}</span>
              <Button onClick={app.refresh}>Try again</Button>
            </div>
          )}
          <Outlet />
          <footer className="footer">
            <span>Concord · Institutional settlement sandbox</span>
            <span className="secure">
              <Icon name="lock" />
              Authenticated session ·{" "}
              {app.user.tenant || app.user.institution_id}
            </span>
          </footer>
        </main>
      </div>
      <Dialogs />
    </div>
  );
}
