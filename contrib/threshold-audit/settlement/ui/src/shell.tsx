import { Outlet, useRouterState } from "@tanstack/react-router";
import { useEffect } from "react";
import { useApp } from "./context";
import { Brand, Button, Icon } from "./components";
import {
  forAccount,
  human,
  needsAction,
  needsInstitutionApproval,
} from "./domain";
import { DemoSwitcher } from "./demo";
import { memberName } from "./guardian";
import { Dialogs } from "./dialogs";
import { WorkspaceLink } from "./navigation";
import type { Page } from "./types";
const ORGANIZATIONS: Record<string, string> = {
  bank: "Bank",
  "bank-b": "Bank B",
  regulator: "Regulator",
  federation: "Federation",
};
/** "Acme" from "Acme · Operating"; known names for banks and authorities. */
function organization(app: ReturnType<typeof useApp>) {
  const tenant = app.user.tenant;
  const own = app.data.accounts.find((a) => a.tenant === tenant);
  return (
    ORGANIZATIONS[tenant] ??
    own?.name.split(" · ")[0] ??
    tenant.charAt(0).toUpperCase() + tenant.slice(1)
  );
}
export function Shell() {
  const app = useApp();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const page = pathname.split("/")[2] || "overview";
  const items: [Page, string, string][] = app.guardian
    ? [
        ["overview", "Overview", "grid"],
        ["approvals", "Approvals", "shield"],
        ["reserves", "Reserves", "bank"],
        ["network", "Network", "network"],
      ]
    : app.data.accounts.length
      ? [
          ["overview", "Wallet", "wallet"],
          ["payments", "Requests", "activity"],
          ["banking", "Bank transfers", "bank"],
          ["beneficiaries", "Recipients", "users"],
        ]
      : []; // e.g. a regulator: no accounts, only disclosures and activity
  if (app.guardian && app.can("view_bank"))
    items.push(
      ["federation", "Operators", "refresh"],
      ["ledger", "Ledger", "document"],
    );
  if (
    app.can("request_disclosure") ||
    app.can("receive_disclosure") ||
    app.can("review_disclosure")
  )
    items.push(["disclosures", "Disclosures", "lock"]);
  items.push(["activity", "Activity log", "document"]);
  // Same count as "Needs your attention": requests this person can act on.
  const pending = app.guardian
    ? app.data.operations.filter(needsInstitutionApproval).length
    : forAccount(app.data.operations, app.account).filter(needsAction).length;
  const title = items.find((item) => item[0] === page)?.[1] || "Overview";
  useEffect(() => {
    document.title = `${title} · CEND ${app.guardian ? "network" : "wallet"}`;
  }, [title, app.guardian]);
  return (
    <div className="shell">
      <aside className="sidebar">
        <Brand />
        <div className="workspace-label">
          <Icon name={app.guardian ? "shield" : "wallet"} />
          {app.guardian ? "Network console" : "Institutional wallet"}
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
      </aside>
      <div className="shell-main">
        <header className="topbar">
          <div className="breadcrumb">
            {app.guardian ? "Network console" : organization(app)}
            <Icon name="chevron" />
            <strong>{title}</strong>
          </div>
          <div className="top-actions">
            <span
              className="environment"
              title="Test tokens on a local chain. Bank deposits and payouts are simulated; the legal issuer is undecided."
            >
              <span className="dot gold" /> Test network · simulated bank
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
                  {app.user.institution_id &&
                    ` · ${memberName(app.user.institution_id)}`}
                </div>
              </div>
            </div>
            <DemoSwitcher guardian={app.guardian} current={app.user.id} />
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
          {app.error && (
            <div className="error-banner" role="alert">
              <span>{app.error.message}</span>
              <Button onClick={app.refresh}>Try again</Button>
            </div>
          )}
          <Outlet />
        </main>
      </div>
      <Dialogs />
    </div>
  );
}
