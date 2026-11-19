import {
  createRootRoute,
  createRoute,
  createRouter,
  Navigate,
  notFound,
  Outlet,
  redirect,
} from "@tanstack/react-router";
import { lazy, Suspense, useEffect } from "react";
import { SessionGate, useApp } from "./context";
import {
  FederationPage,
  GuardianOverview,
  NetworkPage,
  ReservesPage,
} from "./guardian";
import { LedgerPage } from "./ledger";
import { Shell } from "./shell";
import { ActivityPage, RecipientsPage, WalletPage } from "./wallet";

// Recipient-side crypto is only needed on the disclosures page.
const DisclosuresPage = lazy(() =>
  import("./disclosures").then((m) => ({ default: m.DisclosuresPage })),
);
const DISCLOSURE_PERMISSIONS = [
  "request_disclosure",
  "receive_disclosure",
  "review_disclosure",
];

// The page each person last had open in this tab, so switching between demo
// personas returns each to where they were (the bank to its Ledger, say).
const lastPage = (user: string, workspace: string) =>
  `concord-last-page:${workspace}:${user}`;
function readLastPage(user: string, workspace: string) {
  try {
    return sessionStorage.getItem(lastPage(user, workspace));
  } catch {
    return null;
  }
}
function rememberPage(user: string, workspace: string, page: string) {
  try {
    sessionStorage.setItem(lastPage(user, workspace), page);
  } catch {
    /* A convenience only. */
  }
}

const rootRoute = createRootRoute({
  component: Outlet,
  notFoundComponent: () => (
    <main className="not-found">
      <h1>Page not found</h1>
      <a href="/wallet">Open wallet</a>
    </main>
  ),
});

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  beforeLoad: () => {
    throw redirect({ to: "/$workspace", params: { workspace: "wallet" } });
  },
});

const workspaceRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "$workspace",
  beforeLoad: ({ params }) => {
    if (!["wallet", "guardian"].includes(params.workspace)) throw notFound();
  },
  component: function Workspace() {
    const navigate = workspaceRoute.useNavigate();
    const { workspace } = workspaceRoute.useParams();
    // Redirect bookmarks from the earlier hash-based navigation.
    useEffect(() => {
      const page = location.hash.replace(/^#\/?/, "");
      if (page && /^[a-z]+$/.test(page))
        void navigate({
          to: "/$workspace/$page",
          params: { workspace, page },
          replace: true,
          hash: "",
        });
    }, [workspace, navigate]);
    return (
      <SessionGate guardian={workspace === "guardian"}>
        <Shell />
      </SessionGate>
    );
  },
});

const homeRoute = createRoute({
  getParentRoute: () => workspaceRoute,
  path: "/",
  component: function Home() {
    const app = useApp();
    const workspace = app.guardian ? "guardian" : "wallet";
    const last = readLastPage(app.user.id, workspace);
    // Operators review disclosures too, but their work is approvals.
    const page =
      last && last !== "overview"
        ? last
        : DISCLOSURE_PERMISSIONS.some(app.can) && !app.can("guardian_approve")
          ? "disclosures"
          : null;
    if (page)
      return (
        <Navigate to="/$workspace/$page" params={{ workspace, page }} replace />
      );
    return app.guardian ? <GuardianOverview /> : <WalletPage page="overview" />;
  },
});

const pageRoute = createRoute({
  getParentRoute: () => workspaceRoute,
  path: "$page",
  component: function Page() {
    const app = useApp();
    const { page } = pageRoute.useParams();
    const content = pageContent(app, page);
    const workspace = app.guardian ? "guardian" : "wallet";
    const shown = content !== null;
    useEffect(() => {
      if (shown) rememberPage(app.user.id, workspace, page);
    }, [shown, app.user.id, workspace, page]);
    if (content) return content;
    // After switching to someone who can't open this page (or following an
    // old link), go to their own home page rather than an error.
    return <Navigate to="/$workspace" params={{ workspace }} replace />;
  },
});

function pageContent(app: ReturnType<typeof useApp>, page: string) {
  if (page === "disclosures" && DISCLOSURE_PERMISSIONS.some(app.can))
    return (
      <Suspense fallback={<p role="status">Loading disclosures…</p>}>
        <DisclosuresPage />
      </Suspense>
    );
  if (page === "activity") return <ActivityPage />;
  if (app.guardian) {
    if (page === "reserves") return <ReservesPage />;
    if (page === "network") return <NetworkPage />;
    if (page === "federation" && app.can("view_bank"))
      return <FederationPage />;
    if (page === "ledger" && app.can("view_bank")) return <LedgerPage />;
    if (page === "overview" || page === "approvals")
      return <GuardianOverview approvals={page === "approvals"} />;
  } else {
    if (page === "beneficiaries") return <RecipientsPage />;
    if (page === "overview" || page === "payments" || page === "banking")
      return <WalletPage key={page} page={page} />;
  }
  return null;
}

const routeTree = rootRoute.addChildren([
  indexRoute,
  workspaceRoute.addChildren([homeRoute, pageRoute]),
]);

export const router = createRouter({ routeTree, scrollRestoration: true });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
