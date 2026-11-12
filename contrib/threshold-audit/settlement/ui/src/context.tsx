import {
  createContext,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api, clearSession, queryClient, refreshData } from "./api";
import { Brand, Button, ErrorNote, Icon } from "./components";
import type { Dashboard, DialogState, Session, User } from "./types";

interface AppContext {
  data: Dashboard;
  user: User;
  account: string;
  setAccount: (id: string) => void;
  guardian: boolean;
  can: (permission: string) => boolean;
  accountName: (id?: string) => string;
  dialog: DialogState;
  setDialog: (dialog: DialogState) => void;
  notify: (message: string, error?: boolean) => void;
  openApproval: (
    id: string,
    rotation?: boolean,
    expected?: {
      amount_minor: number;
      currency: string;
      asset_id?: string;
      destination_hash?: string;
      manifest_hash?: string;
    },
  ) => Promise<void>;
  refresh: () => Promise<void>;
  logout: () => void;
  loggingOut: boolean;
  refreshing: boolean;
  error: Error | null;
}
const Context = createContext<AppContext | null>(null);
export function useApp() {
  const context = useContext(Context);
  if (!context) throw new Error("Authenticated workspace required");
  return context;
}
export const guardianApp =
  typeof window !== "undefined" &&
  window.location.pathname.startsWith("/guardian");
export function SessionGate({ children }: { children: ReactNode }) {
  const session = useQuery({
    queryKey: ["session"],
    queryFn: ({ signal }) => api<Session>("/api/session", undefined, signal),
  });
  if (session.isPending)
    return (
      <div className="boot-screen" role="status">
        <Brand />
        <p>Opening your workspace…</p>
      </div>
    );
  if (session.error)
    return (
      <div className="boot-screen">
        <ErrorNote error={session.error} />
        <Button onClick={() => session.refetch()}>Reconnect</Button>
      </div>
    );
  if (!session.data?.user) return <Login />;
  return (
    <Workspace key={session.data.user.id} session={session.data}>
      {children}
    </Workspace>
  );
}
function Login() {
  const login = useMutation({
    gcTime: 0,
    mutationFn: (body: { username: string; password: string }) =>
      api<Session>("/api/login", body),
    onSuccess: async (session) => {
      await queryClient.cancelQueries();
      queryClient.removeQueries({
        predicate: (query) => query.queryKey[0] !== "session",
      });
      queryClient.setQueryData(["session"], session);
    },
  });
  useEffect(() => {
    document.title = `Sign in · Concord ${guardianApp ? "guardian" : "wallet"}`;
  }, []);
  return (
    <main className="login-shell">
      <section className="login-story">
        <Brand />
        <h1>
          A shared standard.
          <br />
          <em>A stronger foundation.</em>
        </h1>
        <p className="intro">
          Confidential settlement for institutions. Clear oversight for the
          federation that safeguards it.
        </p>
        <div className="login-points">
          <span>
            <Icon name="shield" />
            Federated oversight
          </span>
          <span>
            <Icon name="lock" />
            Confidential by design
          </span>
        </div>
        <footer>
          Built for banks and the businesses they serve.
          <br />
          Concord institutional settlement · Local development sandbox
        </footer>
      </section>
      <section className="login-form-side">
        <div className="login-card">
          <div className="login-badge">
            <Icon name={guardianApp ? "shield" : "wallet"} />
            {guardianApp ? "Federation guardian" : "Institutional wallet"}
          </div>
          <h2>Welcome to your workspace.</h2>
          <p className="muted">
            Sign in with your assigned{" "}
            {guardianApp ? "guardian institution" : "bank or corporate"}{" "}
            account.
          </p>
          <form
            data-testid="login-form"
            onSubmit={(e) => {
              e.preventDefault();
              const form = new FormData(e.currentTarget);
              login.mutate({
                username: String(form.get("username")),
                password: String(form.get("password")),
              });
            }}
          >
            <div className="form-field">
              <label htmlFor="username">Username</label>
              <input
                id="username"
                name="username"
                autoComplete="username"
                required
                autoFocus
              />
            </div>
            <div className="form-field">
              <label htmlFor="password">Password</label>
              <input
                id="password"
                type="password"
                name="password"
                autoComplete="current-password"
                required
              />
            </div>
            <ErrorNote error={login.error} />
            <Button
              type="submit"
              className="primary"
              disabled={login.isPending}
              data-testid="login-submit"
            >
              {login.isPending ? "Signing in…" : "Sign in securely"}
              <Icon name="arrow" />
            </Button>
          </form>
          <div className="login-notice">
            <Icon name="info" />
            <span>
              <strong>Local sandbox only.</strong> Reserve accounts and bank
              payments are simulated. Test tokens have no real-world redemption
              promise.
            </span>
          </div>
          <p className="login-switch">
            <a href={guardianApp ? "/wallet" : "/guardian"}>
              Open {guardianApp ? "institutional wallet" : "guardian console"}
              <Icon name="arrow" />
            </a>
          </p>
        </div>
      </section>
    </main>
  );
}
function Workspace({
  session,
  children,
}: {
  session: Session;
  children: ReactNode;
}) {
  const [selected, setAccount] = useState("");
  const [dialog, setDialog] = useState<DialogState>(null);
  const [toasts, setToasts] = useState<
    { id: number; message: string; error: boolean }[]
  >([]);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);
  const seq = useRef(0);
  const notify = (message: string, error = false) => {
    const id = ++seq.current;
    setToasts((items) => [...items, { id, message, error }]);
    timers.current.push(
      setTimeout(
        () => setToasts((items) => items.filter((item) => item.id !== id)),
        error ? 14000 : 7000,
      ),
    );
  };
  const pending = useRef(
    new Map<
      string,
      {
        popup: Window;
        origin: string;
        institution: string;
        path: string;
        rotation: boolean;
      }
    >(),
  );
  const user = session.user!;
  const dashboard = useQuery({
    queryKey: ["dashboard", user.id],
    queryFn: ({ signal }) =>
      api<Dashboard>("/api/dashboard", undefined, signal),
    refetchInterval: 30000,
    refetchIntervalInBackground: false,
  });
  const logout = useMutation({
    mutationFn: () => api("/api/logout", {}),
    onSuccess: async () => {
      await queryClient.cancelQueries();
      clearSession();
    },
    onError: (e) => notify(e.message, true),
  });
  useEffect(() => {
    const handler = async (event: MessageEvent) => {
      const message = event.data;
      if (
        !message ||
        typeof message !== "object" ||
        message.type !== "institution-approval" ||
        typeof message.operation_id !== "string"
      )
        return;
      const expected = pending.current.get(message.operation_id);
      if (
        !expected ||
        expected.origin !== event.origin ||
        expected.popup !== event.source ||
        message.signature?.guardian_id !== expected.institution
      )
        return;
      pending.current.delete(message.operation_id);
      try {
        await api(expected.path + "/certificates", {
          signature: message.signature,
        });
        notify(
          `Independent ${expected.rotation ? "handover authorization" : "institution certificate"} verified and recorded.`,
        );
        await refreshData();
      } catch (error) {
        notify(
          error instanceof Error
            ? error.message
            : "Certificate could not be recorded.",
          true,
        );
      }
    };
    window.addEventListener("message", handler);
    const windows = pending.current;
    return () => {
      window.removeEventListener("message", handler);
      windows.forEach((item) => item.popup.close());
      windows.clear();
      timers.current.forEach(clearTimeout);
    };
  }, [user.id]);
  const account = dashboard.data?.accounts.some((a) => a.id === selected)
    ? selected
    : dashboard.data?.accounts[0]?.id || "";
  async function openApproval(
    id: string,
    rotation = false,
    expected?: {
      amount_minor: number;
      currency: string;
      asset_id?: string;
      destination_hash?: string;
      manifest_hash?: string;
    },
  ) {
    const institution = dashboard.data?.guardians.find(
      (g) => (g.institution_id || g.id) === user.institution_id,
    );
    const url = new URL(institution?.approval_url || "");
    const allowedHost =
      ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) ||
      (location.hostname.endsWith(".ray") &&
        url.hostname === location.hostname &&
        url.protocol === location.protocol);
    if (
      url.protocol !== "http:" ||
      !allowedHost ||
      url.username ||
      url.password ||
      !user.institution_id
    )
      throw new Error(
        "Your institution’s independent approval service is not configured.",
      );
    // Open synchronously while still in the user's submit gesture.
    const popup = window.open(
      "about:blank",
      `concord-institution-${user.institution_id}`,
      "popup,width=750,height=900",
    );
    if (!popup)
      throw new Error(
        "Allow the independent institution approval window, then try again.",
      );
    const path = rotation
      ? `/api/federation/rotations/${encodeURIComponent(id)}`
      : `/api/operations/${encodeURIComponent(id)}`;
    try {
      const prepared = await api<{
        id?: string;
        approval_request?: import("./types").ApprovalRequest;
        manifest_hash?: string;
        plan_hash?: string;
        payload_hash?: string;
      }>(path + "/prepare-approval", {});
      const request = prepared.approval_request;
      if (
        !request ||
        request.id !== id ||
        (rotation ? request.kind !== "federation_rotation" : prepared.id !== id)
      )
        throw new Error(
          "The server did not supply the exact approval request.",
        );
      if (
        expected &&
        !rotation &&
        (request.amount_minor !== expected.amount_minor ||
          request.currency !== expected.currency ||
          request.asset_id !== expected.asset_id ||
          request.destination_hash !== expected.destination_hash)
      )
        throw new Error(
          "The request changed. Close this review and inspect the updated operation.",
        );
      const manifest =
        prepared.manifest_hash || prepared.plan_hash || prepared.payload_hash;
      if (
        rotation &&
        expected?.manifest_hash &&
        manifest &&
        expected.manifest_hash !== manifest
      )
        throw new Error(
          "The handover manifest changed. Review it again before approving.",
        );
      pending.current.get(id)?.popup.close();
      pending.current.set(id, {
        popup,
        origin: url.origin,
        institution: user.institution_id,
        path,
        rotation,
      });
      url.hash = encodeURIComponent(
        JSON.stringify({ ...request, return_origin: location.origin }),
      );
      popup.location.href = url.href;
      setDialog(null);
      notify(
        "Continue in your institution’s independent approval window. No approval is recorded yet.",
      );
    } catch (error) {
      popup.close();
      throw error;
    }
  }
  if (!dashboard.data)
    return (
      <div className="boot-screen">
        <Brand />
        {dashboard.error ? (
          <>
            <ErrorNote error={dashboard.error} />
            <Button onClick={() => dashboard.refetch()}>Try again</Button>
            <Button onClick={() => logout.mutate()}>Sign out</Button>
          </>
        ) : (
          <p role="status">Loading your workspace…</p>
        )}
      </div>
    );
  return (
    <Context.Provider
      value={{
        data: dashboard.data,
        user,
        account,
        setAccount,
        guardian: guardianApp,
        can: (p) => session.permissions.includes(p),
        accountName: (id) =>
          dashboard.data!.accounts.find((a) => a.id === id)?.name ||
          id ||
          "Configured account",
        dialog,
        setDialog,
        notify,
        openApproval,
        refresh: refreshData,
        logout: () => logout.mutate(),
        loggingOut: logout.isPending,
        refreshing: dashboard.isFetching,
        error: dashboard.error,
      }}
    >
      {children}
      <div className="notifications" aria-live="polite">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={`toast${t.error ? " error" : ""}`}
            role={t.error ? "alert" : "status"}
          >
            <Icon name={t.error ? "info" : "check"} />
            <span>{t.message}</span>
            <button
              aria-label="Dismiss notification"
              onClick={() =>
                setToasts((items) => items.filter((item) => item.id !== t.id))
              }
            >
              <Icon name="close" />
            </button>
          </div>
        ))}
      </div>
    </Context.Provider>
  );
}
