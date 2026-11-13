import {
  createContext,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  api,
  clearSession,
  queryClient,
  refreshData,
  startSession,
} from "./api";
import { Brand, Button, ErrorNote, Icon } from "./components";
import { DemoSignIn, takeReopenRequest, usePersonas } from "./demo";
import type {
  ApprovalRequest,
  Dashboard,
  DialogState,
  Session,
  User,
} from "./types";

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
  notify: (message: string, tone?: Tone) => number;
  openApproval: (
    id: string,
    rotation?: boolean,
    expected?: ExpectedRequest,
    labels?: { from: string; to: string },
  ) => Promise<void>;
  refresh: () => Promise<void>;
  logout: () => void;
  loggingOut: boolean;
  refreshing: boolean;
  error: Error | null;
}
/** Fields the operator reviewed; the prepared request must still match them. */
type ExpectedRequest = Pick<
  ApprovalRequest,
  "amount_minor" | "currency" | "asset_id" | "destination_hash"
>;
type Tone = "success" | "error" | "info";
const Context = createContext<AppContext | null>(null);
export function useApp() {
  const context = useContext(Context);
  if (!context) throw new Error("Authenticated workspace required");
  return context;
}
export function SessionGate({
  guardian,
  children,
}: {
  guardian: boolean;
  children: ReactNode;
}) {
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
  if (!session.data?.user) return <Login guardian={guardian} />;
  return (
    <Workspace
      key={session.data.user.id}
      session={session.data}
      guardian={guardian}
    >
      {children}
    </Workspace>
  );
}
function Login({ guardian }: { guardian: boolean }) {
  const demo = !!usePersonas().data?.length;
  const login = useMutation({
    gcTime: 0,
    mutationFn: (body: { username: string; password: string }) =>
      api<Session>("/api/login", body),
    onSuccess: startSession,
  });
  useEffect(() => {
    document.title = `Sign in · Concord ${guardian ? "guardian" : "wallet"}`;
  }, [guardian]);
  return (
    <main className="login-shell">
      <section className="login-story">
        <Brand />
        <h1>
          Bank money,
          <br />
          <em>on a shared ledger.</em>
        </h1>
        <p className="intro">
          Banks issue tokenized deposits that their customers can pay with in
          seconds, across banks. Payment details stay private, and a named
          authority can be shown a specific payment when independent guardians
          agree.
        </p>
        <div className="login-points">
          <span>
            <Icon name="shield" />
            Approved by independent institutions
          </span>
          <span>
            <Icon name="lock" />
            Private by default
          </span>
          <span>
            <Icon name="document" />
            Disclosed only with a quorum
          </span>
        </div>
        <footer>
          Concord settlement sandbox. Banks, reserves and payouts are simulated.
        </footer>
      </section>
      <section className="login-form-side">
        <div className="login-card">
          <div className="login-badge">
            <Icon name={guardian ? "shield" : "wallet"} />
            {guardian ? "Federation guardian" : "Institutional wallet"}
          </div>
          <h2>Welcome to your workspace.</h2>
          <p className="muted">
            {demo
              ? "Choose who to sign in as. Each person sees only what their role allows."
              : `Sign in with your assigned ${guardian ? "guardian institution" : "bank or corporate"} account.`}
          </p>
          {demo ? (
            <>
              <DemoSignIn guardian={guardian} />
              <details className="password-sign-in">
                <summary>Sign in with a password</summary>
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
              </details>
            </>
          ) : (
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
          )}
          <div className="login-notice">
            <Icon name="info" />
            <span>
              <strong>Local sandbox only.</strong> Reserve accounts and bank
              payments are simulated. Test tokens have no real-world redemption
              promise.
            </span>
          </div>
          <p className="login-switch">
            <a href={guardian ? "/wallet" : "/guardian"}>
              Open {guardian ? "institutional wallet" : "guardian console"}
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
  guardian,
  children,
}: {
  session: Session;
  guardian: boolean;
  children: ReactNode;
}) {
  const [selected, setAccount] = useState("");
  const [dialog, setDialog] = useState<DialogState>(null);
  const [toasts, setToasts] = useState<
    { id: number; message: string; tone: Tone }[]
  >([]);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);
  const seq = useRef(0);
  const dismiss = (id: number) =>
    setToasts((items) => items.filter((item) => item.id !== id));
  const notify = (message: string, tone: Tone = "success") => {
    const id = ++seq.current;
    setToasts((items) => [...items, { id, message, tone }]);
    timers.current.push(
      setTimeout(() => dismiss(id), tone === "error" ? 14000 : 7000),
    );
    return id;
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
        toast: number;
      }
    >(),
  );
  const user = session.user!;
  useEffect(() => {
    const id = takeReopenRequest();
    if (id) setDialog({ type: "operation", id });
  }, []);
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
    onError: (e) => notify(e.message, "error"),
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
      dismiss(expected.toast);
      try {
        await api(expected.path + "/certificates", {
          signature: message.signature,
        });
        notify(
          expected.rotation
            ? "Handover authorization recorded."
            : "Institution approval recorded.",
        );
        await refreshData();
        // Show the request again so the updated approval count is visible.
        if (!expected.rotation)
          setDialog({ type: "operation", id: message.operation_id });
      } catch (error) {
        notify(
          error instanceof Error
            ? error.message
            : "Certificate could not be recorded.",
          "error",
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
    expected?: ExpectedRequest,
    labels?: { from: string; to: string },
  ) {
    const institution = dashboard.data?.guardians.find(
      (g) => (g.institution_id || g.id) === user.institution_id,
    );
    const url = URL.parse(institution?.approval_url ?? "");
    const allowedHost =
      url &&
      (["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) ||
        (location.hostname.endsWith(".ray") &&
          url.hostname === location.hostname &&
          url.protocol === location.protocol));
    if (
      !url ||
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
      // One window per request: reusing a name can target a window that has
      // already closed itself, and then nothing visibly opens.
      `concord-institution-${user.institution_id}-${id}`,
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
        approval_request?: ApprovalRequest;
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
      const previous = pending.current.get(id);
      if (previous) {
        previous.popup.close();
        dismiss(previous.toast);
      }
      url.hash = encodeURIComponent(
        // `display` is for people only; signatures cover the request fields.
        JSON.stringify({
          ...request,
          return_origin: location.origin,
          ...(labels ? { display: labels } : {}),
        }),
      );
      popup.location.href = url.href;
      setDialog(null);
      pending.current.set(id, {
        popup,
        origin: url.origin,
        institution: user.institution_id,
        path,
        rotation,
        toast: notify(
          "Sign in your institution’s approval window to record this approval.",
          "info",
        ),
      });
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
        guardian,
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
            className={`toast ${t.tone}`}
            role={t.tone === "error" ? "alert" : "status"}
          >
            <Icon name={t.tone === "success" ? "check" : "info"} />
            <span>{t.message}</span>
            <button
              aria-label="Dismiss notification"
              onClick={() => dismiss(t.id)}
            >
              <Icon name="close" />
            </button>
          </div>
        ))}
      </div>
    </Context.Provider>
  );
}
