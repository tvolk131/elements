// Password-less persona sign-in for runtimes explicitly configured for live
// demos. The server lists no personas (404) anywhere else, so nothing renders.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, startSession } from "./api";
import { Button, ErrorNote, Icon, Modal } from "./components";
import type { Session } from "./types";

export interface Persona {
  username: string;
  label: string;
  workspace: "wallet" | "guardian";
  name: string;
  role: string;
}

export function usePersonas() {
  return useQuery({
    queryKey: ["demo-personas"],
    queryFn: ({ signal }) =>
      api<Persona[]>("/api/demo/personas", undefined, signal),
    retry: false,
    staleTime: Infinity,
  });
}

function useSignInAs(currentWorkspace: "wallet" | "guardian") {
  return useMutation({
    mutationFn: (persona: Persona) =>
      api<Session>("/api/demo/login", { username: persona.username }),
    onSuccess: async (session, persona) => {
      if (persona.workspace !== currentWorkspace)
        return location.assign("/" + persona.workspace);
      await startSession(session);
    },
  });
}

// "Operator 3 · signs approvals" → ["3", "signs approvals"]
const OPERATOR = /^Operator (\d+) · (.+)$/;

function PersonaList({
  personas,
  workspace,
  current,
  onPick,
  pending,
}: {
  personas: Persona[];
  workspace: "wallet" | "guardian";
  current?: string;
  onPick: (persona: Persona) => void;
  pending?: Persona;
}) {
  // The console the viewer is in comes first.
  const order =
    workspace === "wallet"
      ? (["wallet", "guardian"] as const)
      : (["guardian", "wallet"] as const);
  const groups = order
    .map((w) => [w, personas.filter((p) => p.workspace === w)] as const)
    .filter(([, list]) => list.length);
  // Two personas can be the same account (the bank administrator confirms
  // deposits and oversees reserves), so the one clicked is matched by label.
  const isPending = (p: Persona) =>
    pending?.username === p.username && pending.label === p.label;
  return (
    <div className="persona-groups">
      {groups.map(([w, list]) => {
        // The operators share one card with a button each, so seven of them
        // don't push the other personas off the screen.
        const operators = list.filter((p) => OPERATOR.test(p.label));
        const others = list.filter((p) => !operators.includes(p));
        const operatorRole = operators[0]?.label.match(OPERATOR)?.[2];
        return (
          <div key={w}>
            <h3>
              {w === "wallet" ? "Institutional wallet" : "Network console"}
            </h3>
            <ul className="persona-list">
              {others.map((p) => (
                <li key={p.username + p.label}>
                  <button
                    type="button"
                    className="persona"
                    aria-current={p.username === current ? "true" : undefined}
                    disabled={!!pending || p.username === current}
                    onClick={() => onPick(p)}
                    data-testid={`persona-${p.username}`}
                  >
                    <strong>{p.label}</strong>
                    <span>{p.name}</span>
                    {isPending(p) ? (
                      <small>Signing in…</small>
                    ) : p.username === current ? (
                      <small>Signed in</small>
                    ) : (
                      <Icon name="arrow" />
                    )}
                  </button>
                </li>
              ))}
              {operators.length > 0 && (
                <li>
                  <div
                    className="persona persona-operators"
                    role="group"
                    aria-label={`Operators · ${operatorRole}`}
                  >
                    <strong>Operators · {operatorRole}</strong>
                    <span>
                      {operators.some(isPending)
                        ? "Signing in…"
                        : "Each runs its own approval service"}
                    </span>
                    <div className="operator-picks">
                      {operators.map((p) => (
                        <button
                          key={p.username}
                          type="button"
                          aria-label={p.label}
                          title={p.name}
                          aria-current={
                            p.username === current ? "true" : undefined
                          }
                          disabled={!!pending || p.username === current}
                          onClick={() => onPick(p)}
                          data-testid={`persona-${p.username}`}
                        >
                          {p.label.match(OPERATOR)?.[1]}
                        </button>
                      ))}
                    </div>
                  </div>
                </li>
              )}
            </ul>
          </div>
        );
      })}
    </div>
  );
}

export function DemoSignIn({ guardian }: { guardian: boolean }) {
  const workspace = guardian ? "guardian" : "wallet";
  const personas = usePersonas();
  const signIn = useSignInAs(workspace);
  if (!personas.data?.length) return null;
  return (
    <section className="demo-sign-in" aria-label="Demo accounts">
      <PersonaList
        personas={personas.data}
        workspace={workspace}
        onPick={(p) => signIn.mutate(p)}
        pending={signIn.isPending ? signIn.variables : undefined}
      />
      <ErrorNote error={signIn.error} />
    </section>
  );
}

export function DemoSwitcher({
  guardian,
  current,
}: {
  guardian: boolean;
  current: string;
}) {
  const workspace = guardian ? "guardian" : "wallet";
  const [open, setOpen] = useState(false);
  const personas = usePersonas();
  const signIn = useSignInAs(workspace);
  if (!personas.data?.length) return null;
  return (
    <>
      <Button
        symbol="users"
        className="switch-user"
        onClick={() => setOpen(true)}
        data-testid="switch-user"
      >
        Switch user
      </Button>
      {open && (
        <Modal
          title="Switch demo user"
          description="Sign in as another persona. Each keeps its own permissions."
          close={() => setOpen(false)}
        >
          <div className="dialog-body">
            <PersonaList
              personas={personas.data}
              workspace={workspace}
              current={current}
              onPick={(p) => signIn.mutate(p)}
              pending={signIn.isPending ? signIn.variables : undefined}
            />
            <ErrorNote error={signIn.error} />
          </div>
        </Modal>
      )}
    </>
  );
}

const REOPEN = "concord-demo-reopen";

/** After a demo switch, reopen the request the presenter was looking at. */
export function takeReopenRequest(): string | null {
  try {
    const id = sessionStorage.getItem(REOPEN);
    sessionStorage.removeItem(REOPEN);
    return id;
  } catch {
    return null;
  }
}

/**
 * Demo only: one-click "Switch to …" buttons for the people who can take a
 * request's next step. Renders nothing outside demo runtimes.
 */
export function DemoNext({
  usernames = [],
  roles = [],
  operation,
  guardian,
  current,
}: {
  usernames?: string[];
  roles?: string[];
  operation: string;
  guardian: boolean;
  current: string;
}) {
  const workspace = guardian ? "guardian" : "wallet";
  const personas = usePersonas();
  const signIn = useSignInAs(workspace);
  const wanted = (personas.data || []).filter(
    (p) =>
      p.username !== current &&
      (usernames.includes(p.username) || roles.includes(p.role)),
  );
  // One button per person, preferring the console where they act.
  const choices = [...new Set(wanted.map((p) => p.username))].map(
    (username) => {
      const options = wanted.filter((p) => p.username === username);
      return (
        options.find((p) =>
          p.role === "institutionguardian"
            ? p.workspace === "guardian"
            : p.workspace === "wallet",
        ) || options[0]
      );
    },
  );
  // One operator is enough to show signing live; the demo shortcut then
  // collects the rest, so offer only the first operator who can sign.
  const firstOperator = choices.find((p) => p.role === "institutionguardian");
  const shown = choices.filter(
    (p) => p.role !== "institutionguardian" || p === firstOperator,
  );
  if (!shown.length) return null;
  return (
    <div className="demo-next">
      {shown.map((p) => (
        <button
          key={p.username}
          type="button"
          className="demo-next-button"
          disabled={signIn.isPending}
          onClick={() => {
            try {
              sessionStorage.setItem(REOPEN, operation);
            } catch {
              /* Reopening is a convenience only. */
            }
            signIn.mutate(p);
          }}
          data-testid={`demo-next-${p.username}`}
        >
          <Icon name="users" />
          Switch to {p.name}
        </button>
      ))}
    </div>
  );
}

/**
 * Demo only: after one institution has signed live, have the remaining ones
 * approve through their own approval services in one click.
 */
export function DemoInstitutions({ operation }: { operation: string }) {
  const personas = usePersonas();
  const queryClient = useQueryClient();
  const sign = useMutation({
    mutationFn: () =>
      api(
        `/api/demo/operations/${encodeURIComponent(operation)}/institutions`,
        {},
      ),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["operation"] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });
  if (!personas.data?.length) return null;
  return (
    <div className="demo-next">
      <button
        type="button"
        className="demo-next-button"
        disabled={sign.isPending}
        onClick={() => sign.mutate()}
        data-testid="demo-sign-institutions"
      >
        <Icon name="shield" />
        {sign.isPending
          ? "Collecting approvals…"
          : "Add the other operators’ approvals"}
      </button>
      <ErrorNote error={sign.error} />
    </div>
  );
}
