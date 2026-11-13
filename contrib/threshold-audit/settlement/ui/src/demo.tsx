// Password-less persona sign-in for runtimes explicitly configured for live
// demos. The server lists no personas (404) anywhere else, so nothing renders.
import { useMutation, useQuery } from "@tanstack/react-query";
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
  pending?: string;
}) {
  // The console the viewer is in comes first.
  const order =
    workspace === "wallet"
      ? (["wallet", "guardian"] as const)
      : (["guardian", "wallet"] as const);
  const groups = order
    .map((w) => [w, personas.filter((p) => p.workspace === w)] as const)
    .filter(([, list]) => list.length);
  return (
    <div className="persona-groups">
      {groups.map(([w, list]) => (
        <div key={w}>
          <h3>
            {w === "wallet" ? "Institutional wallet" : "Guardian console"}
          </h3>
          <ul className="persona-list">
            {list.map((p) => (
              <li key={p.username}>
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
                  {pending === p.username ? (
                    <small>Signing in…</small>
                  ) : p.username === current ? (
                    <small>Signed in</small>
                  ) : (
                    <Icon name="arrow" />
                  )}
                </button>
              </li>
            ))}
          </ul>
        </div>
      ))}
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
        pending={signIn.isPending ? signIn.variables?.username : undefined}
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
              pending={
                signIn.isPending ? signIn.variables?.username : undefined
              }
            />
            <ErrorNote error={signIn.error} />
          </div>
        </Modal>
      )}
    </>
  );
}
