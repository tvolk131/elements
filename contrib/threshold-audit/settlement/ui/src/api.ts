import { QueryClient } from "@tanstack/react-query";
import type { Session } from "./types";
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: false, staleTime: 5000 },
    // Financial actions must never be automatically replayed.
    mutations: { retry: false, networkMode: "always" },
  },
});
export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
  }
}
export function clearSession() {
  // Remove all prior-account data before another identity can sign in.
  queryClient.removeQueries({
    predicate: (query) => query.queryKey[0] !== "session",
  });
  queryClient.getMutationCache().clear();
  queryClient.setQueryData<Session>(["session"], {
    user: null,
    csrf: null,
    permissions: [],
  });
}
/** Replace any prior identity's cached data with a newly signed-in session. */
export async function startSession(session: Session) {
  await queryClient.cancelQueries();
  queryClient.removeQueries({
    predicate: (query) =>
      query.queryKey[0] !== "session" && query.queryKey[0] !== "demo-personas",
  });
  queryClient.getMutationCache().clear();
  queryClient.setQueryData(["session"], session);
}
export async function api<T>(
  path: string,
  body?: unknown,
  signal?: AbortSignal,
): Promise<T> {
  const session = queryClient.getQueryData<Session>(["session"]);
  const response = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    credentials: "same-origin",
    cache: "no-store",
    signal,
    headers: {
      Accept: "application/json",
      ...(body === undefined
        ? {}
        : {
            "Content-Type": "application/json",
            "X-CSRF-Token": session?.csrf || "",
          }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401 && path !== "/api/login") clearSession();
    throw new ApiError(
      data.message ||
        (typeof data.error === "string"
          ? data.error
          : "The settlement service could not complete this request."),
      response.status,
    );
  }
  return data as T;
}
export async function refreshData() {
  await Promise.all([
    queryClient.invalidateQueries({ queryKey: ["dashboard"] }),
    queryClient.invalidateQueries({ queryKey: ["operation"] }),
  ]);
}
