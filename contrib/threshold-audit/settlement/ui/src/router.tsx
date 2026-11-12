import { createRouter } from "@tanstack/react-router";
import { routeTree } from "./routeTree.gen";
export async function getRouter() {
  const nonce = import.meta.env.SSR
    ? (await import("@tanstack/react-start/server")).getRequestHeader(
        "x-concord-csp-nonce",
      )
    : undefined;
  return createRouter({ routeTree, scrollRestoration: true, ssr: { nonce } });
}
declare module "@tanstack/react-router" {
  interface Register {
    router: Awaited<ReturnType<typeof getRouter>>;
  }
}
