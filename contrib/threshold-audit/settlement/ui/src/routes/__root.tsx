import {
  createRootRoute,
  HeadContent,
  Outlet,
  Scripts,
} from "@tanstack/react-router";
import { QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { queryClient } from "../api";
import css from "../styles.css?url";
export const Route = createRootRoute({
  // Authenticated data is fetched only in the browser. No private query cache is serialized.
  ssr: false,
  head: () => ({
    meta: [
      { charSet: "utf-8" },
      { name: "viewport", content: "width=device-width, initial-scale=1" },
      { title: "Concord · Institutional settlement" },
    ],
    links: [{ rel: "stylesheet", href: css }],
  }),
  component: () => (
    <QueryClientProvider client={queryClient}>
      <Outlet />
    </QueryClientProvider>
  ),
  shellComponent: ({ children }: { children: ReactNode }) => (
    <html lang="en">
      <head>
        <HeadContent />
      </head>
      <body>
        <div id="app">{children}</div>
        <Scripts />
      </body>
    </html>
  ),
  notFoundComponent: () => (
    <main>
      <h1>Page not found</h1>
      <a href="/wallet">Open wallet</a>
    </main>
  ),
});
