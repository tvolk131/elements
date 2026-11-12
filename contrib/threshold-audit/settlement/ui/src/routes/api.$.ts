import { createFileRoute } from "@tanstack/react-router";
import { forwardEngine } from "../server/engine.server";
export const Route = createFileRoute("/api/$")({
  server: {
    handlers: {
      GET: ({ request }) => forwardEngine(request),
      POST: ({ request }) => forwardEngine(request),
    },
  },
});
