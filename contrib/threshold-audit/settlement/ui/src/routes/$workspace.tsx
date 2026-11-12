import { createFileRoute, notFound } from "@tanstack/react-router";
import { useEffect } from "react";
import { SessionGate } from "../context";
import { Shell } from "../shell";
export const Route = createFileRoute("/$workspace")({
  beforeLoad: ({ params }) => {
    if (!["wallet", "guardian"].includes(params.workspace)) throw notFound();
  },
  component: Workspace,
});
function Workspace() {
  const navigate = Route.useNavigate();
  const { workspace } = Route.useParams();
  useEffect(() => {
    const page = location.hash.replace(/^#\/?/, "");
    if (page && /^[a-z]+$/.test(page)) {
      void navigate({
        to: "/$workspace/$page",
        params: { workspace, page },
        replace: true,
        hash: "",
      });
    }
  }, [workspace, navigate]);
  return (
    <SessionGate>
      <Shell />
    </SessionGate>
  );
}
