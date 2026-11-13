import { createFileRoute, Navigate } from "@tanstack/react-router";
import { useApp } from "../context";
import { GuardianOverview } from "../guardian";
import { WalletPage } from "../wallet";
export const Route = createFileRoute("/$workspace/")({ component: Home });
function Home() {
  const app = useApp();
  if (
    app.can("request_disclosure") ||
    app.can("review_disclosure") ||
    app.can("receive_disclosure")
  )
    return (
      <Navigate
        to="/$workspace/$page"
        params={{
          workspace: app.guardian ? "guardian" : "wallet",
          page: "disclosures",
        }}
        replace
      />
    );
  return app.guardian ? <GuardianOverview /> : <WalletPage page="overview" />;
}
