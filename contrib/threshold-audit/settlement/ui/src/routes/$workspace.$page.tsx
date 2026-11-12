import { createFileRoute } from "@tanstack/react-router";
import { useApp } from "../context";
import { ActivityPage, RecipientsPage, WalletPage } from "../wallet";
import {
  FederationPage,
  GuardianOverview,
  NetworkPage,
  ReservesPage,
} from "../guardian";
export const Route = createFileRoute("/$workspace/$page")({ component: Page });
function Page() {
  const app = useApp();
  const { page } = Route.useParams();
  if (page === "activity") return <ActivityPage />;
  if (app.guardian) {
    if (page === "reserves") return <ReservesPage />;
    if (page === "network") return <NetworkPage />;
    if (page === "federation" && app.can("view_bank"))
      return <FederationPage />;
    if (["overview", "approvals"].includes(page))
      return <GuardianOverview approvals={page === "approvals"} />;
  } else {
    if (page === "beneficiaries") return <RecipientsPage />;
    if (["overview", "payments", "banking"].includes(page))
      return (
        <WalletPage
          key={page}
          page={page as "overview" | "payments" | "banking"}
        />
      );
  }
  return <h1>Page not available in this workspace</h1>;
}
