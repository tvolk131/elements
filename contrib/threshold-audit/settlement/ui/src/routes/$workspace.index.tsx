import { createFileRoute } from "@tanstack/react-router";
import { useApp } from "../context";
import { GuardianOverview } from "../guardian";
import { WalletPage } from "../wallet";
export const Route = createFileRoute("/$workspace/")({ component: Home });
function Home() {
  return useApp().guardian ? (
    <GuardianOverview />
  ) : (
    <WalletPage page="overview" />
  );
}
