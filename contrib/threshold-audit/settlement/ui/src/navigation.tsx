import { Link, useParams } from "@tanstack/react-router";
import type { ReactNode } from "react";
export function WorkspaceLink({
  page,
  children,
  ...props
}: {
  page: string;
  children: ReactNode;
  className?: string;
  "aria-current"?: "page";
  "data-testid"?: string;
}) {
  const params = useParams({ strict: false });
  return (
    <Link
      to="/$workspace/$page"
      params={{ workspace: params.workspace || "wallet", page }}
      {...props}
    >
      {children}
    </Link>
  );
}
