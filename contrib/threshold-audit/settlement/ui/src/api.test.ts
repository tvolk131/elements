import { afterEach, describe, expect, it, vi } from "vitest";
import { api, clearSession, queryClient } from "./api";
afterEach(() => {
  queryClient.clear();
  vi.unstubAllGlobals();
});
describe("authenticated requests", () => {
  it("sends same-origin credentials and the active CSRF token", async () => {
    queryClient.setQueryData(["session"], {
      user: { id: "maker" },
      csrf: "csrf-value",
      permissions: [],
    });
    const fetcher = vi
      .fn()
      .mockResolvedValue(new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetcher);
    await api("/api/transfers", { amount: "1.23" });
    expect(fetcher).toHaveBeenCalledWith(
      "/api/transfers",
      expect.objectContaining({
        method: "POST",
        credentials: "same-origin",
        body: '{"amount":"1.23"}',
        headers: expect.objectContaining({ "X-CSRF-Token": "csrf-value" }),
      }),
    );
  });
  it("removes private cached data when the session expires", async () => {
    queryClient.setQueryData(["dashboard", "previous"], { private: "balance" });
    queryClient.setQueryData(["operation", "previous", "case"], {
      private: "request",
    });
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          new Response('{"message":"expired"}', { status: 401 }),
        ),
    );
    await expect(api("/api/dashboard")).rejects.toThrow("expired");
    expect(queryClient.getQueryData(["dashboard", "previous"])).toBeUndefined();
    expect(
      queryClient.getQueryData(["operation", "previous", "case"]),
    ).toBeUndefined();
    expect(queryClient.getQueryData(["session"])).toMatchObject({ user: null });
  });
  it("does not retry financial mutations automatically", () =>
    expect(queryClient.getDefaultOptions().mutations?.retry).toBe(false));
  it("clears all prior identity data on sign-out", () => {
    queryClient.getMutationCache().build(queryClient, {
      mutationFn: async () => ({ private: "old request" }),
    });
    queryClient.setQueryData(["dashboard", "old"], {});
    clearSession();
    expect(queryClient.getMutationCache().getAll()).toHaveLength(0);
    expect(queryClient.getQueryData(["dashboard", "old"])).toBeUndefined();
  });
});
