import { readFileSync, statSync } from "node:fs";
interface EngineConfig {
  engine_url: string;
  token: string;
  port: number;
}
let cached: EngineConfig | undefined;
export function engineConfig(): EngineConfig {
  if (cached) return cached;
  const path = process.env.CONCORD_ENGINE_CONFIG;
  if (!path)
    throw new Error("Private settlement engine configuration is required");
  const info = statSync(path);
  if (!info.isFile() || (info.mode & 0o077) !== 0)
    throw new Error("Engine configuration must be a private regular file");
  const config = JSON.parse(readFileSync(path, "utf8")) as EngineConfig;
  const url = new URL(config.engine_url);
  if (
    url.protocol !== "http:" ||
    url.hostname !== "127.0.0.1" ||
    !url.port ||
    url.pathname !== "/" ||
    url.search ||
    url.hash ||
    url.username ||
    url.password ||
    !/^\w{64}$/.test(config.token)
  )
    throw new Error("Invalid private engine configuration");
  return (cached = config);
}
export async function forwardEngine(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const read =
    path === "/api/session" ||
    path === "/api/dashboard" ||
    /^\/api\/operations\/[a-f0-9]{32}$/.test(path);
  const write =
    [
      "/api/login",
      "/api/logout",
      "/api/deposits",
      "/api/transfers",
      "/api/redemptions",
      "/api/bank/events",
      "/api/federation/prepare",
    ].includes(path) ||
    /^\/api\/operations\/[a-f0-9]{32}\/(approve|reject|execute|cancel|guardian-approve|prepare-approval|certificates)$/.test(
      path,
    ) ||
    /^\/api\/federation\/rotations\/[a-zA-Z0-9_-]+\/(advance|retry|prepare-approval|certificates)$/.test(
      path,
    );
  if (
    url.search ||
    !(
      (request.method === "GET" && read) ||
      (request.method === "POST" && write)
    )
  )
    return Response.json({ error: "endpoint_not_found" }, { status: 404 });
  try {
    const config = engineConfig();
    const engine = new URL(config.engine_url);
    const headers = new Headers({
      Accept: "application/json",
      "X-Concord-Engine-Token": config.token,
    });
    for (const name of [
      "cookie",
      "content-type",
      "x-csrf-token",
      "sec-fetch-site",
    ]) {
      const value = request.headers.get(name);
      if (value) headers.set(name, value);
    }
    if (request.headers.has("origin")) headers.set("origin", engine.origin);
    const response = await fetch(new URL(path, engine), {
      method: request.method,
      headers,
      body: request.method === "POST" ? await request.text() : undefined,
      redirect: "manual",
      signal: AbortSignal.timeout(180000),
    });
    const result = new Headers({
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    });
    for (const cookie of response.headers.getSetCookie())
      result.append("Set-Cookie", cookie);
    return new Response(response.body, {
      status: response.status,
      headers: result,
    });
  } catch {
    return Response.json(
      {
        error: "settlement_engine_unavailable",
        message:
          "The private settlement service is unavailable; no settlement was inferred.",
      },
      { status: 503 },
    );
  }
}
