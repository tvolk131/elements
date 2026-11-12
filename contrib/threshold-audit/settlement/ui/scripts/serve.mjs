// Small Node adapter for TanStack Start's fetch handler. No keys enter the client build.
import { createServer } from "node:http";
import { randomBytes } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { resolve, sep } from "node:path";
import { Readable } from "node:stream";
import { fileURLToPath, pathToFileURL } from "node:url";

const types = {
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
};
export function makeServer(config, handler, assetRoot) {
  const authorities = new Set([
    `127.0.0.1:${config.port}`,
    `localhost:${config.port}`,
    `[::1]:${config.port}`,
  ]);
  const origins = new Set([...authorities].map((host) => "http://" + host));
  const server = createServer(async (req, res) => {
    const nonce = randomBytes(24).toString("base64");
    const security = {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "same-origin",
      "Content-Security-Policy": `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`,
    };
    for (const [name, value] of Object.entries(security))
      res.setHeader(name, value);
    const fail = (status, error) => {
      res.writeHead(status, {
        "Content-Type": "application/json",
        Connection: "close",
      });
      res.end(JSON.stringify({ error }));
      req.resume();
    };
    try {
      const count = (name) =>
        req.rawHeaders.filter(
          (_, i) => i % 2 === 0 && req.rawHeaders[i].toLowerCase() === name,
        ).length;
      if (
        count("host") !== 1 ||
        count("origin") > 1 ||
        count("content-length") > 1 ||
        req.headers["transfer-encoding"]
      )
        return fail(400, "invalid_request_framing");
      if (
        !authorities.has(req.headers.host) ||
        (req.headers.origin && !origins.has(req.headers.origin)) ||
        (req.headers["sec-fetch-site"] &&
          !["same-origin", "none"].includes(req.headers["sec-fetch-site"]))
      )
        return fail(403, "host_or_origin_rejected");
      if (!["GET", "POST", "HEAD"].includes(req.method))
        return fail(405, "method_not_allowed");
      const raw = req.url || "/";
      if (!raw.startsWith("/") || /[\\?#%]/.test(raw))
        return fail(400, "invalid_request_target");
      const length = Number(req.headers["content-length"] || 0);
      if (!Number.isSafeInteger(length) || length < 0 || length > 32768)
        return fail(413, "request_too_large");
      let size = 0;
      const chunks = [];
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 32768) return fail(413, "request_too_large");
        chunks.push(chunk);
      }
      if (size !== length) return fail(400, "incomplete_request");
      const url = new URL(raw, "http://" + req.headers.host);
      if (url.pathname.startsWith("/assets/")) {
        if (!["GET", "HEAD"].includes(req.method))
          return fail(405, "method_not_allowed");
        const path = resolve(assetRoot, "." + url.pathname);
        if (!path.startsWith(resolve(assetRoot, "assets") + sep))
          return fail(404, "asset_not_found");
        const suffix = path.slice(path.lastIndexOf("."));
        const type = types[suffix];
        if (!type) return fail(404, "asset_not_found");
        const info = await stat(path).catch(() => null);
        if (!info?.isFile()) return fail(404, "asset_not_found");
        const bytes = await readFile(path);
        res.writeHead(200, {
          "Content-Type": type,
          "Content-Length": bytes.length,
        });
        return res.end(req.method === "HEAD" ? undefined : bytes);
      }
      const request = new Request(url, {
        method: req.method,
        headers: { ...req.headers, "x-concord-csp-nonce": nonce },
        ...(req.method === "POST" ? { body: Buffer.concat(chunks) } : {}),
      });
      const response = await handler.fetch(request, { context: { nonce } });
      res.statusCode = response.status;
      for (const [name, value] of response.headers) {
        if (
          ![
            "set-cookie",
            "transfer-encoding",
            "connection",
            "content-security-policy",
          ].includes(name.toLowerCase())
        )
          res.setHeader(name, value);
      }
      const cookies = response.headers.getSetCookie();
      if (cookies.length) res.setHeader("Set-Cookie", cookies);
      // Preserve the nonce policy and no-store even if framework/engine headers differ.
      for (const [name, value] of Object.entries(security))
        res.setHeader(name, value);
      if (req.method === "HEAD" || !response.body) {
        res.end();
        return;
      }
      const stream = Readable.fromWeb(response.body);
      stream.on("error", () => res.destroy());
      res.on("close", () => stream.destroy());
      stream.pipe(res);
    } catch {
      if (!res.headersSent) fail(503, "web_service_unavailable");
      else res.destroy();
    }
  });
  server.requestTimeout = 190000;
  server.headersTimeout = 15000;
  server.keepAliveTimeout = 5000;
  return server;
}
async function main() {
  const index = process.argv.indexOf("--config");
  if (index < 0 || !process.argv[index + 1])
    throw new Error("Usage: node scripts/serve.mjs --config PRIVATE_FILE");
  const path = resolve(process.argv[index + 1]);
  const info = await stat(path);
  if (!info.isFile() || (info.mode & 0o077) !== 0)
    throw new Error("Web configuration must be private (0600)");
  const config = JSON.parse(await readFile(path, "utf8"));
  if (!Number.isInteger(config.port) || config.port < 1 || config.port > 65535)
    throw new Error("Invalid web port");
  process.env.CONCORD_ENGINE_CONFIG = path;
  const build = resolve(config.build_dir);
  const handler = (
    await import(pathToFileURL(resolve(build, "server/server.js")).href)
  ).default;
  const server = makeServer(config, handler, resolve(build, "client"));
  await new Promise((done, fail) => {
    server.once("error", fail);
    server.listen(config.port, "127.0.0.1", done);
  });
  console.log(
    JSON.stringify({
      url: `http://127.0.0.1:${config.port}/`,
      pid: process.pid,
      backend: "tanstack-start",
    }),
  );
  let closing = false;
  const close = () => {
    if (closing) return;
    closing = true;
    server.close(() => process.exit(0));
    server.closeIdleConnections();
    setTimeout(() => {
      server.closeAllConnections();
      process.exit(1);
    }, 180000).unref();
  };
  process.on("SIGTERM", close);
  process.on("SIGINT", close);
}
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
)
  main().catch(() => {
    console.error(
      "TanStack Start web startup failed. Check the build and private web configuration.",
    );
    process.exitCode = 1;
  });
