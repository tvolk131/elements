// @vitest-environment node
import { afterEach, beforeEach, expect, it } from "vitest";
import { request } from "node:http";
import { makeServer } from "../../scripts/serve.mjs";
let server, port, calls;
beforeEach(async () => {
  calls = 0;
  const handler = {
    fetch: async (req, options) => {
      calls++;
      return new Response(
        JSON.stringify({
          path: new URL(req.url).pathname,
          nonce: options.context.nonce,
        }),
        {
          headers: {
            "Content-Type": "application/json",
            "Set-Cookie": "session=value; HttpOnly; SameSite=Strict",
          },
        },
      );
    },
  };
  server = makeServer({ port: 0 }, handler, "/tmp/nonexistent-concord-assets");
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  port = server.address().port;
  server.closeAllConnections();
  await new Promise((r) => server.close(r));
  server = makeServer({ port }, handler, "/tmp/nonexistent-concord-assets");
  await new Promise((r) => server.listen(port, "127.0.0.1", r));
});
afterEach(async () => {
  server.closeAllConnections();
  await new Promise((r) => server.close(r));
});
const send = (headers = {}, path = "/wallet") =>
  new Promise((resolve, reject) => {
    const req = request(
      { hostname: "127.0.0.1", port, path, headers },
      (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () =>
          resolve({ status: res.statusCode, headers: res.headers, body }),
        );
      },
    );
    req.on("error", reject);
    req.end();
  });
it("serves Start responses with the matching nonce CSP and session cookie", async () => {
  const r = await send();
  expect(r.status).toBe(200);
  expect(r.headers["content-security-policy"]).toContain(
    `'nonce-${JSON.parse(r.body).nonce}'`,
  );
  expect(r.headers["set-cookie"][0]).toContain("HttpOnly");
  expect(r.headers["cache-control"]).toBe("no-store");
});
it("rejects unrecognized Host headers before reaching Start", async () => {
  expect((await send({ Host: "attacker.invalid" })).status).toBe(403);
  expect(calls).toBe(0);
});
it("rejects cross-origin and cross-site requests", async () => {
  expect((await send({ Origin: "https://attacker.invalid" })).status).toBe(403);
  expect((await send({ "Sec-Fetch-Site": "cross-site" })).status).toBe(403);
  expect(calls).toBe(0);
});
it("rejects queries and encoded traversal before routing", async () => {
  expect((await send({}, "/wallet?unexpected=1")).status).toBe(400);
  expect((await send({}, "/assets/%2e%2e/.env")).status).toBe(400);
  expect(calls).toBe(0);
});
