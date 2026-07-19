#!/usr/bin/env node
import { createServer } from "node:http";
import { appendFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

function option(name) {
  const index = process.argv.indexOf(name);
  if (index === -1 || !process.argv[index + 1]) throw new Error(`${name} is required`);
  return process.argv[index + 1];
}

const portFile = resolve(option("--port-file"));
const logFile = resolve(option("--log-file"));
const token = process.env.OATH_COMPAT_REGISTRY_TOKEN ?? "oath-compat-token";
const username = process.env.OATH_COMPAT_REGISTRY_USER ?? "oath-compat-user";

const server = createServer(async (request, response) => {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  const body = Buffer.concat(chunks).toString("utf8");
  const authorization = request.headers.authorization ?? null;
  await appendFile(logFile, `${JSON.stringify({
    method: request.method,
    url: request.url,
    authorization: authorization ? "present" : "absent",
    body_sha256: body.length
      ? (await import("node:crypto")).createHash("sha256").update(body).digest("hex")
      : null,
  })}\n`);

  response.setHeader("content-type", "application/json");
  if (request.method === "GET" && request.url === "/-/whoami") {
    if (authorization === `Bearer ${token}`) {
      response.writeHead(200);
      response.end(JSON.stringify({ username }));
    } else {
      response.writeHead(401);
      response.end(JSON.stringify({ error: "unauthorized" }));
    }
    return;
  }
  if (request.method === "DELETE" && request.url?.startsWith("/-/user/token/")) {
    response.writeHead(200);
    response.end(JSON.stringify({ ok: true }));
    return;
  }
  if ((request.method === "PUT" || request.method === "POST") && request.url?.includes("org.couchdb.user")) {
    response.writeHead(201);
    response.end(JSON.stringify({ ok: true, token }));
    return;
  }
  response.writeHead(404);
  response.end(JSON.stringify({ error: "not_found" }));
});

server.listen(0, "127.0.0.1", async () => {
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("fixture server did not expose a TCP port");
  await writeFile(logFile, "");
  await writeFile(portFile, `${address.port}\n`);
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
