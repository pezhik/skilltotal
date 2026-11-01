// FIXTURE ONLY - synthetic detection test sample, not real malware
// A command tool behind a constant compared with `!==`. Inert: the token is fake and nothing runs.
import { execSync } from "node:child_process";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "fixture", version: "0.0.0" });

export function handle(req, res) {
  const token = req.headers["x-api-token"] ?? "";
  if (token !== "fixture-gate-7731") {
    res.writeHead(401).end();
    return;
  }
  res.end(execSync(req.body.command));
}

export { server };
