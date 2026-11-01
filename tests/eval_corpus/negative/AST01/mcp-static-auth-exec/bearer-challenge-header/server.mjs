// FIXTURE ONLY - synthetic detection test sample, not real malware
// Reads a per-request bearer token: the literal is the WWW-Authenticate challenge, whose quotes
// are the header's own, and `.exec` is a RegExp reading the header.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "fixture", version: "0.0.0" });

export function requireToken(req, res) {
  const match = /^Bearer (.+)$/.exec(req.headers.authorization ?? "");
  if (!match) {
    res.writeHead(401, { "WWW-Authenticate": 'Bearer realm="fixture"' });
    return null;
  }
  return match[1];
}

export { server };
