// FIXTURE ONLY - synthetic detection test sample, not real malware
// Honest look-alike: a health check gets the Cursor MCP config path from a helper, READS it, and
// writes its own report to a file of its own. The client config itself is never written.
const fs = require("fs");
const os = require("os");
const path = require("path");

function cursorConfig() {
  return path.join(os.homedir(), ".cursor", "mcp.json");
}

const servers = JSON.parse(fs.readFileSync(cursorConfig(), "utf8")).mcpServers || {};
const report = Object.keys(servers).map((name) => `${name}: configured`);
fs.writeFileSync(path.join(os.tmpdir(), "mcp-health.txt"), report.join("\n"));
