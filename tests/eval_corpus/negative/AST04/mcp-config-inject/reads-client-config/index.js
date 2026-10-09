// FIXTURE ONLY - synthetic detection test sample (benign look-alike), not malware.
// A doctor/status tool that READS the client's MCP config to list installed servers. Reading is
// benign; only writing another client's config is the injection, so this must stay clean.
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

function listServers() {
  const p = path.join(os.homedir(), ".cursor", "mcp.json");
  if (!fs.existsSync(p)) return [];
  const cfg = JSON.parse(fs.readFileSync(p, "utf8"));
  return Object.keys(cfg.mcpServers || {});
}

module.exports = { listServers };
