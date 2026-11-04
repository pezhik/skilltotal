// FIXTURE ONLY - synthetic detection test sample, not real malware
// Honest look-alike: a local runner that imports its own config module and runs the coding agent
// with approvals off on the checkout. The imported module reads a local file and opens no
// network connection, so nothing remote drives the agent.
const { spawnSync } = require("child_process");
const { tasks } = require("./config");

for (const prompt of tasks()) {
  spawnSync("claude", ["-p", prompt, "--dangerously-skip-permissions"], { stdio: "inherit" });
}
